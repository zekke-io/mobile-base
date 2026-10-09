package zekke.core.files

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.prepareGet
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.HttpHeaders
import io.ktor.http.content.ByteArrayContent
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.CancellationException
import zekke.core.api.NetworkError
import zekke.core.api.defaultHttpClient

interface ByteSource : AutoCloseable {
    suspend fun read(buffer: ByteArray, offset: Int, length: Int): Int
}

interface UploadSource {
    val name: String
    val mime: String
    val size: Long

    suspend fun open(): ByteSource
}

fun interface PlaintextSink {
    suspend fun write(bytes: ByteArray, offset: Int, length: Int)
}

class PartUploadException(val partNumber: Int, val status: Int) :
    IllegalStateException("part $partNumber was rejected by the object store with status $status")

class ObjectStoreException(val status: Int) : IllegalStateException("the object store answered $status for this file")

interface ObjectStore {
    suspend fun put(part: UploadPart, body: ByteArray)

    suspend fun <T> read(url: String, range: ByteRange? = null, block: suspend (ByteSource) -> T): T
}

class HttpObjectStore(httpClient: HttpClient? = null) : ObjectStore, AutoCloseable {
    private val client = httpClient ?: defaultHttpClient()

    override suspend fun put(part: UploadPart, body: ByteArray) {
        val status = try {
            client.put(part.url) { setBody(ByteArrayContent(body)) }.status.value
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw NetworkError("PUT part ${part.number}", error)
        }
        if (status !in 200..299) throw PartUploadException(part.number, status)
    }

    override suspend fun <T> read(url: String, range: ByteRange?, block: suspend (ByteSource) -> T): T {
        val statement = client.prepareGet(url) {
            if (range != null) header(HttpHeaders.Range, "bytes=${range.start}-${range.endExclusive - 1}")
        }
        return try {
            statement.execute { response ->
                val status = response.status.value
                if (status !in 200..299) throw ObjectStoreException(status)
                block(ChannelSource(response.bodyAsChannel()))
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: ObjectStoreException) {
            throw error
        } catch (error: kotlinx.io.IOException) {
            throw NetworkError("GET object", error)
        }
    }

    override fun close() = client.close()
}

private class ChannelSource(private val channel: ByteReadChannel) : ByteSource {
    override suspend fun read(buffer: ByteArray, offset: Int, length: Int): Int = channel.readAvailable(buffer, offset, length)

    override fun close() {}
}

class ByteArraySource(private val bytes: ByteArray) : ByteSource {
    private var at = 0

    override suspend fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (at >= bytes.size) return -1
        val take = minOf(length, bytes.size - at)
        bytes.copyInto(buffer, offset, at, at + take)
        at += take
        return take
    }

    override fun close() {}
}

class ByteArrayUpload(override val name: String, override val mime: String, private val bytes: ByteArray) : UploadSource {
    override val size: Long get() = bytes.size.toLong()

    override suspend fun open(): ByteSource = ByteArraySource(bytes)
}

internal suspend fun ByteSource.readFully(buffer: ByteArray, offset: Int, length: Int): Int {
    var filled = 0
    while (filled < length) {
        val read = read(buffer, offset + filled, length - filled)
        if (read < 0) break
        filled += read
    }
    return filled
}
