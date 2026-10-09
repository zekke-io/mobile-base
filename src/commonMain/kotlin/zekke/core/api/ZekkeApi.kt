package zekke.core.api

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.content.TextContent
import io.ktor.http.ContentType
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import zekke.core.memory.newPlatformLock
import zekke.core.memory.withLock
import zekke.core.signing.currentTimestamp
import kotlin.math.abs
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

const val DEFAULT_BASE_URL = "http://localhost:8080"
const val MAX_BODY_BYTES = 1024 * 1024
const val DOCUMENT_MAX_BODY_BYTES = 8 * 1024 * 1024
val DEFAULT_TIMEOUT: Duration = 30.seconds
val MIN_TIMEOUT: Duration = 2.seconds
const val CLOCK_SKEW_WARNING_SECONDS = 120L

val wireJson: Json = Json {
    explicitNulls = false
    ignoreUnknownKeys = true
    encodeDefaults = true
}

@Serializable
class PageInfo(
    @SerialName("next_cursor") val nextCursor: String? = null,
    @SerialName("has_more") val hasMore: Boolean = false,
)

class ApiResponse(val status: Int, val message: String?, val data: JsonElement?, val page: PageInfo?) {
    fun <T> decode(serializer: KSerializer<T>): T {
        val element = data ?: throw MissingDataException()
        return wireJson.decodeFromJsonElement(serializer, element)
    }
}

class MissingDataException : IllegalStateException("the response carried no data")

internal expect fun defaultHttpClient(): HttpClient

enum class Method(internal val ktor: HttpMethod) {
    GET(HttpMethod.Get),
    POST(HttpMethod.Post),
    PUT(HttpMethod.Put),
    PATCH(HttpMethod.Patch),
    DELETE(HttpMethod.Delete),
}

class ZekkeApi(
    baseUrl: String = DEFAULT_BASE_URL,
    val tokens: TokenStore = TokenStore(),
    private val clientIdentity: ClientIdentity? = null,
    val defaultTimeout: Duration = DEFAULT_TIMEOUT,
    httpClient: HttpClient? = null,
    private val nowEpochSeconds: () -> Long = ::currentTimestamp,
) {
    val baseUrl: String = baseUrl.trimEnd('/')
    private val client: HttpClient = (httpClient ?: defaultHttpClient()).config { install(HttpTimeout) }
    private val guard = newPlatformLock()
    private var lastClockOffset: Long? = null

    val serverClockOffsetSeconds: Long? get() = guard.withLock { lastClockOffset }

    val isClockSkewed: Boolean get() = serverClockOffsetSeconds?.let { abs(it) > CLOCK_SKEW_WARNING_SECONDS } ?: false

    suspend fun request(
        method: Method,
        path: String,
        body: JsonElement? = null,
        token: String? = null,
        query: Map<String, String?> = emptyMap(),
        timeout: Duration = defaultTimeout,
        maxBodyBytes: Int = MAX_BODY_BYTES,
    ): ApiResponse {
        val normalized = if (path.startsWith('/')) path else "/$path"
        val endpoint = "${method.name} $normalized"
        val serialized = body?.let { wireJson.encodeToString(JsonElement.serializer(), it) }
        if (serialized != null) {
            val bytes = serialized.encodeToByteArray().size
            if (bytes > maxBodyBytes) throw RequestTooLargeException(bytes, maxBodyBytes)
        }
        val effectiveTimeout = if (timeout < MIN_TIMEOUT) MIN_TIMEOUT else timeout

        val response: HttpResponse = try {
            client.request(baseUrl + normalized) {
                this.method = method.ktor
                for ((name, value) in query) if (value != null) parameter(name, value)
                if (token != null) header(HttpHeaders.Authorization, "Bearer $token")
                if (clientIdentity != null) header(CLIENT_HEADER, clientIdentity.header)
                if (serialized != null) setBody(TextContent(serialized, ContentType.Application.Json))
                timeout { requestTimeoutMillis = effectiveTimeout.inWholeMilliseconds }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw NetworkError(endpoint, error)
        }

        recordClockOffset(response.headers[HttpHeaders.Date])

        val status = response.status.value
        if (status == 204) return ApiResponse(204, null, null, null)

        val raw = try {
            response.bodyAsText()
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw NetworkError(endpoint, error)
        }
        val parsed: JsonObject? = try {
            if (raw.isEmpty()) null else wireJson.parseToJsonElement(raw) as? JsonObject
        } catch (_: SerializationException) {
            null
        }

        if (status !in 200..299) {
            val code = (parsed?.get("code") as? JsonPrimitive)?.takeIf { it.isString }?.content ?: fallbackCode(status)
            throw ApiError(
                code = code,
                status = status,
                endpoint = endpoint,
                allow = response.headers[HttpHeaders.Allow],
                retryAfterSeconds = parseRetryAfter(response.headers[HttpHeaders.RetryAfter]),
            )
        }

        return ApiResponse(
            status = status,
            message = (parsed?.get("message") as? JsonPrimitive)?.takeIf { it.isString }?.content,
            data = parsed?.get("data"),
            page = parsed?.get("page")?.let { wireJson.decodeFromJsonElement(PageInfo.serializer(), it) },
        )
    }

    private fun recordClockOffset(dateHeader: String?) {
        val serverSeconds = dateHeader?.let(::parseHttpDate) ?: return
        guard.withLock { lastClockOffset = serverSeconds - nowEpochSeconds() }
    }

    fun close() = client.close()
}

private val MONTHS = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
private val HTTP_DATE = Regex("^[A-Z][a-z]{2}, (\\d{2}) ([A-Z][a-z]{2}) (\\d{4}) (\\d{2}):(\\d{2}):(\\d{2}) GMT$")

fun parseHttpDate(value: String): Long? {
    val match = HTTP_DATE.matchEntire(value.trim()) ?: return null
    val (day, monthName, year, hour, minute, second) = match.destructured
    val month = MONTHS.indexOf(monthName) + 1
    if (month == 0) return null
    return daysFromCivil(year.toLong(), month.toLong(), day.toLong()) * 86_400 + hour.toLong() * 3600 + minute.toLong() * 60 + second.toLong()
}

private fun daysFromCivil(year: Long, month: Long, day: Long): Long {
    val y = if (month <= 2) year - 1 else year
    val era = (if (y >= 0) y else y - 399) / 400
    val yearOfEra = y - era * 400
    val dayOfYear = (153 * (if (month > 2) month - 3 else month + 9) + 2) / 5 + day - 1
    val dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
    return era * 146_097 + dayOfEra - 719_468
}

suspend fun <T> collectPages(
    maxPages: Int = 1000,
    fetchPage: suspend (cursor: String?) -> Pair<List<T>, PageInfo?>,
): List<T> {
    val items = mutableListOf<T>()
    var cursor: String? = null
    repeat(maxPages) {
        val (page, info) = fetchPage(cursor)
        items += page
        val next = info?.nextCursor
        if (info == null || !info.hasMore || next == null) return items
        cursor = next
    }
    throw IllegalStateException("pagination exceeded $maxPages pages: refusing to loop further")
}
