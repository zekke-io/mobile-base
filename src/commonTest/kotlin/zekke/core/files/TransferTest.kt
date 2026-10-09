package zekke.core.files

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import zekke.core.encoding.bytesToHex
import zekke.core.items.SentRequest
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.newItemId
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MemoryObjectStore : ObjectStore {
    val parts = linkedMapOf<Int, ByteArray>()
    var failOnPart: Int? = null
    val puts = mutableListOf<Int>()

    fun whole(): ByteArray = parts.toSortedMap().values.fold(ByteArray(0)) { acc, part -> acc + part }

    override suspend fun put(part: UploadPart, body: ByteArray) {
        if (part.number == failOnPart) throw PartUploadException(part.number, 500)
        puts += part.number
        parts[part.number] = body.copyOf()
    }

    override suspend fun <T> read(url: String, range: ByteRange?, block: suspend (ByteSource) -> T): T {
        val object_ = whole()
        val bytes = if (range == null) object_ else object_.copyOfRange(range.start.toInt(), range.endExclusive.toInt())
        return block(ByteArraySource(bytes))
    }
}

class TransferTest {
    private fun content(size: Int, salt: Int = 0) = ByteArray(size) { ((it.toLong() * 31 + 7 + salt) % 251).toByte() }

    private fun ticket(count: Int, numbers: List<Int> = (1..count).toList()) = buildJsonObject {
        put("multipart", count > 1)
        put("chunk_size", CHUNK_PAYLOAD_BYTES)
        putJsonArray("parts") {
            numbers.forEach { n -> add(buildJsonObject { put("number", n); put("url", "mem://part/$n"); put("size", CHUNK_STRIDE_BYTES) }) }
        }
        put("expires_at", "2026-10-09T13:00:00Z")
    }

    private fun row(request: SentRequest, state: String = R2States.PENDING, sha: String = "") = JsonObject(
        request.json.filterKeys { it != "chunk_count" } + mapOf(
            "r2_state" to JsonPrimitive(state),
            "gcs_state" to JsonPrimitive("pending"),
            "ciphertext_sha256" to JsonPrimitive(sha),
            "created_at" to JsonPrimitive("2026-10-09T12:00:00Z"),
            "updated_at" to JsonPrimitive("2026-10-09T12:00:00Z"),
        ),
    )

    private lateinit var created: JsonObject

    private fun TestVault.acceptCreate(count: Int) = server.answer { request ->
        created = row(request)
        data(JsonObject(created + ("upload" to ticket(count))), 201)
    }

    private fun TestVault.acceptCompletion() = server.answer { request ->
        data(JsonObject(created + mapOf("r2_state" to JsonPrimitive("ok"), "ciphertext_sha256" to request.json.getValue("ciphertext_sha256"))))
    }

    private fun TestVault.serveDownload() = server.answer {
        data(JsonObject(created + mapOf("r2_state" to JsonPrimitive("ok"), "url" to JsonPrimitive("mem://object"))))
    }

    @Test
    fun anUploadSealsEveryChunkHashesTheObjectAndDownloadsBack() = runTest {
        val vault = TestVault()
        val store = MemoryObjectStore()
        val bytes = content(CHUNK_PAYLOAD_BYTES + 100)
        val progress = mutableListOf<UploadProgress>()
        vault.acceptCreate(2)
        vault.acceptCompletion()
        val stored = uploadFile(vault.context, ByteArrayUpload("photo.raw", "image/x-raw", bytes), store, options = UploadOptions(onProgress = { progress += it }))

        val (post, patch) = vault.server.sent
        assertEquals(2, post.json.getValue("chunk_count").jsonPrimitive.int)
        assertEquals(layoutFor(bytes.size.toLong()).storedBytes, post.json.getValue("size_bytes").jsonPrimitive.long)
        assertEquals("PATCH" to "/files/${stored.id}", patch.method to patch.path)
        assertEquals(bytesToHex(primitives.sha2.sha256(store.whole())), patch.json.getValue("ciphertext_sha256").jsonPrimitive.content)
        assertEquals(UploadPhase.COMPLETING, progress.last().phase)
        assertEquals(store.whole().size.toLong(), progress.last().doneBytes)

        vault.serveDownload()
        val downloaded = downloadBytes(vault.context, stored.id, store)
        assertContentEquals(bytes, downloaded.bytes)
        assertEquals("photo.raw", downloaded.manifest.name)

        vault.serveDownload()
        val opened = openFile(vault.context, stored.id)
        assertContentEquals(bytes.copyOfRange(CHUNK_PAYLOAD_BYTES, bytes.size), readChunk(store, opened.record.url, opened.manifest, 1, opened.dek, primitives).copyOf(100))
        opened.close()
    }

    @Test
    fun twoUploadsOfTheSameBytesUseDifferentKeys() = runTest {
        val vault = TestVault()
        val first = MemoryObjectStore()
        val second = MemoryObjectStore()
        repeat(2) {
            vault.acceptCreate(1)
            vault.acceptCompletion()
            uploadFile(vault.context, ByteArrayUpload("a", "text/plain", content(10)), if (it == 0) first else second)
        }
        assertTrue(!first.whole().contentEquals(second.whole()))
    }

    @Test
    fun aResumeSendsOnlyTheMissingPartsAndHashesTheWholeObject() = runTest {
        val vault = TestVault()
        val store = MemoryObjectStore().apply { failOnPart = 2 }
        val bytes = content(2 * CHUNK_PAYLOAD_BYTES + 5)
        val source = ByteArrayUpload("film.mov", "video/quicktime", bytes)
        vault.acceptCreate(3)
        assertFailsWith<PartUploadException> { uploadFile(vault.context, source, store, options = UploadOptions(concurrency = 1)) }
        val row = zekke.core.api.wireJson.decodeFromJsonElement(FileRecord.serializer(), created)

        store.failOnPart = null
        store.puts.clear()
        vault.server.reply(data(buildJsonObject {
            putJsonArray("uploaded") { add(1) }
            put("parts", ticket(3, listOf(2, 3)).getValue("parts"))
        }))
        vault.acceptCompletion()
        resumeUpload(vault.context, row, source, store)
        assertEquals(listOf(2, 3), store.puts.sorted())
        assertEquals(bytesToHex(primitives.sha2.sha256(store.whole())), vault.server.sent.last().json.getValue("ciphertext_sha256").jsonPrimitive.content)

        vault.serveDownload()
        assertContentEquals(bytes, downloadBytes(vault.context, row.id, store).bytes)
    }

    @Test
    fun aResumeRefusesAFileThatIsNotTheOneItStarted() = runTest {
        val vault = TestVault()
        val bytes = content(1000)
        vault.acceptCreate(1)
        assertFailsWith<PartUploadException> {
            uploadFile(vault.context, ByteArrayUpload("a.txt", "text/plain", bytes), MemoryObjectStore().apply { failOnPart = 1 })
        }
        val row = zekke.core.api.wireJson.decodeFromJsonElement(FileRecord.serializer(), created)
        suspend fun mismatch(source: UploadSource) = assertFailsWith<SourceMismatchException> { resumeUpload(vault.context, row, source, MemoryObjectStore()) }.mismatch
        assertEquals(SourceMismatch.SIZE, mismatch(ByteArrayUpload("a.txt", "text/plain", content(999))))
        assertEquals(SourceMismatch.NAME, mismatch(ByteArrayUpload("b.txt", "text/plain", bytes)))
        assertEquals(SourceMismatch.CONTENT, mismatch(ByteArrayUpload("a.txt", "text/plain", content(1000, salt = 1))))
        assertEquals(1, vault.server.sent.size)
    }

    @Test
    fun aSourceThatLiesAboutItsLengthIsRefused() = runTest {
        class Lying(override val size: Long, private val actual: ByteArray) : UploadSource {
            override val name = "x"
            override val mime = "y"

            override suspend fun open(): ByteSource = ByteArraySource(actual)
        }
        val vault = TestVault()
        assertFailsWith<SourceLengthException> { uploadFile(vault.context, Lying(100, content(50)), MemoryObjectStore()) }
        vault.acceptCreate(1)
        assertFailsWith<SourceLengthException> { uploadFile(vault.context, Lying(100, content(150)), MemoryObjectStore()) }
    }

    @Test
    fun aTruncatedOrAlteredObjectIsRefusedWhileStreaming() = runTest {
        val vault = TestVault()
        val store = MemoryObjectStore()
        vault.acceptCreate(2)
        vault.acceptCompletion()
        val stored = uploadFile(vault.context, ByteArrayUpload("a", "b", content(CHUNK_PAYLOAD_BYTES + 1)), store)
        vault.serveDownload()
        openFile(vault.context, stored.id).use { opened ->
            val whole = store.whole()
            assertFailsWith<TruncatedObjectException> {
                decryptObject(ByteArraySource(whole.copyOf(CHUNK_STRIDE_BYTES)), opened.manifest, opened.dek, { _, _, _ -> }, primitives = primitives)
            }
            assertFailsWith<ObjectTooLongException> {
                decryptObject(ByteArraySource(whole + byteArrayOf(0)), opened.manifest, opened.dek, { _, _, _ -> }, primitives = primitives)
            }
            assertFailsWith<ObjectDigestException> {
                decryptObject(ByteArraySource(whole), opened.manifest, opened.dek, { _, _, _ -> }, "0".repeat(64), primitives = primitives)
            }
        }
    }

    @Test
    fun aRenameReSealsTheManifestUnderTheSameKeyAndChangesOnlyTheName() = runTest {
        val vault = TestVault()
        vault.acceptCreate(1)
        vault.acceptCompletion()
        val stored = uploadFile(vault.context, ByteArrayUpload("old.txt", "text/plain", content(10)), MemoryObjectStore(), thumbnailId = newItemId(primitives))
        vault.serveDownload()
        vault.server.answer { data(JsonObject(created + ("ciphertext" to it.json.getValue("ciphertext")))) }
        val renamed = renameFile(vault.context, stored.id, "new.txt")
        val put = vault.server.sent.last()
        assertEquals("PUT" to "/files/${stored.id}/manifest", put.method to put.path)
        assertEquals(setOf("ciphertext"), put.json.keys)
        val dek = fileDeks(vault.context).unwrapHeld(stored.wrappedDek, stored.keyGeneration)
        val reopened = openManifest(put.json.getValue("ciphertext").jsonPrimitive.content, dek, primitives)
        assertEquals("new.txt", reopened.name)
        assertEquals(renamed.manifest.thumbnailId, reopened.thumbnailId)
        assertEquals(10, reopened.size)
    }
}
