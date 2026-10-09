package zekke.core.files

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import zekke.core.api.wireJson
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.hexToBytes
import zekke.core.fixtures.WEB_DRIVE_OBJECT_JSON
import zekke.core.keyrings.generateScopeKek
import zekke.core.memory.adoptAsSecret
import zekke.core.primitives.primitives
import zekke.core.sealed.SealedBlobAuthenticationException
import zekke.core.sealed.UnsupportedSealedVersionException
import zekke.core.sealed.sealBytes
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class FilesFormatTest {
    private val web = Json.parseToJsonElement(WEB_DRIVE_OBJECT_JSON).jsonObject

    private fun content(size: Int) = ByteArray(size) { ((it.toLong() * 31 + 7) % 251).toByte() }

    private fun sealObject(bytes: ByteArray, dek: zekke.core.memory.SecretBytes): List<ByteArray> {
        val layout = layoutFor(bytes.size.toLong())
        var at = 0
        return (0 until layout.chunkCount).map { index ->
            val payload = ByteArray(payloadBytesFor(layout.paddedBytes, index))
            val take = minOf(payload.size, bytes.size - at)
            bytes.copyInto(payload, 0, at, at + take)
            at += take
            sealChunk(payload, index, layout.chunkCount, dek, primitives)
        }
    }

    @Test
    fun theLayoutPadsChunksAndDerivesTheStoredSize() {
        assertEquals(8_388_645, CHUNK_STRIDE_BYTES)
        assertEquals(65_536L, padToBucket(0))
        assertEquals(65_536L, padToBucket(40_000))
        assertEquals(131_072L, padToBucket(65_537))
        assertEquals(65_573L, layoutFor(65_536).storedBytes)
        assertEquals(1, layoutFor(CHUNK_PAYLOAD_BYTES.toLong()).chunkCount)
        val twoChunks = layoutFor(CHUNK_PAYLOAD_BYTES + 1L)
        assertEquals(2, twoChunks.chunkCount)
        assertEquals(twoChunks.paddedBytes + 2 * CHUNK_OVERHEAD_BYTES, twoChunks.storedBytes)
        assertNotEquals(twoChunks.chunkCount.toLong() * CHUNK_STRIDE_BYTES, twoChunks.storedBytes)
        assertEquals(65_536, payloadBytesFor(twoChunks.paddedBytes, 1))
        assertEquals(CHUNK_STRIDE_BYTES.toLong(), chunkRange(twoChunks.paddedBytes, 1).start)
        assertEquals(twoChunks.storedBytes, chunkRange(twoChunks.paddedBytes, 1).endExclusive)
        assertFailsWith<IllegalArgumentException> { padToBucket(-1) }
        assertFailsWith<IllegalArgumentException> { payloadBytesFor(twoChunks.paddedBytes, 2) }
        val gib = layoutFor(1L shl 30)
        assertEquals(128, gib.chunkCount)
        assertEquals((1L shl 30) + 128 * 37, gib.storedBytes)
    }

    @Test
    fun aChunkIsBoundToItsPositionItsObjectAndItsKey() {
        val dek = generateScopeKek(primitives)
        val chunk = sealChunk(byteArrayOf(1, 2, 3), 1, 3, dek, primitives)
        assertEquals(3 + CHUNK_OVERHEAD_BYTES, chunk.size)
        assertEquals(1, chunk[0].toInt())
        assertContentEquals(byteArrayOf(1, 2, 3), openChunk(chunk, 1, 3, dek, primitives))
        assertContentEquals(chunk, sealChunk(byteArrayOf(1, 2, 3), 1, 3, dek, primitives))
        assertEquals("000000000000000000000007", bytesToHex(chunkIv(7)))
        val wrongIndex = assertFailsWith<ChunkPositionException> { openChunk(chunk, 0, 3, dek, primitives) }
        assertEquals(1 to 3, wrongIndex.foundIndex to wrongIndex.foundCount)
        assertFailsWith<ChunkPositionException> { openChunk(chunk, 1, 4, dek, primitives) }
        assertFailsWith<SealedBlobAuthenticationException> { openChunk(chunk, 1, 3, generateScopeKek(primitives), primitives) }
        assertFailsWith<SealedBlobAuthenticationException> { openChunk(chunk.copyOf().also { it[20] = (it[20] + 1).toByte() }, 1, 3, dek, primitives) }
        assertFailsWith<UnsupportedSealedVersionException> { openChunk(chunk.copyOf().also { it[0] = 2 }, 1, 3, dek, primitives) }
        assertFailsWith<IllegalArgumentException> { sealChunk(byteArrayOf(), 3, 3, dek, primitives) }
        val randomIv = sealBytes(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 1, 9), dek, primitives)
        assertContentEquals(byteArrayOf(9), openChunk(randomIv, 0, 1, dek, primitives))
    }

    @Test
    fun reproducesTheWebAppsChunksByteForByte() {
        val dek = hexToBytes(web.getValue("dek_hex").jsonPrimitive.content).adoptAsSecret()
        val small = web.getValue("small").jsonObject
        assertContentEquals(hexToBytes(small.getValue("object_hex").jsonPrimitive.content), sealObject(content(100), dek).single())
        val large = web.getValue("large").jsonObject
        val chunks = sealObject(content(large.getValue("size").jsonPrimitive.int), dek)
        assertEquals(large.getValue("chunk_sha256").jsonArray.map { it.jsonPrimitive.content }, chunks.map { bytesToHex(primitives.sha2.sha256(it)) })
        assertEquals(large.getValue("stored_bytes").jsonPrimitive.long, chunks.sumOf { it.size.toLong() })
    }

    @Test
    fun opensTheWebAppsObjectAndManifest() = runTest {
        val dek = hexToBytes(web.getValue("dek_hex").jsonPrimitive.content).adoptAsSecret()
        val large = web.getValue("large").jsonObject
        val manifest = openManifest(large.getValue("manifest_ciphertext").jsonPrimitive.content, dek, primitives)
        assertEquals("Relatório final.pdf", manifest.name)
        assertEquals(2, manifest.chunkCount)
        assertEquals("0c892e57-93cf-423a-a9e9-fee5a9f87681", manifest.thumbnailId)
        assertManifestMatchesRow(manifest, large.getValue("stored_bytes").jsonPrimitive.long)
        val rebuilt = buildManifest(manifest.name, manifest.mime, manifest.size, manifest.firstChunkSha256, manifest.thumbnailId, manifest.createdAt)
        assertEquals(large.getValue("manifest_json").jsonPrimitive.content, wireJson.encodeToString(JsonObject.serializer(), rebuilt.fields))

        val small = web.getValue("small").jsonObject
        val smallManifest = buildManifest("a", "text/plain", 100)
        val opened = openSealedObject(hexToBytes(small.getValue("object_hex").jsonPrimitive.content), smallManifest, dek, primitives)
        assertContentEquals(content(100), opened)
    }

    @Test
    fun aManifestIsCheckedAgainstTheRowAndKeepsWhatItDoesNotKnow() {
        val manifest = buildManifest("a.txt", "text/plain", 10, createdAt = "2026-10-09T00:00:00.000Z")
        assertManifestMatchesRow(manifest, 65_573)
        assertFailsWith<ManifestLayoutException> { assertManifestMatchesRow(manifest, 65_574) }
        assertNull(manifest.thumbnailId)
        val later = parseManifest("{\"name\":\"a\",\"mime\":\"m\",\"size\":1,\"chunk_size\":8388608,\"chunk_count\":1,\"created_at\":\"x\",\"later\":true}")
        assertEquals(
            "{\"name\":\"b\",\"mime\":\"m\",\"size\":1,\"chunk_size\":8388608,\"chunk_count\":1,\"created_at\":\"x\",\"later\":true}",
            wireJson.encodeToString(JsonObject.serializer(), later.renamed("b").fields),
        )
        for (bad in listOf("[]", "{\"mime\":\"m\",\"size\":1,\"chunk_size\":1,\"chunk_count\":1,\"created_at\":\"x\"}",
            "{\"name\":\"a\",\"mime\":\"m\",\"size\":1.5,\"chunk_size\":1,\"chunk_count\":1,\"created_at\":\"x\"}",
            "{\"name\":\"a\",\"mime\":\"m\",\"size\":-1,\"chunk_size\":1,\"chunk_count\":1,\"created_at\":\"x\"}",
            "{\"name\":\"a\",\"mime\":\"m\",\"size\":1,\"chunk_size\":1,\"chunk_count\":1,\"created_at\":\"x\",\"first_chunk_sha256\":\"zz\"}")) {
            assertFailsWith<MalformedManifestException>(bad) { parseManifest(bad) }
        }
    }

    @Test
    fun theStreamingHashEqualsTheOneShotHash() {
        val data = content(200_000)
        val streamed = primitives.sha2.sha256Stream().use { hash ->
            hash.update(data, 0, 70_000)
            hash.update(data, 70_000, 1)
            hash.update(data, 70_001, data.size - 70_001)
            hash.finish()
        }
        assertContentEquals(primitives.sha2.sha256(data), streamed)
    }

    @Test
    fun thumbnailsKeepTheirAspectAndOnlyDecodableKindsGetOne() {
        val wide = thumbnailExtent(4000, 3000)
        assertEquals(320 to 240, wide.width to wide.height)
        val small = thumbnailExtent(100, 50)
        assertEquals(100 to 50, small.width to small.height)
        assertEquals(1, thumbnailExtent(10_000, 1).height)
        assertEquals(true, canThumbnail("IMAGE/JPEG; charset=x"))
        assertEquals(false, canThumbnail("image/svg+xml"))
    }
}
