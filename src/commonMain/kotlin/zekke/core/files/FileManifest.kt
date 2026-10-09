package zekke.core.files

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import zekke.core.api.wireJson
import zekke.core.folders.nowTimestamp
import zekke.core.memory.SecretBytes
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.sealed.openText
import zekke.core.sealed.sealText

class FileManifest internal constructor(val fields: JsonObject) {
    val name: String get() = fields.getValue("name").string()
    val mime: String get() = fields.getValue("mime").string()
    val size: Long get() = fields.getValue("size").whole()
    val chunkSize: Long get() = fields.getValue("chunk_size").whole()
    val chunkCount: Int get() = fields.getValue("chunk_count").whole().toInt()
    val firstChunkSha256: String? get() = fields["first_chunk_sha256"]?.string()
    val thumbnailId: String? get() = fields["thumbnail_id"]?.string()
    val createdAt: String get() = fields.getValue("created_at").string()

    fun renamed(name: String): FileManifest = FileManifest(JsonObject(fields + ("name" to JsonPrimitive(name))))
}

private fun JsonElement.string(): String = (this as JsonPrimitive).content

private fun JsonElement.whole(): Long = (this as JsonPrimitive).longOrNull ?: error("not a whole number")

class MalformedManifestException(reason: String) : IllegalStateException("this file's details could not be read: $reason")

class ManifestLayoutException(val expectedSizeBytes: Long, val rowSizeBytes: Long) : IllegalStateException(
    "this file does not match its stored size, so it has not been opened: its details describe $expectedSizeBytes stored " +
        "bytes and the drive holds $rowSizeBytes. This is almost always a fault in the upload that created it",
)

private val SHA256_HEX = Regex("^[0-9a-f]{64}$")

fun buildManifest(
    name: String,
    mime: String,
    size: Long,
    firstChunkSha256: String? = null,
    thumbnailId: String? = null,
    createdAt: String = nowTimestamp(),
): FileManifest = FileManifest(
    buildJsonObject {
        put("name", name)
        put("mime", mime)
        put("size", size)
        put("chunk_size", CHUNK_PAYLOAD_BYTES)
        put("chunk_count", layoutFor(size).chunkCount)
        if (firstChunkSha256 != null) put("first_chunk_sha256", firstChunkSha256)
        if (thumbnailId != null) put("thumbnail_id", thumbnailId)
        put("created_at", createdAt)
    },
)

fun sealManifest(manifest: FileManifest, dek: SecretBytes, primitives: Primitives = platformPrimitives()): String =
    sealText(wireJson.encodeToString(JsonObject.serializer(), manifest.fields), dek, primitives)

fun openManifest(ciphertext: String, dek: SecretBytes, primitives: Primitives = platformPrimitives()): FileManifest =
    parseManifest(openText(ciphertext, dek, primitives))

fun parseManifest(text: String): FileManifest {
    val parsed = try {
        wireJson.parseToJsonElement(text) as? JsonObject
    } catch (_: SerializationException) {
        null
    } ?: throw MalformedManifestException("it is not an object")
    for (field in listOf("name", "mime", "created_at")) {
        if ((parsed[field] as? JsonPrimitive)?.isString != true) throw MalformedManifestException("$field is missing")
    }
    for (field in listOf("size", "chunk_size", "chunk_count")) {
        val number = (parsed[field] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
        if (number == null || number < 0) throw MalformedManifestException("$field is not a whole number")
    }
    parsed["thumbnail_id"]?.let { if ((it as? JsonPrimitive)?.isString != true) throw MalformedManifestException("thumbnail_id is not an id") }
    parsed["first_chunk_sha256"]?.let {
        val digest = (it as? JsonPrimitive)?.takeIf { value -> value.isString }?.content
        if (digest == null || !SHA256_HEX.matches(digest)) throw MalformedManifestException("first_chunk_sha256 is not a digest")
    }
    return FileManifest(parsed)
}

fun assertManifestMatchesRow(manifest: FileManifest, rowSizeBytes: Long) {
    if (manifest.chunkSize != CHUNK_PAYLOAD_BYTES.toLong()) throw ManifestLayoutException(-1, rowSizeBytes)
    val layout = layoutFor(manifest.size)
    if (layout.chunkCount != manifest.chunkCount || layout.storedBytes != rowSizeBytes) {
        throw ManifestLayoutException(layout.storedBytes, rowSizeBytes)
    }
}
