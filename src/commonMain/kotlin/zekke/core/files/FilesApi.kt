package zekke.core.files

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.assertCanonicalUuid
import zekke.core.api.collectPages
import zekke.core.api.wireJson
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.canonicalSelection
import zekke.core.items.signedBody
import zekke.core.scopes.Scope
import zekke.core.signing.Action

const val FILE_VERSION = "v1"
const val ROOT_FOLDER = "root"

object R2States {
    const val PENDING = "pending"
    const val OK = "ok"
    const val MISSING = "missing"
}

@Serializable
class FileRecord(
    val id: String,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    @SerialName("size_bytes") val sizeBytes: Long,
    @SerialName("ciphertext_sha256") val ciphertextSha256: String = "",
    val version: String = FILE_VERSION,
    @SerialName("r2_state") val r2State: String = R2States.PENDING,
    @SerialName("gcs_state") val gcsState: String = R2States.PENDING,
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("updated_at") val updatedAt: String = "",
    @SerialName("folder_id") val folderId: String? = null,
    @SerialName("deleted_at") val deletedAt: String? = null,
) {
    val isInVault: Boolean get() = r2State == R2States.OK
}

@Serializable
class UploadPart(val number: Int, val url: String, val size: Long)

@Serializable
class UploadTicket(
    val multipart: Boolean,
    @SerialName("chunk_size") val chunkSize: Long,
    val parts: List<UploadPart>,
    @SerialName("expires_at") val expiresAt: String,
)

@Serializable
class ResumeState(val uploaded: List<Int> = emptyList(), val parts: List<UploadPart> = emptyList())

@Serializable
class FileDownload(
    val id: String,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    @SerialName("size_bytes") val sizeBytes: Long,
    @SerialName("ciphertext_sha256") val ciphertextSha256: String = "",
    @SerialName("r2_state") val r2State: String = R2States.PENDING,
    val url: String,
    @SerialName("expires_at") val expiresAt: String = "",
)

@Serializable
class StorageUsage(
    @SerialName("used_bytes") val usedBytes: Long,
    @SerialName("stored_bytes") val storedBytes: Long = 0,
    @SerialName("quota_bytes") val quotaBytes: Long,
    @SerialName("file_count") val fileCount: Long = 0,
    @SerialName("attachment_bytes") val attachmentBytes: Long? = null,
) {
    val remainingBytes: Long get() = maxOf(0, quotaBytes - usedBytes)

    fun fits(storedBytes: Long): Boolean = usedBytes + storedBytes <= quotaBytes
}

@Serializable
class FileDeleteResult(val requested: Int, val deleted: Int)

class CreateFileResult(val file: FileRecord, val upload: UploadTicket?, val created: Boolean)

fun fileDeks(context: ItemContext): ScopeDeks = ScopeDeks(context, Scope.FILES)

suspend fun createFile(
    context: ItemContext,
    id: String,
    ciphertext: String,
    wrappedDek: String,
    keyGeneration: Int,
    sizeBytes: Long,
    chunkCount: Int,
): CreateFileResult {
    require(sizeBytes >= 1) { "size_bytes must be positive, got $sizeBytes" }
    require(chunkCount >= 1) { "chunk_count must be positive, got $chunkCount" }
    val body = buildJsonObject {
        put("id", assertCanonicalUuid(id))
        put("ciphertext", ciphertext)
        put("wrapped_dek", wrappedDek)
        put("key_generation", keyGeneration)
        put("size_bytes", sizeBytes)
        put("chunk_count", chunkCount)
        put("version", FILE_VERSION)
    }
    val response = context.api.request(Method.POST, "/files", body = body, token = context.api.tokens.require())
    val upload = (response.data as? JsonObject)?.get("upload")?.let { wireJson.decodeFromJsonElement(UploadTicket.serializer(), it) }
    return CreateFileResult(response.decode(FileRecord.serializer()), upload, response.status == 201)
}

suspend fun listFiles(context: ItemContext, folder: String? = null, limit: Int? = null): List<FileRecord> = collectPages { cursor ->
    val response = context.api.request(
        Method.GET,
        "/files",
        token = context.api.tokens.require(),
        query = mapOf("limit" to limit?.toString(), "cursor" to cursor, "folder" to folder),
    )
    val page = if (response.data == null) emptyList() else response.decode(ListSerializer(FileRecord.serializer()))
    page to response.page
}

suspend fun getStorageUsage(context: ItemContext): StorageUsage =
    context.api.request(Method.GET, "/files/usage", token = context.api.tokens.require()).decode(StorageUsage.serializer())

suspend fun getFileDownload(context: ItemContext, id: String): FileDownload =
    context.api.request(Method.GET, "/files/${assertCanonicalUuid(id)}", token = context.api.tokens.require())
        .decode(FileDownload.serializer())

suspend fun getUploadState(context: ItemContext, id: String): ResumeState =
    context.api.request(Method.GET, "/files/${assertCanonicalUuid(id)}/upload", token = context.api.tokens.require())
        .decode(ResumeState.serializer())

private val SHA256_HEX = Regex("^[0-9a-f]{64}$")

suspend fun completeUpload(context: ItemContext, id: String, ciphertextSha256: String): FileRecord {
    require(SHA256_HEX.matches(ciphertextSha256)) { "ciphertext_sha256 must be 64 lowercase hex characters" }
    val body = buildJsonObject { put("ciphertext_sha256", ciphertextSha256) }
    return context.api.request(Method.PATCH, "/files/${assertCanonicalUuid(id)}", body = body, token = context.api.tokens.require())
        .decode(FileRecord.serializer())
}

suspend fun abandonUpload(context: ItemContext, id: String) {
    try {
        context.api.request(Method.DELETE, "/files/${assertCanonicalUuid(id)}/upload", token = context.api.tokens.require())
    } catch (error: ApiError) {
        if (error.status != 404) throw error
    }
}

suspend fun deleteFile(context: ItemContext, id: String) {
    val canonical = assertCanonicalUuid(id)
    val body = signedBody(context, Action.FILE_DELETE, listOf(canonical))
    context.api.request(Method.DELETE, "/files/$canonical", body = body, token = context.api.tokens.require())
}

suspend fun deleteFiles(context: ItemContext, ids: List<String>): FileDeleteResult {
    val normalized = canonicalSelection(Action.FILE_DELETE, ids)
    val body = signedBody(context, Action.FILE_DELETE, normalized) { putJsonArray("ids") { normalized.forEach { add(it) } } }
    return context.api.request(Method.DELETE, "/files", body = body, token = context.api.tokens.require())
        .decode(FileDeleteResult.serializer())
}
