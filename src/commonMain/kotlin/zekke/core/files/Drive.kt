package zekke.core.files

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.assertCanonicalUuid
import zekke.core.api.wireJson
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Replica
import zekke.core.feed.ReplicaItem
import zekke.core.folders.TreeScope
import zekke.core.folders.moveItemsToFolder
import zekke.core.items.ItemContext
import zekke.core.items.newItemId
import kotlin.math.max
import kotlin.math.roundToInt

const val THUMBNAIL_MAX_EDGE = 320
const val THUMBNAIL_MIME = "image/jpeg"
const val THUMBNAIL_QUALITY = 0.72
const val THUMBNAIL_NAME = "thumbnail.jpg"

private val THUMBNAILABLE = setOf("image/jpeg", "image/png", "image/webp", "image/gif", "image/avif", "image/bmp", "image/heic", "image/heif")

fun canThumbnail(mime: String): Boolean = mime.lowercase().substringBefore(';').trim() in THUMBNAILABLE

class Extent(val width: Int, val height: Int)

fun thumbnailExtent(width: Int, height: Int, maxEdge: Int = THUMBNAIL_MAX_EDGE): Extent {
    val longest = max(width, height)
    if (longest <= 0) return Extent(0, 0)
    if (longest <= maxEdge) return Extent(width, height)
    val scale = maxEdge.toDouble() / longest
    return Extent(max(1, (width * scale).roundToInt()), max(1, (height * scale).roundToInt()))
}

fun thumbnailIdsOf(manifests: Iterable<FileManifest?>): Set<String> = manifests.mapNotNull { it?.thumbnailId }.toSet()

class RenamedFile(val record: FileRecord, val manifest: FileManifest)

suspend fun renameFile(context: ItemContext, id: String, name: String): RenamedFile {
    val canonical = assertCanonicalUuid(id)
    val row = getFileDownload(context, canonical)
    return fileDeks(context).unwrap(row.wrappedDek, row.keyGeneration).use { dek ->
        val manifest = openManifest(row.ciphertext, dek, context.primitives).renamed(name)
        val body = buildJsonObject { put("ciphertext", sealManifest(manifest, dek, context.primitives)) }
        val response = context.api.request(Method.PUT, "/files/$canonical/manifest", body = body, token = context.api.tokens.require())
        RenamedFile(response.decode(FileRecord.serializer()), manifest)
    }
}

interface SealedObjectCache {
    suspend fun read(id: String): ByteArray?

    suspend fun write(id: String, sealed: ByteArray)

    suspend fun prune(keep: Set<String>)
}

class OpenedPreview(val bytes: ByteArray, val mime: String, val cached: Boolean)

suspend fun openPreview(context: ItemContext, record: FileRecord, store: ObjectStore, cache: SealedObjectCache? = null): OpenedPreview =
    fileDeks(context).unwrap(record.wrappedDek, record.keyGeneration).use { dek ->
        val manifest = openManifest(record.ciphertext, dek, context.primitives)
        assertManifestMatchesRow(manifest, record.sizeBytes)
        val held = cache?.read(record.id)
        val sealed = held ?: fetchSealedObject(context, record.id, store)
        val bytes = openSealedObject(sealed, manifest, dek, context.primitives)
        if (held == null) cache?.write(record.id, sealed)
        OpenedPreview(bytes, manifest.mime, held != null)
    }

class DriveUpload(val file: FileRecord, val thumbnailId: String?)

suspend fun uploadToDrive(
    context: ItemContext,
    source: UploadSource,
    store: ObjectStore,
    folderId: String? = null,
    thumbnail: ByteArray? = null,
    id: String = newItemId(context.primitives),
    options: UploadOptions = UploadOptions(),
): DriveUpload {
    val thumbnailId = thumbnail?.let { newItemId(context.primitives) }
    val stored = uploadFile(context, source, store, id, thumbnailId, options)
    val sentThumbnail = if (thumbnail != null && thumbnailId != null) uploadThumbnail(context, thumbnail, thumbnailId, store) else null
    if (folderId != null) moveItemsToFolder(context, TreeScope.FILES, listOfNotNull(stored.id, sentThumbnail), folderId)
    return DriveUpload(stored, sentThumbnail)
}

fun isCreationPaused(error: Throwable): Long? = (error as? ApiError)?.takeIf { it.isRateLimited }?.let { it.retryAfterSeconds ?: 30 }

class DriveFile(
    val record: FileRecord,
    val manifest: FileManifest?,
) {
    val id: String get() = record.id
    val name: String? get() = manifest?.name
    val mime: String? get() = manifest?.mime
    val size: Long? get() = manifest?.size
    val thumbnailId: String? get() = manifest?.thumbnailId
    val isPending: Boolean get() = record.r2State == R2States.PENDING
    val isMissing: Boolean get() = record.r2State == R2States.MISSING
    val readable: Boolean get() = manifest != null
}

fun fileRecords(items: List<ReplicaItem>): List<FileRecord> =
    items.map { wireJson.decodeFromJsonElement(FileRecord.serializer(), it.item) }

suspend fun openDriveFiles(context: ItemContext, records: List<FileRecord>): List<DriveFile> {
    val deks = fileDeks(context)
    deks.refreshForGenerations(records.map { it.keyGeneration }.toSet())
    return records.map { record ->
        val manifest = try {
            if (!context.session.hasKek(zekke.core.scopes.Scope.FILES, record.keyGeneration)) {
                null
            } else {
                deks.unwrapHeld(record.wrappedDek, record.keyGeneration).use { dek -> openManifest(record.ciphertext, dek, context.primitives) }
            }
        } catch (error: zekke.core.memory.SecretZeroedException) {
            throw error
        } catch (error: zekke.core.session.SessionLockedException) {
            throw error
        } catch (_: IllegalStateException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
        DriveFile(record, manifest)
    }
}

class DriveView(val live: List<DriveFile>, val trashed: List<DriveFile>) {
    fun inFolder(folderId: String?): List<DriveFile> = live.filter { it.record.folderId == folderId }
}

suspend fun driveView(context: ItemContext, items: List<ReplicaItem>): DriveView {
    val opened = openDriveFiles(context, fileRecords(items))
    val thumbnails = thumbnailIdsOf(opened.map { it.manifest })
    val (trashed, live) = opened.filter { it.id !in thumbnails }.partition { it.record.deletedAt != null }
    val ordered = compareBy<DriveFile> { it.name?.lowercase() ?: "" }.thenBy { it.id }
    return DriveView(live.sortedWith(ordered), trashed.sortedByDescending { it.record.deletedAt })
}

suspend fun driveView(context: ItemContext, replica: Replica): DriveView =
    driveView(context, replica.items(FeedScope.FILES, ItemTypes.FILE))

fun storedFileCount(records: List<FileRecord>, thumbnailIds: Set<String>): Int =
    records.count { it.isInVault && it.id !in thumbnailIds && it.deletedAt == null }
