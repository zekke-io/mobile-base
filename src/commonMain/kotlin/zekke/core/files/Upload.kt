package zekke.core.files

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import zekke.core.encoding.bytesToHex
import zekke.core.items.ItemContext
import zekke.core.items.generateDek
import zekke.core.items.itemIdOrNew
import zekke.core.keyrings.withCurrentGeneration
import zekke.core.memory.SecretBytes
import zekke.core.memory.newPlatformLock
import zekke.core.memory.withLock

const val DEFAULT_PART_CONCURRENCY = 3

class MissingUploadTicketException(id: String) : IllegalStateException("the server returned no upload ticket for $id")

enum class SourceMismatch { SIZE, NAME, NOT_RESUMABLE, CONTENT }

class SourceMismatchException(val mismatch: SourceMismatch) :
    IllegalArgumentException("this is not the file the unfinished upload was started with: ${mismatch.name.lowercase()}")

class SourceLengthException(val declared: Long, val produced: Long) :
    IllegalStateException("the source declared $declared bytes and produced ${if (produced > declared) "more" else produced.toString()}")

enum class UploadPhase { UPLOADING, COMPLETING }

class UploadProgress(val phase: UploadPhase, val doneBytes: Long, val totalBytes: Long)

class UploadOptions(
    val concurrency: Int = DEFAULT_PART_CONCURRENCY,
    val onProgress: (UploadProgress) -> Unit = {},
)

suspend fun uploadFile(
    context: ItemContext,
    source: UploadSource,
    store: ObjectStore,
    id: String? = null,
    thumbnailId: String? = null,
    options: UploadOptions = UploadOptions(),
): FileRecord {
    val fileId = itemIdOrNew(id, context.primitives)
    val layout = layoutFor(source.size)
    return generateDek(context.primitives).use { dek ->
        val manifest = buildManifest(
            name = source.name,
            mime = source.mime,
            size = source.size,
            firstChunkSha256 = firstChunkDigest(context, source, dek, layout),
            thumbnailId = thumbnailId,
        )
        val ciphertext = sealManifest(manifest, dek, context.primitives)
        val created = withCurrentGeneration(context.api, context.session) {
            val wrapped = fileDeks(context).wrap(dek)
            createFile(context, fileId, ciphertext, wrapped.wrappedDek, wrapped.keyGeneration, layout.storedBytes, layout.chunkCount)
        }
        if (!created.created) return@use continueStored(context, created.file, source, store, options)
        val ticket = created.upload ?: throw MissingUploadTicketException(fileId)
        val digest = streamChunks(context, source, dek, ticket.parts, layout, store, options)
        options.onProgress(UploadProgress(UploadPhase.COMPLETING, layout.storedBytes, layout.storedBytes))
        completeUpload(context, fileId, digest)
    }
}

private suspend fun continueStored(context: ItemContext, stored: FileRecord, source: UploadSource, store: ObjectStore, options: UploadOptions): FileRecord {
    if (!stored.isInVault) return resumeUpload(context, stored, source, store, options)
    fileDeks(context).unwrap(stored.wrappedDek, stored.keyGeneration).use { dek ->
        val manifest = openManifest(stored.ciphertext, dek, context.primitives)
        assertManifestMatchesRow(manifest, stored.sizeBytes)
        assertSameSource(context, source, manifest, dek)
    }
    return stored
}

suspend fun resumeUpload(
    context: ItemContext,
    row: FileRecord,
    source: UploadSource,
    store: ObjectStore,
    options: UploadOptions = UploadOptions(),
): FileRecord = fileDeks(context).unwrap(row.wrappedDek, row.keyGeneration).use { dek ->
    val manifest = openManifest(row.ciphertext, dek, context.primitives)
    assertManifestMatchesRow(manifest, row.sizeBytes)
    assertSameSource(context, source, manifest, dek)
    val layout = layoutFor(manifest.size)
    val state = getUploadState(context, row.id)
    val digest = streamChunks(context, source, dek, state.parts, layout, store, options, state.uploaded.toSet())
    options.onProgress(UploadProgress(UploadPhase.COMPLETING, layout.storedBytes, layout.storedBytes))
    completeUpload(context, row.id, digest)
}

private suspend fun assertSameSource(context: ItemContext, source: UploadSource, manifest: FileManifest, dek: SecretBytes) {
    if (source.size != manifest.size) throw SourceMismatchException(SourceMismatch.SIZE)
    if (source.name != manifest.name) throw SourceMismatchException(SourceMismatch.NAME)
    val expected = manifest.firstChunkSha256 ?: throw SourceMismatchException(SourceMismatch.NOT_RESUMABLE)
    if (firstChunkDigest(context, source, dek, layoutFor(manifest.size)) != expected) throw SourceMismatchException(SourceMismatch.CONTENT)
}

private suspend fun firstChunkDigest(context: ItemContext, source: UploadSource, dek: SecretBytes, layout: ObjectLayout): String {
    val payload = ByteArray(payloadBytesFor(layout.paddedBytes, 0))
    val wanted = minOf(payload.size.toLong(), source.size).toInt()
    val filled = source.open().use { it.readFully(payload, 0, wanted) }
    if (filled != wanted) {
        payload.fill(0)
        throw SourceLengthException(source.size, filled.toLong())
    }
    val chunk = sealChunk(payload, 0, layout.chunkCount, dek, context.primitives)
    payload.fill(0)
    return bytesToHex(context.primitives.sha2.sha256(chunk))
}

private suspend fun streamChunks(
    context: ItemContext,
    source: UploadSource,
    dek: SecretBytes,
    parts: List<UploadPart>,
    layout: ObjectLayout,
    store: ObjectStore,
    options: UploadOptions,
    skip: Set<Int> = emptySet(),
): String {
    val byNumber = parts.associateBy { it.number }
    val permits = Semaphore(maxOf(1, options.concurrency))
    val guard = newPlatformLock()
    var doneBytes = 0L
    fun advance(bytes: Int) {
        val done = guard.withLock { (doneBytes + bytes).also { doneBytes = it } }
        options.onProgress(UploadProgress(UploadPhase.UPLOADING, done, layout.storedBytes))
    }

    context.primitives.sha2.sha256Stream().use { digest ->
        source.open().use { input ->
            coroutineScope {
                var plaintextRead = 0L
                for (index in 0 until layout.chunkCount) {
                    val payload = ByteArray(payloadBytesFor(layout.paddedBytes, index))
                    val wanted = minOf(payload.size.toLong(), source.size - plaintextRead).coerceAtLeast(0).toInt()
                    val filled = input.readFully(payload, 0, wanted)
                    plaintextRead += filled
                    if (filled != wanted) {
                        payload.fill(0)
                        throw SourceLengthException(source.size, plaintextRead)
                    }
                    if (index == layout.chunkCount - 1 && input.read(ByteArray(1), 0, 1) > 0) {
                        payload.fill(0)
                        throw SourceLengthException(source.size, source.size + 1)
                    }
                    val chunk = sealChunk(payload, index, layout.chunkCount, dek, context.primitives)
                    payload.fill(0)
                    digest.update(chunk)
                    val number = index + 1
                    if (number in skip) {
                        advance(chunk.size)
                        continue
                    }
                    val part = byNumber[number] ?: throw MissingUploadTicketException("part $number")
                    permits.acquire()
                    launch {
                        try {
                            store.put(part, chunk)
                            advance(chunk.size)
                        } finally {
                            permits.release()
                        }
                    }
                }
            }
        }
        return bytesToHex(digest.finish())
    }
}

suspend fun uploadThumbnail(context: ItemContext, jpeg: ByteArray, id: String, store: ObjectStore): String? = try {
    uploadFile(context, ByteArrayUpload(THUMBNAIL_NAME, THUMBNAIL_MIME, jpeg), store, id).id
} catch (error: kotlinx.coroutines.CancellationException) {
    throw error
} catch (_: Exception) {
    null
}
