package zekke.core.files

import zekke.core.encoding.bytesToHex
import zekke.core.items.ItemContext
import zekke.core.memory.SecretBytes
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

const val DEFAULT_DOWNLOAD_BUFFER_BYTES = 128L shl 20

class TruncatedObjectException(val expectedChunks: Int, val foundChunks: Int) :
    IllegalStateException("this file is incomplete in storage: it should be $expectedChunks chunks and only $foundChunks arrived")

class ObjectTooLongException : IllegalStateException("the object is longer than its chunk count describes")

class ObjectDigestException(val expected: String, val found: String) :
    IllegalStateException("this file does not match the hash recorded for it (expected $expected, got $found)")

class DownloadBufferExceededException(val bytes: Long, val limit: Long) :
    IllegalArgumentException("this file is $bytes bytes and the in-memory limit is $limit: stream it to a sink instead")

class OpenedFile(val record: FileDownload, val manifest: FileManifest, val dek: SecretBytes) : AutoCloseable {
    override fun close() = dek.zero()
}

suspend fun openFile(context: ItemContext, id: String): OpenedFile {
    val record = getFileDownload(context, id)
    val dek = fileDeks(context).unwrap(record.wrappedDek, record.keyGeneration)
    try {
        val manifest = openManifest(record.ciphertext, dek, context.primitives)
        assertManifestMatchesRow(manifest, record.sizeBytes)
        return OpenedFile(record, manifest, dek)
    } catch (error: Throwable) {
        dek.zero()
        throw error
    }
}

suspend fun decryptObject(
    source: ByteSource,
    manifest: FileManifest,
    dek: SecretBytes,
    sink: PlaintextSink,
    expectedSha256: String? = null,
    onProgress: (Long, Long) -> Unit = { _, _ -> },
    primitives: Primitives = platformPrimitives(),
) {
    val padded = layoutFor(manifest.size).paddedBytes
    var emitted = 0L
    onProgress(0, manifest.size)
    primitives.sha2.sha256Stream().use { digest ->
        for (index in 0 until manifest.chunkCount) {
            val held = ByteArray(sealedChunkLength(payloadBytesFor(padded, index)))
            if (source.readFully(held, 0, held.size) != held.size) throw TruncatedObjectException(manifest.chunkCount, index)
            digest.update(held)
            val payload = openChunk(held, index, manifest.chunkCount, dek, primitives)
            try {
                val usable = minOf(payload.size.toLong(), manifest.size - emitted).coerceAtLeast(0).toInt()
                if (usable > 0) {
                    sink.write(payload, 0, usable)
                    emitted += usable
                    onProgress(emitted, manifest.size)
                }
            } finally {
                payload.fill(0)
            }
        }
        if (source.read(ByteArray(1), 0, 1) > 0) throw ObjectTooLongException()
        val found = bytesToHex(digest.finish())
        if (expectedSha256 != null && expectedSha256.isNotEmpty() && expectedSha256 != found) throw ObjectDigestException(expectedSha256, found)
    }
}

suspend fun downloadFile(
    context: ItemContext,
    id: String,
    store: ObjectStore,
    sink: PlaintextSink,
    verifyDigest: Boolean = true,
    onProgress: (Long, Long) -> Unit = { _, _ -> },
): FileManifest = openFile(context, id).use { opened ->
    store.read(opened.record.url) { source ->
        decryptObject(
            source,
            opened.manifest,
            opened.dek,
            sink,
            if (verifyDigest) opened.record.ciphertextSha256 else null,
            onProgress,
            context.primitives,
        )
    }
    opened.manifest
}

class DownloadedFile(val manifest: FileManifest, val bytes: ByteArray)

suspend fun downloadBytes(
    context: ItemContext,
    id: String,
    store: ObjectStore,
    maxBytes: Long = DEFAULT_DOWNLOAD_BUFFER_BYTES,
    onProgress: (Long, Long) -> Unit = { _, _ -> },
): DownloadedFile = openFile(context, id).use { opened ->
    if (opened.manifest.size > maxBytes) throw DownloadBufferExceededException(opened.manifest.size, maxBytes)
    val out = ByteArray(opened.manifest.size.toInt())
    var at = 0
    store.read(opened.record.url) { source ->
        decryptObject(source, opened.manifest, opened.dek, { bytes, offset, length ->
            bytes.copyInto(out, at, offset, offset + length)
            at += length
        }, opened.record.ciphertextSha256, onProgress, context.primitives)
    }
    DownloadedFile(opened.manifest, out)
}

suspend fun fetchSealedObject(context: ItemContext, id: String, store: ObjectStore): ByteArray {
    val record = getFileDownload(context, id)
    val expected = record.sizeBytes.toInt()
    return store.read(record.url) { source ->
        val sealed = ByteArray(expected)
        if (source.readFully(sealed, 0, expected) != expected) throw TruncatedObjectException(-1, -1)
        sealed
    }
}

suspend fun openSealedObject(sealed: ByteArray, manifest: FileManifest, dek: SecretBytes, primitives: Primitives = platformPrimitives()): ByteArray {
    val out = ByteArray(manifest.size.toInt())
    var at = 0
    decryptObject(ByteArraySource(sealed), manifest, dek, { bytes, offset, length ->
        bytes.copyInto(out, at, offset, offset + length)
        at += length
    }, primitives = primitives)
    return out
}

suspend fun readChunk(store: ObjectStore, url: String, manifest: FileManifest, index: Int, dek: SecretBytes, primitives: Primitives = platformPrimitives()): ByteArray {
    val range = chunkRange(layoutFor(manifest.size).paddedBytes, index)
    val length = (range.endExclusive - range.start).toInt()
    val chunk = store.read(url, range) { source ->
        ByteArray(length).also { if (source.readFully(it, 0, length) != length) throw TruncatedObjectException(manifest.chunkCount, index) }
    }
    return openChunk(chunk, index, manifest.chunkCount, dek, primitives)
}
