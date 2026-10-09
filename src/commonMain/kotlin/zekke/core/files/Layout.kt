package zekke.core.files

import zekke.core.encoding.concatBytes
import zekke.core.memory.SecretBytes
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.sealed.SEALED_IV_LENGTH
import zekke.core.sealed.openBytes
import zekke.core.sealed.sealBytesWithIv

const val CHUNK_PAYLOAD_BYTES = 8 shl 20
const val CHUNK_OVERHEAD_BYTES = 37
const val CHUNK_STRIDE_BYTES = CHUNK_PAYLOAD_BYTES + CHUNK_OVERHEAD_BYTES
const val PADDING_BUCKET_BYTES = 64 shl 10
const val POSITION_HEADER_BYTES = 8

class ObjectLayout(val paddedBytes: Long, val chunkCount: Int, val storedBytes: Long)

class ByteRange(val start: Long, val endExclusive: Long)

fun padToBucket(plaintextBytes: Long): Long {
    require(plaintextBytes >= 0) { "plaintext length $plaintextBytes is negative" }
    if (plaintextBytes == 0L) return PADDING_BUCKET_BYTES.toLong()
    return ceilDiv(plaintextBytes, PADDING_BUCKET_BYTES.toLong()) * PADDING_BUCKET_BYTES
}

fun chunkCountFor(paddedBytes: Long): Int = maxOf(1L, ceilDiv(paddedBytes, CHUNK_PAYLOAD_BYTES.toLong())).toInt()

fun layoutFor(plaintextBytes: Long): ObjectLayout {
    val padded = padToBucket(plaintextBytes)
    val count = chunkCountFor(padded)
    return ObjectLayout(padded, count, padded + count.toLong() * CHUNK_OVERHEAD_BYTES)
}

fun payloadBytesFor(paddedBytes: Long, index: Int): Int {
    val count = chunkCountFor(paddedBytes)
    require(index in 0 until count) { "chunk $index is outside a $count-chunk object" }
    return if (index < count - 1) CHUNK_PAYLOAD_BYTES else (paddedBytes - index.toLong() * CHUNK_PAYLOAD_BYTES).toInt()
}

fun sealedChunkLength(payloadBytes: Int): Int = payloadBytes + CHUNK_OVERHEAD_BYTES

fun chunkRange(paddedBytes: Long, index: Int): ByteRange {
    val start = index.toLong() * CHUNK_STRIDE_BYTES
    return ByteRange(start, start + sealedChunkLength(payloadBytesFor(paddedBytes, index)))
}

private fun ceilDiv(value: Long, divisor: Long): Long = (value + divisor - 1) / divisor

class ChunkPositionException(val expectedIndex: Int, val expectedCount: Int, val foundIndex: Int, val foundCount: Int) :
    IllegalStateException("chunk claims position $foundIndex of $foundCount, but was read as $expectedIndex of $expectedCount")

fun chunkIv(index: Int): ByteArray = ByteArray(SEALED_IV_LENGTH).also { writeU32(it, SEALED_IV_LENGTH - 4, index) }

private fun writeU32(target: ByteArray, at: Int, value: Int) {
    target[at] = (value ushr 24).toByte()
    target[at + 1] = (value ushr 16).toByte()
    target[at + 2] = (value ushr 8).toByte()
    target[at + 3] = value.toByte()
}

private fun readU32(source: ByteArray, at: Int): Long =
    ((source[at].toLong() and 0xff) shl 24) or ((source[at + 1].toLong() and 0xff) shl 16) or
        ((source[at + 2].toLong() and 0xff) shl 8) or (source[at + 3].toLong() and 0xff)

fun sealChunk(payload: ByteArray, index: Int, count: Int, dek: SecretBytes, primitives: Primitives = platformPrimitives()): ByteArray {
    require(count >= 1 && index in 0 until count) { "chunk $index is outside a $count-chunk object" }
    val header = ByteArray(POSITION_HEADER_BYTES).also {
        writeU32(it, 0, index)
        writeU32(it, 4, count)
    }
    val plaintext = concatBytes(header, payload)
    try {
        return sealBytesWithIv(plaintext, dek, chunkIv(index), primitives)
    } finally {
        plaintext.fill(0)
    }
}

fun openChunk(chunk: ByteArray, index: Int, count: Int, dek: SecretBytes, primitives: Primitives = platformPrimitives()): ByteArray {
    val plaintext = openBytes(chunk, dek, primitives)
    if (plaintext.size < POSITION_HEADER_BYTES) throw ChunkPositionException(index, count, -1, -1)
    val foundIndex = readU32(plaintext, 0)
    val foundCount = readU32(plaintext, 4)
    if (foundIndex != index.toLong() || foundCount != count.toLong()) {
        plaintext.fill(0)
        throw ChunkPositionException(index, count, foundIndex.toInt(), foundCount.toInt())
    }
    return plaintext.copyOfRange(POSITION_HEADER_BYTES, plaintext.size).also { plaintext.fill(0) }
}
