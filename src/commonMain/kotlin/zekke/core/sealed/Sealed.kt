package zekke.core.sealed

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToUtf8
import zekke.core.encoding.concatBytes
import zekke.core.encoding.zeroBytes
import zekke.core.primitives.AesGcm
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

const val SEALED_VERSION: Byte = 0x01
const val SEALED_IV_LENGTH = AesGcm.IV_BYTES
const val SEALED_TAG_LENGTH = AesGcm.TAG_BYTES

private const val MIN_SEALED_LENGTH = 1 + SEALED_IV_LENGTH + SEALED_TAG_LENGTH

class UnsupportedSealedVersionException(val version: Byte) :
    IllegalArgumentException("unsupported sealed blob version byte 0x${(version.toInt() and 0xff).toString(16).padStart(2, '0')}")

class MalformedSealedBlobException(message: String) : IllegalArgumentException("malformed sealed blob: $message")

class SealedBlobAuthenticationException : IllegalStateException("sealed blob did not authenticate under this key")

fun sealBytes(plaintext: ByteArray, key: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray =
    sealBytesWithIv(plaintext, key, primitives.secureRandom.nextBytes(SEALED_IV_LENGTH), primitives)

internal fun sealBytesWithIv(plaintext: ByteArray, key: ByteArray, iv: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray {
    if (iv.size != SEALED_IV_LENGTH) {
        throw MalformedSealedBlobException("a supplied IV must be $SEALED_IV_LENGTH bytes, got ${iv.size}")
    }
    return concatBytes(byteArrayOf(SEALED_VERSION), iv, primitives.aesGcm.encrypt(key, iv, plaintext))
}

fun openBytes(blob: ByteArray, key: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray {
    if (blob.size < MIN_SEALED_LENGTH) {
        throw MalformedSealedBlobException("${blob.size} bytes, shorter than the $MIN_SEALED_LENGTH-byte minimum")
    }
    if (blob[0] != SEALED_VERSION) throw UnsupportedSealedVersionException(blob[0])
    val iv = blob.copyOfRange(1, 1 + SEALED_IV_LENGTH)
    val sealed = blob.copyOfRange(1 + SEALED_IV_LENGTH, blob.size)
    return primitives.aesGcm.decrypt(key, iv, sealed) ?: throw SealedBlobAuthenticationException()
}

fun sealBlob(plaintext: ByteArray, key: ByteArray, primitives: Primitives = platformPrimitives()): String =
    bytesToBase64(sealBytes(plaintext, key, primitives))

fun openBlob(blobBase64: String, key: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray =
    openBytes(base64ToBytes(blobBase64), key, primitives)

fun sealText(plaintext: String, key: ByteArray, primitives: Primitives = platformPrimitives()): String {
    val bytes = plaintext.encodeToByteArray()
    try {
        return sealBlob(bytes, key, primitives)
    } finally {
        zeroBytes(bytes)
    }
}

fun openText(blobBase64: String, key: ByteArray, primitives: Primitives = platformPrimitives()): String {
    val bytes = openBlob(blobBase64, key, primitives)
    try {
        return bytesToUtf8(bytes)
    } finally {
        zeroBytes(bytes)
    }
}
