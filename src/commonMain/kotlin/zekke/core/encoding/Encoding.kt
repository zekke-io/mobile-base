package zekke.core.encoding

import kotlin.io.encoding.Base64

const val P256_UNCOMPRESSED_POINT_LENGTH = 65
const val P256_COORDINATE_LENGTH = 32
const val P256_SPKI_DER_LENGTH = 91
const val P256_SPKI_BASE64_LENGTH = 124

private val P256_SPKI_PREFIX = byteArrayOf(
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
)

private const val UNCOMPRESSED_POINT_TAG: Byte = 0x04

private const val HEX_ALPHABET = "0123456789abcdef"

private val base64UrlWithOptionalPadding = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)

fun bytesToHex(bytes: ByteArray): String {
    val hex = StringBuilder(bytes.size * 2)
    for (byte in bytes) {
        val value = byte.toInt() and 0xff
        hex.append(HEX_ALPHABET[value ushr 4]).append(HEX_ALPHABET[value and 0x0f])
    }
    return hex.toString()
}

fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string must have an even length" }
    val bytes = ByteArray(hex.length / 2)
    for (index in bytes.indices) {
        val high = hexDigit(hex[2 * index])
        val low = hexDigit(hex[2 * index + 1])
        bytes[index] = ((high shl 4) or low).toByte()
    }
    return bytes
}

private fun hexDigit(character: Char): Int = when (character) {
    in '0'..'9' -> character - '0'
    in 'a'..'f' -> character - 'a' + 10
    in 'A'..'F' -> character - 'A' + 10
    else -> throw IllegalArgumentException("hex string contains non-hex characters")
}

fun bytesToBase64(bytes: ByteArray): String = Base64.encode(bytes)

fun base64ToBytes(base64: String): ByteArray = Base64.decode(base64)

fun base64UrlToBytes(base64Url: String): ByteArray = base64UrlWithOptionalPadding.decode(base64Url)

fun utf8ToBytes(text: String): ByteArray = text.encodeToByteArray()

fun bytesToUtf8(bytes: ByteArray): String = bytes.decodeToString(throwOnInvalidSequence = true)

fun concatBytes(vararg chunks: ByteArray): ByteArray {
    val out = ByteArray(chunks.sumOf { it.size })
    var offset = 0
    for (chunk in chunks) {
        chunk.copyInto(out, offset)
        offset += chunk.size
    }
    return out
}

fun zeroBytes(vararg targets: ByteArray?) {
    for (target in targets) target?.fill(0)
}

fun bytesEqual(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var difference = 0
    for (index in a.indices) difference = difference or (a[index].toInt() xor b[index].toInt())
    return difference == 0
}

class P256Coordinates(val x: ByteArray, val y: ByteArray)

private fun assertUncompressedPoint(point: ByteArray) {
    require(point.size == P256_UNCOMPRESSED_POINT_LENGTH) {
        "uncompressed P-256 point must be $P256_UNCOMPRESSED_POINT_LENGTH bytes, got ${point.size}"
    }
    require(point[0] == UNCOMPRESSED_POINT_TAG) { "uncompressed P-256 point must start with 0x04" }
}

fun uncompressedPointToXY(point: ByteArray): P256Coordinates {
    assertUncompressedPoint(point)
    return P256Coordinates(
        x = point.copyOfRange(1, 1 + P256_COORDINATE_LENGTH),
        y = point.copyOfRange(1 + P256_COORDINATE_LENGTH, P256_UNCOMPRESSED_POINT_LENGTH),
    )
}

fun xyToUncompressedPoint(x: ByteArray, y: ByteArray): ByteArray {
    require(x.size == P256_COORDINATE_LENGTH && y.size == P256_COORDINATE_LENGTH) {
        "P-256 coordinates must be $P256_COORDINATE_LENGTH bytes each"
    }
    return concatBytes(byteArrayOf(UNCOMPRESSED_POINT_TAG), x, y)
}

fun uncompressedPointToSpkiDer(point: ByteArray): ByteArray {
    assertUncompressedPoint(point)
    return concatBytes(P256_SPKI_PREFIX, point)
}

fun spkiDerToUncompressedPoint(spki: ByteArray): ByteArray {
    require(spki.size == P256_SPKI_DER_LENGTH) { "P-256 SPKI DER must be $P256_SPKI_DER_LENGTH bytes, got ${spki.size}" }
    require(bytesEqual(spki.copyOfRange(0, P256_SPKI_PREFIX.size), P256_SPKI_PREFIX)) {
        "unexpected SPKI header — not an uncompressed P-256 public key"
    }
    return spki.copyOfRange(P256_SPKI_PREFIX.size, P256_SPKI_DER_LENGTH)
}

fun uncompressedPointToSpkiBase64(point: ByteArray): String = bytesToBase64(uncompressedPointToSpkiDer(point))

fun spkiBase64ToUncompressedPoint(spkiBase64: String): ByteArray = spkiDerToUncompressedPoint(base64ToBytes(spkiBase64))
