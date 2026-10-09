package zekke.core.oprf

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.primitives.PrimitiveFailureException
import zekke.core.primitives.Primitives
import zekke.core.primitives.Ristretto255
import zekke.core.primitives.platformPrimitives

const val OPRF_SUITE = "ristretto255-SHA512"
const val OPRF_MODE_BASE: Byte = 0x00
const val OPRF_CONTEXT_STRING = "OPRFV1-\u0000-$OPRF_SUITE"
const val OPRF_HASH_TO_GROUP_DST = "HashToGroup-$OPRF_CONTEXT_STRING"
const val OPRF_HASH_TO_SCALAR_DST = "HashToScalar-$OPRF_CONTEXT_STRING"
const val OPRF_OUTPUT_BYTES = 64
const val ELEMENT_BYTES = Ristretto255.POINT_BYTES

private const val SHA512_BYTES = 64
private const val SHA512_BLOCK_BYTES = 128
private const val FINALIZE_LABEL = "Finalize"

class MalformedElementException :
    IllegalArgumentException("the server returned an element that is not a valid ristretto255 encoding")

class BlindedPin internal constructor(val input: SecretBytes, val blind: SecretBytes, val blindedElement: String)

fun expandMessageXmd(message: ByteArray, dst: ByteArray, length: Int, primitives: Primitives = platformPrimitives()): ByteArray {
    val blocks = (length + SHA512_BYTES - 1) / SHA512_BYTES
    require(blocks in 1..255 && length <= 65535 && dst.size <= 255) { "expand_message_xmd parameters out of range" }
    val dstPrime = concatBytes(dst, byteArrayOf(dst.size.toByte()))
    val messagePrime = concatBytes(
        ByteArray(SHA512_BLOCK_BYTES),
        message,
        i2osp(length, 2),
        byteArrayOf(0),
        dstPrime,
    )
    val b0 = primitives.sha2.sha512(messagePrime)
    val output = ByteArray(blocks * SHA512_BYTES)
    var previous = primitives.sha2.sha512(concatBytes(b0, byteArrayOf(1), dstPrime))
    previous.copyInto(output, 0)
    for (index in 2..blocks) {
        val mixed = ByteArray(SHA512_BYTES) { (b0[it].toInt() xor previous[it].toInt()).toByte() }
        previous = primitives.sha2.sha512(concatBytes(mixed, byteArrayOf(index.toByte()), dstPrime))
        previous.copyInto(output, (index - 1) * SHA512_BYTES)
    }
    zeroBytes(b0, messagePrime)
    return output.copyOf(length)
}

fun hashToGroup(input: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray {
    val uniform = expandMessageXmd(input, utf8ToBytes(OPRF_HASH_TO_GROUP_DST), Ristretto255.UNIFORM_BYTES, primitives)
    try {
        return primitives.ristretto255.fromUniformBytes(uniform)
    } finally {
        zeroBytes(uniform)
    }
}

fun hashToScalar(input: ByteArray, dst: ByteArray = utf8ToBytes(OPRF_HASH_TO_SCALAR_DST), primitives: Primitives = platformPrimitives()): ByteArray {
    val uniform = expandMessageXmd(input, dst, Ristretto255.UNIFORM_BYTES, primitives)
    try {
        return primitives.ristretto255.reduceScalar(uniform)
    } finally {
        zeroBytes(uniform)
    }
}

fun blindPin(pin: CharArray, primitives: Primitives = platformPrimitives()): BlindedPin =
    primitives.ristretto255.randomScalar().adoptAsSecret().use { blind -> blindPinWithScalar(pin, blind, primitives) }

fun blindPinWithScalar(pin: CharArray, blind: SecretBytes, primitives: Primitives = platformPrimitives()): BlindedPin =
    pinInput(pin).use { input -> blindInputWithScalar(input, blind, primitives) }

fun blindInputWithScalar(input: SecretBytes, blind: SecretBytes, primitives: Primitives = platformPrimitives()): BlindedPin {
    val element = input.withBytes { hashToGroup(it, primitives) }
    val blindedElement = blind.withBytes { primitives.ristretto255.scalarMult(it, element) }
    return BlindedPin(input = input.copy(), blind = blind.copy(), blindedElement = bytesToBase64(blindedElement))
}

fun finalizePin(blinded: BlindedPin, evaluatedElement: String, primitives: Primitives = platformPrimitives()): SecretBytes {
    try {
        val evaluated = try {
            base64ToBytes(evaluatedElement)
        } catch (_: IllegalArgumentException) {
            throw MalformedElementException()
        }
        if (evaluated.size != ELEMENT_BYTES || !primitives.ristretto255.isValidPoint(evaluated)) throw MalformedElementException()
        val unblinded = blinded.blind.withBytes { blind ->
            val inverse = primitives.ristretto255.invertScalar(blind)
            try {
                primitives.ristretto255.scalarMult(inverse, evaluated)
            } catch (_: PrimitiveFailureException) {
                throw MalformedElementException()
            } finally {
                zeroBytes(inverse)
            }
        }
        val hashInput = blinded.input.withBytes { input ->
            concatBytes(i2osp(input.size, 2), input, i2osp(unblinded.size, 2), unblinded, utf8ToBytes(FINALIZE_LABEL))
        }
        try {
            return primitives.sha2.sha512(hashInput).adoptAsSecret()
        } finally {
            zeroBytes(hashInput, unblinded)
        }
    } finally {
        zeroSecrets(blinded.blind, blinded.input)
    }
}

internal fun pinInput(pin: CharArray): SecretBytes {
    require(pin.all { it.code < 0x80 }) { "a PIN is ASCII digits" }
    return ByteArray(pin.size) { pin[it].code.toByte() }.adoptAsSecret()
}

internal fun i2osp(value: Int, length: Int): ByteArray {
    require(value >= 0 && (length == 4 || value < (1 shl (8 * length)))) { "$value does not fit in $length bytes" }
    return ByteArray(length) { index -> (value ushr (8 * (length - 1 - index))).toByte() }
}
