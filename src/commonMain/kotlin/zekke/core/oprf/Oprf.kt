package zekke.core.oprf

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
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

class BlindedPin internal constructor(val input: ByteArray, val blind: ByteArray, val blindedElement: String)

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

fun blindPin(pin: CharArray, primitives: Primitives = platformPrimitives()): BlindedPin {
    val blind = primitives.ristretto255.randomScalar()
    try {
        return blindInputWithScalar(pinInput(pin), blind, primitives)
    } finally {
        zeroBytes(blind)
    }
}

fun blindPinWithScalar(pin: CharArray, blind: ByteArray, primitives: Primitives = platformPrimitives()): BlindedPin =
    blindInputWithScalar(pinInput(pin), blind, primitives)

fun blindInputWithScalar(input: ByteArray, blind: ByteArray, primitives: Primitives = platformPrimitives()): BlindedPin {
    val element = hashToGroup(input, primitives)
    return BlindedPin(
        input = input.copyOf(),
        blind = blind.copyOf(),
        blindedElement = bytesToBase64(primitives.ristretto255.scalarMult(blind, element)),
    )
}

fun finalizePin(blinded: BlindedPin, evaluatedElement: String, primitives: Primitives = platformPrimitives()): ByteArray {
    try {
        val evaluated = try {
            base64ToBytes(evaluatedElement)
        } catch (_: IllegalArgumentException) {
            throw MalformedElementException()
        }
        if (evaluated.size != ELEMENT_BYTES || !primitives.ristretto255.isValidPoint(evaluated)) throw MalformedElementException()
        val inverse = primitives.ristretto255.invertScalar(blinded.blind)
        val unblinded = try {
            primitives.ristretto255.scalarMult(inverse, evaluated)
        } catch (_: PrimitiveFailureException) {
            throw MalformedElementException()
        } finally {
            zeroBytes(inverse)
        }
        val hashInput = concatBytes(
            i2osp(blinded.input.size, 2),
            blinded.input,
            i2osp(unblinded.size, 2),
            unblinded,
            utf8ToBytes(FINALIZE_LABEL),
        )
        try {
            return primitives.sha2.sha512(hashInput)
        } finally {
            zeroBytes(hashInput, unblinded)
        }
    } finally {
        zeroBytes(blinded.blind, blinded.input)
    }
}

internal fun pinInput(pin: CharArray): ByteArray {
    require(pin.all { it.code < 0x80 }) { "a PIN is ASCII digits" }
    return ByteArray(pin.size) { pin[it].code.toByte() }
}

internal fun i2osp(value: Int, length: Int): ByteArray {
    require(value >= 0 && (length == 4 || value < (1 shl (8 * length)))) { "$value does not fit in $length bytes" }
    return ByteArray(length) { index -> (value ushr (8 * (length - 1 - index))).toByte() }
}
