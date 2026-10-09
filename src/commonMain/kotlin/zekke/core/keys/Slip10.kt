package zekke.core.keys

import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
import zekke.core.primitives.P256Scalar
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

const val SLIP10_P256_CURVE_NAME = "Nist256p1 seed"
const val HARDENED_OFFSET = 0x80000000L

private const val KEY_LENGTH = 32

class Slip10Node(val privateKey: ByteArray, val chainCode: ByteArray)

private fun ser32(index: Long): ByteArray = byteArrayOf(
    (index ushr 24).toByte(),
    (index ushr 16).toByte(),
    (index ushr 8).toByte(),
    index.toByte(),
)

fun deriveMasterNode(seed: ByteArray, primitives: Primitives = platformPrimitives()): Slip10Node {
    val curveKey = utf8ToBytes(SLIP10_P256_CURVE_NAME)
    var data = seed
    while (true) {
        val i = primitives.hmacSha512.mac(curveKey, data)
        val il = i.copyOfRange(0, KEY_LENGTH)
        val ir = i.copyOfRange(KEY_LENGTH, 2 * KEY_LENGTH)
        if (data !== seed) zeroBytes(data)
        if (P256Scalar.isValidPrivateKey(il)) {
            zeroBytes(i)
            return Slip10Node(privateKey = il, chainCode = ir)
        }
        zeroBytes(il, ir)
        data = i
    }
}

fun deriveHardenedChild(parent: Slip10Node, index: Long, primitives: Primitives = platformPrimitives()): Slip10Node {
    require(index in 0 until HARDENED_OFFSET) { "child index out of range for hardened derivation: $index" }
    val hardenedIndex = ser32(index + HARDENED_OFFSET)
    var data = concatBytes(byteArrayOf(0x00), parent.privateKey, hardenedIndex)
    while (true) {
        val i = primitives.hmacSha512.mac(parent.chainCode, data)
        zeroBytes(data)
        val il = i.copyOfRange(0, KEY_LENGTH)
        val ir = i.copyOfRange(KEY_LENGTH, 2 * KEY_LENGTH)
        zeroBytes(i)
        if (P256Scalar.isBelowOrder(il)) {
            val child = P256Scalar.addModOrder(il, parent.privateKey)
            zeroBytes(il)
            if (!P256Scalar.isZero(child)) return Slip10Node(privateKey = child, chainCode = ir)
            zeroBytes(child)
        } else {
            zeroBytes(il)
        }
        data = concatBytes(byteArrayOf(0x01), ir, hardenedIndex)
        zeroBytes(ir)
    }
}

fun deriveHardenedPath(seed: ByteArray, path: List<Long>, primitives: Primitives = platformPrimitives()): Slip10Node {
    var node = deriveMasterNode(seed, primitives)
    for (index in path) {
        val child = deriveHardenedChild(node, index, primitives)
        zeroBytes(node.privateKey, node.chainCode)
        node = child
    }
    return node
}
