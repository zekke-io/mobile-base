package zekke.core.keys

import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.primitives.P256Scalar
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

const val SLIP10_P256_CURVE_NAME = "Nist256p1 seed"
const val HARDENED_OFFSET = 0x80000000L

private const val KEY_LENGTH = 32

class Slip10Node(val privateKey: SecretBytes, val chainCode: SecretBytes)

private fun ser32(index: Long): ByteArray = byteArrayOf(
    (index ushr 24).toByte(),
    (index ushr 16).toByte(),
    (index ushr 8).toByte(),
    index.toByte(),
)

fun deriveMasterNode(seed: SecretBytes, primitives: Primitives = platformPrimitives()): Slip10Node {
    val curveKey = utf8ToBytes(SLIP10_P256_CURVE_NAME)
    var data = seed.withBytes { it.copyOf() }
    while (true) {
        val i = primitives.hmacSha512.mac(curveKey, data)
        zeroBytes(data)
        val il = i.copyOfRange(0, KEY_LENGTH)
        if (P256Scalar.isValidPrivateKey(il)) {
            val chainCode = i.copyOfRange(KEY_LENGTH, 2 * KEY_LENGTH)
            zeroBytes(i)
            return Slip10Node(privateKey = il.adoptAsSecret(), chainCode = chainCode.adoptAsSecret())
        }
        zeroBytes(il)
        data = i
    }
}

fun deriveHardenedChild(parent: Slip10Node, index: Long, primitives: Primitives = platformPrimitives()): Slip10Node {
    require(index in 0 until HARDENED_OFFSET) { "child index out of range for hardened derivation: $index" }
    val hardenedIndex = ser32(index + HARDENED_OFFSET)
    var data = parent.privateKey.withBytes { concatBytes(byteArrayOf(0x00), it, hardenedIndex) }
    while (true) {
        val i = parent.chainCode.withBytes { primitives.hmacSha512.mac(it, data) }
        zeroBytes(data)
        val il = i.copyOfRange(0, KEY_LENGTH)
        val ir = i.copyOfRange(KEY_LENGTH, 2 * KEY_LENGTH)
        zeroBytes(i)
        if (P256Scalar.isBelowOrder(il)) {
            val child = parent.privateKey.withBytes { P256Scalar.addModOrder(il, it) }
            zeroBytes(il)
            if (!P256Scalar.isZero(child)) return Slip10Node(privateKey = child.adoptAsSecret(), chainCode = ir.adoptAsSecret())
            zeroBytes(child)
        } else {
            zeroBytes(il)
        }
        data = concatBytes(byteArrayOf(0x01), ir, hardenedIndex)
        zeroBytes(ir)
    }
}

fun deriveHardenedPath(seed: SecretBytes, path: List<Long>, primitives: Primitives = platformPrimitives()): Slip10Node {
    var node = deriveMasterNode(seed, primitives)
    for (index in path) {
        val child = deriveHardenedChild(node, index, primitives)
        zeroSecrets(node.privateKey, node.chainCode)
        node = child
    }
    return node
}
