package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EcdsaP256Test {
    private val order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551".hexToBytes()

    @Test
    fun derivesThePublicPointFromARawScalar() {
        assertEquals(
            TestVectors.string("identity_key_p256", "public_key_uncompressed_hex"),
            primitives.ecdsaP256.publicKey(TestVectors.hex("identity_key_p256", "private_key_hex")).toHex(),
        )
    }

    @Test
    fun verifiesEveryGenesisChainSignatureIncludingHighS() {
        val rootPublicKey = TestVectors.hex("identity_key_p256", "public_key_uncompressed_hex")
        var highSSignatures = 0
        for (index in 0 until 3) {
            val statement = TestVectors.string("device_keys", "genesis_chain", index, "statement").utf8()
            val signature = TestVectors.base64("device_keys", "genesis_chain", index, "signature_base64")
            if (isHighS(signature)) highSSignatures++
            assertTrue(primitives.ecdsaP256.verify(rootPublicKey, statement, signature), "chain event $index")
        }
        assertTrue(highSSignatures > 0, "the chain must keep at least one high-S signature")
    }

    @Test
    fun signsAndVerifiesInP1363Form() {
        val privateKey = TestVectors.hex("device_keys", "genesis_device", "signing_private_key_hex")
        val publicKey = primitives.ecdsaP256.publicKey(privateKey)
        val message = "challenge:1767225600".utf8()
        val signature = primitives.ecdsaP256.sign(privateKey, message)
        assertEquals(EcdsaP256.SIGNATURE_BYTES, signature.size)
        assertTrue(primitives.ecdsaP256.verify(publicKey, message, signature))
        assertFalse(primitives.ecdsaP256.verify(publicKey, "challenge:1767225601".utf8(), signature))
    }

    private fun isHighS(signature: ByteArray): Boolean {
        val s =signature.copyOfRange(32, 64)
        val doubled = ByteArray(33)
        var carry = 0
        for (index in 31 downTo 0) {
            val sum = ((s[index].toInt() and 0xff) shl 1) + carry
            doubled[index + 1] = sum.toByte()
            carry = sum ushr 8
        }
        doubled[0] = carry.toByte()
        val orderWithPrefix = byteArrayOf(0) + order
        for (index in doubled.indices) {
            val left = doubled[index].toInt() and 0xff
            val right = orderWithPrefix[index].toInt() and 0xff
            if (left != right) return left > right
        }
        return false
    }
}
