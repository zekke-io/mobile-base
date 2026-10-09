package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AesGcmTest {
    @Test
    fun encryptsWithACallerChosenIvLikeTheSealedBlobVector() {
        val key = TestVectors.hex("sealed_blob", "key_hex")
        val iv = TestVectors.hex("sealed_blob", "iv_hex")
        val plaintext = TestVectors.hex("sealed_blob", "plaintext_hex")
        val ciphertext = primitives.aesGcm.encrypt(key, iv, plaintext)
        assertEquals(TestVectors.string("sealed_blob", "ciphertext_with_tag_hex"), ciphertext.toHex())
        assertContentEquals(plaintext, primitives.aesGcm.decrypt(key, iv, ciphertext))
    }

    @Test
    fun decryptsThePqxdhWrapExample() {
        val sessionKey = TestVectors.hex("pqxdh", "output", "session_key_hex")
        val iv = TestVectors.hex("pqxdh", "aead_wrap_example", "iv_hex")
        val ciphertext = TestVectors.hex("pqxdh", "aead_wrap_example", "ciphertext_hex")
        assertEquals(
            TestVectors.string("pqxdh", "aead_wrap_example", "plaintext_dek_hex"),
            primitives.aesGcm.decrypt(sessionKey, iv, ciphertext)?.toHex(),
        )
    }

    @Test
    fun aTamperedCiphertextDoesNotOpen() {
        val key = TestVectors.hex("sealed_blob", "key_hex")
        val iv = TestVectors.hex("sealed_blob", "iv_hex")
        val ciphertext = TestVectors.hex("sealed_blob", "ciphertext_with_tag_hex")
        ciphertext[0] = (ciphertext[0].toInt() xor 1).toByte()
        assertNull(primitives.aesGcm.decrypt(key, iv, ciphertext))
    }
}
