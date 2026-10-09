package zekke.core.pqxdh

import zekke.core.primitives.toHex
import zekke.core.memory.adoptAsSecret
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class PqxdhTest {
    private val userAddress = TestVectors.string("seed_and_user_address", "user_address")
    private val context = PqxdhContext(PqxdhUsage.ITEM_SHARE, userAddress, userAddress)
    private val ecdhSecret = TestVectors.secret("pqxdh", "intermediate", "ecdh_secret_hex")
    private val kemSecret = TestVectors.secret("pqxdh", "intermediate", "kem_secret_hex")
    private val wireBlob = TestVectors.string("pqxdh", "aead_wrap_example", "wire_blob_base64")
    private val recipientX25519Private = TestVectors.secret("x25519_key", "private_key_or_seed_hex")
    private val recipientMlKem = primitives.mlKem768.keyPairFromSeed(TestVectors.hex("mlkem768_key", "private_key_or_seed_hex"))
    private val secrets = RecipientSecrets(rawX25519Agreement(recipientX25519Private, primitives), recipientMlKem.secretKey.copyOf().adoptAsSecret())
    private val recipient = RecipientKeys(TestVectors.hex("x25519_key", "public_key_hex"), recipientMlKem.publicKey)

    @Test
    fun buildsTheRecordedInfoString() {
        assertEquals(TestVectors.string("pqxdh", "inputs", "info"), buildInfo(context))
    }

    @Test
    fun reproducesTheSessionKey() {
        assertEquals(
            TestVectors.string("pqxdh", "output", "session_key_hex"),
            deriveSessionKey(ecdhSecret, kemSecret, context, primitives).toHex(),
        )
    }

    @Test
    fun unwrapsTheRecordedWireBlob() {
        assertEquals(
            TestVectors.string("pqxdh", "aead_wrap_example", "plaintext_dek_hex"),
            pqxdhUnwrap(wireBlob, secrets, context, primitives).toHex(),
        )
    }

    @Test
    fun parsesTheRecordedLayout() {
        val parsed = parseBlob(wireBlob)
        assertEquals(PQXDH_VERSION, parsed.version)
        assertEquals(TestVectors.string("pqxdh", "inputs", "kem_ciphertext_hex"), bytesToHex(parsed.kemCiphertext))
        assertEquals(TestVectors.string("pqxdh", "inputs", "sender_ephemeral_x25519_public_hex"), bytesToHex(parsed.ephemeralPublicKey))
        assertEquals(TestVectors.string("pqxdh", "aead_wrap_example", "iv_hex"), bytesToHex(parsed.iv))
        assertEquals(TestVectors.string("pqxdh", "aead_wrap_example", "ciphertext_hex"), bytesToHex(parsed.sealed))
    }

    @Test
    fun theSessionKeyDivergesWhenAnyContextFieldOrTheIkmOrderChanges() {
        val expected = TestVectors.string("pqxdh", "output", "session_key_hex")
        val other = "0".repeat(64)
        val variants = listOf(
            deriveSessionKey(ecdhSecret, kemSecret, PqxdhContext(PqxdhUsage.DEVICE_KEYRING, userAddress, userAddress), primitives),
            deriveSessionKey(ecdhSecret, kemSecret, PqxdhContext(PqxdhUsage.ITEM_SHARE, other, userAddress), primitives),
            deriveSessionKey(ecdhSecret, kemSecret, PqxdhContext(PqxdhUsage.ITEM_SHARE, userAddress, other), primitives),
            deriveSessionKey(kemSecret, ecdhSecret, context, primitives),
        )
        for (variant in variants) assertNotEquals(expected, variant.toHex())
    }

    @Test
    fun wrapsAndUnwrapsForEveryUsageWithAFreshEphemeralAndIv() {
        val payload = TestVectors.secret("pqxdh", "aead_wrap_example", "plaintext_dek_hex")
        for (usage in PqxdhUsage.entries) {
            val usageContext = PqxdhContext(usage, userAddress, userAddress)
            val first = pqxdhWrap(payload, recipient, usageContext, primitives)
            val second = pqxdhWrap(payload, recipient, usageContext, primitives)
            assertEquals(1576, first.length)
            assertNotEquals(bytesToHex(parseBlob(first).ephemeralPublicKey), bytesToHex(parseBlob(second).ephemeralPublicKey))
            assertNotEquals(bytesToHex(parseBlob(first).iv), bytesToHex(parseBlob(second).iv))
            assertEquals(payload.toHex(), pqxdhUnwrap(first, secrets, usageContext, primitives).toHex())
        }
    }

    @Test
    fun refusesAnUnknownVersionAndAShortBlob() {
        val blob = base64ToBytes(wireBlob)
        assertFailsWith<UnsupportedPqxdhVersionException> { parseBlob(bytesToBase64(blob.copyOf().also { it[0] = 0x02 })) }
        assertFailsWith<MalformedPqxdhBlobException> { parseBlob(bytesToBase64(blob.copyOf(1 + 1088 + 32 + 12 + 15))) }
    }

    @Test
    fun aTamperedBlobOrAnotherContextDoesNotOpen() {
        val blob = base64ToBytes(wireBlob)
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        assertFailsWith<PqxdhAuthenticationException> { pqxdhUnwrap(bytesToBase64(blob), secrets, context, primitives) }
        val otherContext = PqxdhContext(PqxdhUsage.DEVICE_KEYRING, userAddress, userAddress)
        assertFailsWith<PqxdhAuthenticationException> { pqxdhUnwrap(wireBlob, secrets, otherContext, primitives) }
    }
}
