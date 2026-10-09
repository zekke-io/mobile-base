package zekke.core.memory

import zekke.core.keys.deriveKeyTreeFromSeed
import zekke.core.keys.deriveRootKeys
import zekke.core.oprf.deriveAccountProofKey
import zekke.core.oprf.deriveDevicePinKeys
import zekke.core.pqxdh.PqxdhContext
import zekke.core.pqxdh.PqxdhUsage
import zekke.core.pqxdh.RecipientSecrets
import zekke.core.pqxdh.pqxdhUnwrap
import zekke.core.pqxdh.rawX25519Agreement
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.sealSecretBlob
import zekke.core.signing.rawKeySigner
import zekke.core.signing.signPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecretBytesTest {
    @Test
    fun aZeroedSecretRefusesEveryUse() {
        val secret = byteArrayOf(1, 2, 3).adoptAsSecret()
        assertEquals(6, secret.withBytes { it.sum() })
        secret.zero()
        assertTrue(secret.isZeroed)
        assertFailsWith<SecretZeroedException> { secret.withBytes { it.size } }
        assertFailsWith<SecretZeroedException> { secret.copy() }
    }

    @Test
    fun adoptingTakesTheArrayAndZeroingClearsIt() {
        val bytes = byteArrayOf(7, 7, 7)
        bytes.adoptAsSecret().zero()
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun closingIsZeroing() {
        val secret = byteArrayOf(9).adoptAsSecret()
        secret.use { assertEquals(9, it.withBytes { bytes -> bytes[0].toInt() }) }
        assertTrue(secret.isZeroed)
    }

    @Test
    fun theContentIsNeverPrinted() {
        val secret = byteArrayOf(0x41, 0x42).adoptAsSecret()
        assertEquals("SecretBytes(2 bytes)", secret.toString())
        secret.zero()
        assertEquals("SecretBytes(2 bytes, zeroed)", secret.toString())
    }

    @Test
    fun aZeroedSecretLeavesTheRegistry() {
        val before = SecretRegistry.liveCount
        val secret = byteArrayOf(1).adoptAsSecret()
        assertEquals(before + 1, SecretRegistry.liveCount)
        secret.zero()
        assertEquals(before, SecretRegistry.liveCount)
    }

    @Test
    fun zeroingAllLeavesNoKeyOfAnyLayerUsable() {
        val userAddress = TestVectors.string("seed_and_user_address", "user_address")
        val pin = TestVectors.string("pin_oprf", "pin").toCharArray()
        val tree = deriveKeyTreeFromSeed(TestVectors.secret("seed_and_user_address", "seed_hex"), primitives)
        val root = deriveRootKeys(TestVectors.secret("seed_and_user_address", "seed_hex"), primitives)
        val deviceKeys = deriveDevicePinKeys(
            TestVectors.secret("pin_oprf", "evaluation", "oprf_output_hex"),
            pin,
            TestVectors.hex("pin_oprf", "argon2id", "device_salt_hex"),
            primitives,
        )
        val proofKey = deriveAccountProofKey(TestVectors.secret("pin_oprf", "evaluation", "oprf_output_hex"), pin, userAddress, primitives)
        val dek = pqxdhUnwrap(
            TestVectors.string("pqxdh", "aead_wrap_example", "wire_blob_base64"),
            RecipientSecrets(rawX25519Agreement(tree.x25519.privateKey, primitives), tree.mlkem768.secretKey),
            PqxdhContext(PqxdhUsage.ITEM_SHARE, userAddress, userAddress),
            primitives,
        )
        val rewrapped = openSecretBlob(sealSecretBlob(dek, root.wrapKey, primitives), root.wrapKey, primitives)
        val signer = rawKeySigner(root.signing.privateKey, primitives)

        val held = listOf(
            tree.seed, tree.identity.privateKey, tree.identity.chainCode, tree.x25519.privateKey,
            tree.mlkem768.seed, tree.mlkem768.secretKey, tree.vaultKek,
            root.signing.privateKey, root.signing.chainCode, root.wrapKey,
            deviceKeys.wrapKey, deviceKeys.confirmSeed, proofKey.seed, dek, rewrapped,
        )
        assertFalse(held.any { it.isZeroed })

        assertTrue(SecretRegistry.zeroAll() >= held.size)

        assertEquals(0, SecretRegistry.liveCount)
        assertTrue(held.all { it.isZeroed })
        assertFailsWith<SecretZeroedException> { signPayload("challenge:1", signer) }
        assertFailsWith<SecretZeroedException> { sealSecretBlob(dek, root.wrapKey, primitives) }
    }
}
