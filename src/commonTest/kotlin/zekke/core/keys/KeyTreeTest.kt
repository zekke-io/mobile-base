package zekke.core.keys

import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class KeyTreeTest {
    private val seed = TestVectors.hex("seed_and_user_address", "seed_hex")
    private val words = TestVectors.string("seed_and_user_address", "mnemonic").split(' ').map { it.toCharArray() }

    @Test
    fun reproducesEveryValueOfTheKeyTree() {
        val tree = deriveKeyTreeFromSeed(seed.copyOf(), primitives)
        assertEquals(TestVectors.string("seed_and_user_address", "user_address"), tree.userAddress)
        assertEquals(TestVectors.string("identity_key_p256", "private_key_hex"), bytesToHex(tree.identity.privateKey))
        assertEquals(TestVectors.string("identity_key_p256", "chain_code_hex"), bytesToHex(tree.identity.chainCode))
        assertEquals(TestVectors.string("identity_key_p256", "public_key_uncompressed_hex"), bytesToHex(tree.identity.publicKeyUncompressed))
        assertEquals(TestVectors.string("identity_key_p256", "public_key_spki_base64"), tree.identity.publicKeySpkiBase64)
        assertEquals(TestVectors.string("x25519_key", "private_key_or_seed_hex"), bytesToHex(tree.x25519.privateKey))
        assertEquals(TestVectors.string("x25519_key", "public_key_hex"), bytesToHex(tree.x25519.publicKey))
        assertEquals(TestVectors.string("x25519_key", "public_key_base64"), tree.x25519.publicKeyBase64)
        assertEquals(TestVectors.string("mlkem768_key", "private_key_or_seed_hex"), bytesToHex(tree.mlkem768.seed))
        assertEquals(TestVectors.string("mlkem768_key", "public_key_hex"), bytesToHex(tree.mlkem768.publicKey))
        assertEquals(TestVectors.string("mlkem768_key", "public_key_base64"), tree.mlkem768.publicKeyBase64)
        assertEquals(TestVectors.string("vault_kek", "vault_kek_hex"), bytesToHex(tree.vaultKek))
    }

    @Test
    fun theUserAddressHashesTheRawSeedNotItsHexString() {
        val fromHexString = bytesToHex(primitives.sha2.sha256(utf8ToBytes(bytesToHex(seed))))
        assertNotEquals(TestVectors.string("seed_and_user_address", "user_address"), fromHexString)
        assertEquals(TestVectors.string("seed_and_user_address", "user_address"), deriveUserAddress(seed, primitives))
    }

    @Test
    fun theFrozenConstantsMatchTheFixture() {
        assertEquals(TestVectors.string("identity_key_p256", "slip10_hmac_key"), SLIP10_P256_CURVE_NAME)
        assertEquals(TestVectors.string("identity_key_p256", "path"), "m/" + IDENTITY_PATH.joinToString("/") { "$it'" })
        assertEquals(TestVectors.string("x25519_key", "hkdf_info_label"), X25519_HKDF_INFO)
        assertEquals(TestVectors.string("mlkem768_key", "hkdf_info_label"), MLKEM768_HKDF_INFO)
        assertEquals(TestVectors.string("vault_kek", "hkdf_info_label"), VAULT_KEK_HKDF_INFO)
    }

    @Test
    fun theRootKeysFromTheMnemonicAreTheTreesRootLeaves() {
        val root = deriveRootKeysFromMnemonic(words, primitives)
        assertEquals(TestVectors.string("seed_and_user_address", "user_address"), root.userAddress)
        assertEquals(TestVectors.string("identity_key_p256", "public_key_spki_base64"), root.signing.publicKeySpkiBase64)
        assertEquals(TestVectors.string("vault_kek", "vault_kek_hex"), bytesToHex(root.wrapKey))
        zeroRootKeys(root)
        assertTrue(root.signing.privateKey.all { it == 0.toByte() } && root.wrapKey.all { it == 0.toByte() })
    }

    @Test
    fun zeroingTheTreeClearsEveryPrivateBuffer() {
        val tree = deriveKeyTree(words, primitives)
        zeroKeyTree(tree)
        val buffers = listOf(
            tree.seed, tree.identity.privateKey, tree.identity.chainCode, tree.x25519.privateKey,
            tree.mlkem768.seed, tree.mlkem768.secretKey, tree.vaultKek,
        )
        assertTrue(buffers.all { buffer -> buffer.all { it == 0.toByte() } })
    }
}
