package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals

class KeyDerivationTest {
    private val emptySalt = ByteArray(0)

    @Test
    fun pbkdf2ReproducesTheBip39Seed() {
        val mnemonic = TestVectors.string("seed_and_user_address", "mnemonic").utf8()
        val salt = ("mnemonic" + TestVectors.string("seed_and_user_address", "passphrase")).utf8()
        assertEquals(
            TestVectors.string("seed_and_user_address", "seed_hex"),
            primitives.pbkdf2HmacSha512.derive(mnemonic, salt, iterations = 2048, outputLength = 64).toHex(),
        )
    }

    @Test
    fun hkdfSha512WithAnEmptySaltReproducesTheKeyTreeLeaves() {
        val seed = TestVectors.hex("seed_and_user_address", "seed_hex")
        val leaves = listOf(
            Triple("x25519_key", "private_key_or_seed_hex", 32),
            Triple("mlkem768_key", "private_key_or_seed_hex", 64),
            Triple("vault_kek", "vault_kek_hex", 32),
        )
        for ((section, field, length) in leaves) {
            val info = TestVectors.string(section, "hkdf_info_label").utf8()
            assertEquals(
                TestVectors.string(section, field),
                primitives.hkdf.sha512(seed, emptySalt, info, length).toHex(),
                section,
            )
        }
    }

    @Test
    fun hkdfSha512TreatsAnEmptySaltAsHashLengthZeros() {
        val seed = TestVectors.hex("seed_and_user_address", "seed_hex")
        val info = TestVectors.string("vault_kek", "hkdf_info_label").utf8()
        assertEquals(
            primitives.hkdf.sha512(seed, ByteArray(64), info, 32).toHex(),
            primitives.hkdf.sha512(seed, emptySalt, info, 32).toHex(),
        )
    }

    @Test
    fun hkdfSha256ReproducesThePinDeviceWrapLeaf() {
        val ikm = TestVectors.hex("pin_oprf", "device_registration", "ikm_hex")
        assertEquals(
            TestVectors.string("pin_oprf", "device_registration", "device_wrap_key_hex"),
            primitives.hkdf.sha256(ikm, emptySalt, "Cryple-PIN-v1|device-wrap".utf8(), 32).toHex(),
        )
    }

    @Test
    fun hkdfSha256ReproducesThePqxdhSessionKey() {
        val ikm = TestVectors.hex("pqxdh", "intermediate", "ikm_prefix_hex") +
            TestVectors.hex("pqxdh", "intermediate", "ecdh_secret_hex") +
            TestVectors.hex("pqxdh", "intermediate", "kem_secret_hex")
        val salt = TestVectors.hex("pqxdh", "intermediate", "salt_hex")
        val info = TestVectors.string("pqxdh", "inputs", "info").utf8()
        assertEquals(
            TestVectors.string("pqxdh", "output", "session_key_hex"),
            primitives.hkdf.sha256(ikm, salt, info, 32).toHex(),
        )
    }
}
