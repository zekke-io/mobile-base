package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class MlKem768Test {
    @Test
    fun generatesTheKeyPairFromTheSixtyFourByteSeed() {
        val keyPair = primitives.mlKem768.keyPairFromSeed(TestVectors.hex("mlkem768_key", "private_key_or_seed_hex"))
        assertEquals(TestVectors.string("mlkem768_key", "public_key_hex"), keyPair.publicKey.toHex())
    }

    @Test
    fun generatesTheGenesisDeviceAndSharingKeysFromTheirSeeds() {
        for (section in listOf("genesis_device", "genesis_sharing_keys")) {
            val keyPair = primitives.mlKem768.keyPairFromSeed(TestVectors.hex("device_keys", section, "mlkem_seed_hex"))
            assertEquals(
                TestVectors.string("device_keys", section, "mlkem_public_key_sha256"),
                primitives.sha2.sha256(keyPair.publicKey).toHex(),
                section,
            )
        }
    }

    @Test
    fun decapsulatesThePqxdhCiphertextToTheRecordedSecret() {
        val keyPair = primitives.mlKem768.keyPairFromSeed(TestVectors.hex("mlkem768_key", "private_key_or_seed_hex"))
        assertEquals(
            TestVectors.string("pqxdh", "inputs", "recipient_mlkem_public_sha256"),
            primitives.sha2.sha256(keyPair.publicKey).toHex(),
        )
        assertEquals(
            TestVectors.string("pqxdh", "intermediate", "kem_secret_hex"),
            primitives.mlKem768.decapsulate(keyPair.secretKey, TestVectors.hex("pqxdh", "inputs", "kem_ciphertext_hex")).toHex(),
        )
    }

    @Test
    fun encapsulationRoundTrips() {
        val keyPair = primitives.mlKem768.keyPairFromSeed(primitives.secureRandom.nextBytes(MlKem768.SEED_BYTES))
        val encapsulation = primitives.mlKem768.encapsulate(keyPair.publicKey)
        assertContentEquals(encapsulation.sharedSecret, primitives.mlKem768.decapsulate(keyPair.secretKey, encapsulation.ciphertext))
    }
}
