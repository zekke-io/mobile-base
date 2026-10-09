package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class X25519Test {
    @Test
    fun clampsTheHkdfBytesInsideTheFunction() {
        assertEquals(
            TestVectors.string("x25519_key", "public_key_hex"),
            primitives.x25519.publicKey(TestVectors.hex("x25519_key", "private_key_or_seed_hex")).toHex(),
        )
    }

    @Test
    fun derivesTheGenesisDevicePublicKeys() {
        assertContentEquals(
            TestVectors.base64("device_keys", "genesis_device", "x25519_public_key"),
            primitives.x25519.publicKey(TestVectors.hex("device_keys", "genesis_device", "x25519_private_key_hex")),
        )
        assertContentEquals(
            TestVectors.base64("device_keys", "genesis_sharing_keys", "x25519_public_key"),
            primitives.x25519.publicKey(TestVectors.hex("device_keys", "genesis_sharing_keys", "x25519_private_key_hex")),
        )
    }

    @Test
    fun reproducesThePqxdhEcdhSecretFromBothSides() {
        val ephemeralPrivate = TestVectors.hex("pqxdh", "inputs", "sender_ephemeral_x25519_private_hex")
        val ephemeralPublic = TestVectors.hex("pqxdh", "inputs", "sender_ephemeral_x25519_public_hex")
        val recipientPrivate = TestVectors.hex("x25519_key", "private_key_or_seed_hex")
        val recipientPublic = TestVectors.hex("pqxdh", "inputs", "recipient_x25519_public_hex")
        val expected = TestVectors.string("pqxdh", "intermediate", "ecdh_secret_hex")

        assertEquals(ephemeralPublic.toHex(), primitives.x25519.publicKey(ephemeralPrivate).toHex())
        assertEquals(expected, primitives.x25519.sharedSecret(ephemeralPrivate, recipientPublic).toHex())
        assertEquals(expected, primitives.x25519.sharedSecret(recipientPrivate, ephemeralPublic).toHex())
    }
}
