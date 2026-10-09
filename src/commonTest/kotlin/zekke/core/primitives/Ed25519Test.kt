package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Ed25519Test {
    @Test
    fun signsTheDeviceConfirmationDeterministically() {
        val seed = TestVectors.hex("pin_oprf", "device_registration", "device_confirm_seed_hex")
        val message = TestVectors.string("pin_oprf", "device_registration", "confirm_message").utf8()
        val publicKey = TestVectors.base64("pin_oprf", "device_registration", "confirm_public_key_base64")
        val signature = TestVectors.base64("pin_oprf", "device_registration", "confirm_signature_base64")

        assertContentEquals(publicKey, primitives.ed25519.publicKey(seed))
        assertContentEquals(signature, primitives.ed25519.sign(seed, message))
        assertTrue(primitives.ed25519.verify(publicKey, message, signature))
    }

    @Test
    fun signsThePinProofOverTheActionDigestDeterministically() {
        val seed = TestVectors.hex("pin_oprf", "account_registration", "account_proof_seed_hex")
        val digest = TestVectors.hex("pin_oprf", "account_registration", "example_action_digest")
        val publicKey = TestVectors.base64("pin_oprf", "account_registration", "proof_public_key_base64")
        val proof = TestVectors.base64("pin_oprf", "account_registration", "pin_proof_base64")

        assertContentEquals(publicKey, primitives.ed25519.publicKey(seed))
        assertContentEquals(proof, primitives.ed25519.sign(seed, digest))
    }

    @Test
    fun refusesASignatureOverAnotherMessage() {
        val publicKey = TestVectors.base64("pin_oprf", "device_registration", "confirm_public_key_base64")
        val signature = TestVectors.base64("pin_oprf", "device_registration", "confirm_signature_base64")
        assertFalse(primitives.ed25519.verify(publicKey, "another message".utf8(), signature))
    }
}
