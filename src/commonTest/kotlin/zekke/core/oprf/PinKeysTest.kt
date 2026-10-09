package zekke.core.oprf

import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PinKeysTest {
    private val pin = TestVectors.string("pin_oprf", "pin").toCharArray()
    private val userAddress = TestVectors.string("seed_and_user_address", "user_address")
    private fun oprfOutput() = TestVectors.hex("pin_oprf", "evaluation", "oprf_output_hex")

    @Test
    fun theDevicePinKeysReproduceTheVectors() {
        val salt = TestVectors.hex("pin_oprf", "argon2id", "device_salt_hex")
        val argon = stretchPin(pin, salt, primitives)
        assertEquals(TestVectors.string("pin_oprf", "argon2id", "device_output_hex"), bytesToHex(argon))
        assertEquals(TestVectors.string("pin_oprf", "device_registration", "ikm_hex"), bytesToHex(pinIkm(oprfOutput(), argon)))

        val output = oprfOutput()
        val keys = deriveDevicePinKeys(output, pin, salt, primitives)
        assertEquals(TestVectors.string("pin_oprf", "device_registration", "device_wrap_key_hex"), bytesToHex(keys.wrapKey))
        assertEquals(TestVectors.string("pin_oprf", "device_registration", "device_confirm_seed_hex"), bytesToHex(keys.confirmSeed))
        assertEquals(TestVectors.string("pin_oprf", "device_registration", "confirm_public_key_base64"), keys.confirmPublicKey)
        assertTrue(output.all { it == 0.toByte() }, "the OPRF output is consumed")
    }

    @Test
    fun theDeviceConfirmationIsTheRecordedSignature() {
        val registrationId = TestVectors.string("pin_oprf", "device_registration", "registration_id")
        val attemptId = TestVectors.string("pin_oprf", "device_registration", "attempt_id")
        assertEquals(TestVectors.string("pin_oprf", "device_registration", "confirm_message"), deviceConfirmMessage(registrationId, attemptId))
        assertEquals(
            TestVectors.string("pin_oprf", "device_registration", "confirm_signature_base64"),
            signDeviceConfirmation(TestVectors.hex("pin_oprf", "device_registration", "device_confirm_seed_hex"), registrationId, attemptId, primitives),
        )
    }

    @Test
    fun theAccountProofKeyAndItsProofReproduceTheVectors() {
        val key = deriveAccountProofKey(oprfOutput(), pin, userAddress, primitives)
        assertEquals(TestVectors.string("pin_oprf", "account_registration", "account_proof_seed_hex"), bytesToHex(key.seed))
        assertEquals(TestVectors.string("pin_oprf", "account_registration", "proof_public_key_base64"), key.publicKey)
        val proof = proofSigner(key, primitives).signDigest(TestVectors.hex("pin_oprf", "account_registration", "example_action_digest"))
        assertEquals(TestVectors.string("pin_oprf", "account_registration", "pin_proof_base64"), bytesToBase64(proof))
        zeroAccountProofKey(key)
        assertTrue(key.seed.all { it == 0.toByte() })
    }

    @Test
    fun theLeavesAreDomainSeparated() {
        val ikm = TestVectors.hex("pin_oprf", "device_registration", "ikm_hex")
        val leaves = PinLeafLabel.entries.map { bytesToHex(pinLeaf(ikm, it, primitives)) }
        assertEquals(leaves.size, leaves.toSet().size)
    }

    @Test
    fun aDeviceSaltIsThirtyTwoFreshBytes() {
        val salt = generateDeviceSalt(primitives)
        assertEquals(DEVICE_SALT_BYTES, salt.size)
        assertTrue(!salt.contentEquals(generateDeviceSalt(primitives)))
    }
}
