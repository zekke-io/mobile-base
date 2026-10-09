package zekke.core.signing

import zekke.core.memory.adoptAsSecret
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SigningTest {
    private val rootPrivate = TestVectors.hex("identity_key_p256", "private_key_hex")
    private val rootPublic = TestVectors.hex("identity_key_p256", "public_key_uncompressed_hex")
    private val devicePrivate = TestVectors.hex("device_keys", "genesis_device", "signing_private_key_hex")
    private val userAddress = TestVectors.string("seed_and_user_address", "user_address")
    private val fixedClock = { 1767225600L }

    @Test
    fun theTableHasEveryActionOfTheSpecOnce() {
        assertEquals(36, Action.entries.size)
        assertEquals(Action.entries.size, Action.entries.map { it.label }.toSet().size)
        assertEquals(7, Action.entries.count { it.signer == SignerRole.ROOT })
        assertEquals(
            setOf(Action.ENABLE_SECOND_FACTOR, Action.PIN_EVALUATE),
            Action.entries.filter { it.signer == SignerRole.ROOT && !it.pinProof }.toSet(),
        )
    }

    @Test
    fun aChallengeIsSixtyFourLowercaseHexCharacters() {
        val challenge = createChallenge(primitives)
        assertTrue(Regex("^[0-9a-f]{64}$").matches(challenge))
    }

    @Test
    fun buildsTheRecordedActionPayloadAndDigest() {
        val recorded = TestVectors.string("pin_oprf", "account_registration", "example_action_payload")
        val challenge = recorded.substringBefore(':')
        val payload = buildActionPayload(challenge, 1767225600L, Action.ACCOUNT_DELETE, listOf(userAddress))
        assertEquals(recorded, payload)
        assertEquals(TestVectors.string("pin_oprf", "account_registration", "example_action_digest"), bytesToHex(payloadDigest(payload, primitives)))
        assertEquals("$challenge:1767225600", buildAuthPayload(challenge, 1767225600L))
    }

    @Test
    fun signsInP1363AndVerifiesAgainstTheRightKeyOnly() {
        val payload = buildAuthPayload(createChallenge(primitives), fixedClock())
        val signature = signPayload(payload, rawKeySigner(rootPrivate.copyOf().adoptAsSecret(), primitives))
        assertEquals(64, base64ToBytes(signature).size)
        assertTrue(verifyPayload(payload, signature, rootPublic, primitives))
        assertFalse(verifyPayload(payload, signature, primitives.ecdsaP256.publicKey(devicePrivate), primitives))
        assertFalse(verifyPayload("$payload:x", signature, rootPublic, primitives))
        assertFalse(verifyPayload(payload, "not base64!", rootPublic, primitives))
    }

    @Test
    fun acceptsTheHighSSignaturesOfTheGenesisChain() {
        for (index in 0 until 3) {
            val statement = TestVectors.string("device_keys", "genesis_chain", index, "statement")
            val signature = TestVectors.string("device_keys", "genesis_chain", index, "signature_base64")
            assertTrue(verifyPayload(statement, signature, rootPublic, primitives), "chain event $index")
        }
    }

    @Test
    fun aPreHashedPayloadDoesNotVerify() {
        val payload = buildAuthPayload(createChallenge(primitives), fixedClock())
        val preHashed = bytesToBase64(primitives.ecdsaP256.sign(rootPrivate, primitives.sha2.sha256(utf8ToBytes(payload))))
        assertFalse(verifyPayload(payload, preHashed, rootPublic, primitives))
    }

    @Test
    fun anAuthSignatureNeverVerifiesAsAnAction() {
        val challenge = createChallenge(primitives)
        val auth = signPayload(buildAuthPayload(challenge, 1L), rawKeySigner(rootPrivate.copyOf().adoptAsSecret(), primitives))
        val action = buildActionPayload(challenge, 1L, Action.CHAIN_READ, listOf(userAddress))
        assertFalse(verifyPayload(action, auth, rootPublic, primitives))
    }

    @Test
    fun variadicIdsAreSortedAndDeduplicated() {
        assertEquals(listOf("a", "b", "c"), normalizeActionArgs(Action.SECRET_DELETE, listOf("c", "a", "b", "a")))
        assertEquals(listOf("only"), normalizeActionArgs(Action.FILE_PURGE, listOf("only")))
    }

    @Test
    fun aRekeyBatchNamingAnIdTwiceIsRefused() {
        for (action in Action.entries.filter { it.refusesRepeatedIds }) {
            assertFailsWith<InvalidActionArgumentsException> { normalizeActionArgs(action, listOf("a", "b", "a")) }
        }
        assertEquals(7, Action.entries.count { it.refusesRepeatedIds })
    }

    @Test
    fun argumentsAreCheckedForArityEmptinessAndTheSeparator() {
        assertFailsWith<InvalidActionArgumentsException> { normalizeActionArgs(Action.CREDENTIAL_PRUNE, listOf("id")) }
        assertFailsWith<InvalidActionArgumentsException> { normalizeActionArgs(Action.ACCOUNT_DELETE, listOf("")) }
        assertFailsWith<InvalidActionArgumentsException> { normalizeActionArgs(Action.USERNAME_UPDATE, listOf("a:b")) }
        assertFailsWith<InvalidActionArgumentsException> { normalizeActionArgs(Action.NOTE_DELETE, emptyList()) }
    }

    @Test
    fun aDeviceActionAndARootActionRefuseTheOtherSigner() {
        val signer = rawKeySigner(devicePrivate.copyOf().adoptAsSecret(), primitives)
        assertFailsWith<WrongSignerException> { signActionEnvelope(Action.ACCOUNT_DELETE, listOf(userAddress), signer, primitives) }
        assertFailsWith<WrongSignerException> { signRootAction(Action.SECRET_DELETE, listOf("id"), signer, primitives = primitives) }
    }

    @Test
    fun aDeviceEnvelopeVerifiesOverItsRebuiltPayload() {
        val envelope = signActionEnvelope(Action.NOTE_DELETE, listOf("b", "a"), rawKeySigner(devicePrivate.copyOf().adoptAsSecret(), primitives), primitives, fixedClock)
        val payload = buildActionPayload(envelope.challenge, envelope.timestamp, Action.NOTE_DELETE, listOf("a", "b"))
        assertEquals(1767225600L, envelope.timestamp)
        assertTrue(verifyPayload(payload, envelope.signature, primitives.ecdsaP256.publicKey(devicePrivate), primitives))
    }

    @Test
    fun aRootActionCarriesAPinProofOverTheSameDigest() {
        val proofSeed = TestVectors.hex("pin_oprf", "account_registration", "account_proof_seed_hex")
        val envelope = signRootAction(
            Action.ACCOUNT_DELETE,
            listOf(userAddress),
            rawKeySigner(rootPrivate.copyOf().adoptAsSecret(), primitives),
            PinProofSigner { digest -> primitives.ed25519.sign(proofSeed, digest) },
            primitives,
            fixedClock,
        )
        val payload = buildActionPayload(envelope.challenge, envelope.timestamp, Action.ACCOUNT_DELETE, listOf(userAddress))
        assertTrue(verifyPayload(payload, envelope.signature, rootPublic, primitives))
        val proof = base64ToBytes(envelope.pinProof!!)
        assertTrue(primitives.ed25519.verify(primitives.ed25519.publicKey(proofSeed), payloadDigest(payload, primitives), proof))
    }

    @Test
    fun aPinProofIsRefusedWhereItNeverApplies() {
        val proof = PinProofSigner { ByteArray(64) }
        assertFailsWith<PinProofNotAllowedException> {
            signRootAction(Action.ENABLE_SECOND_FACTOR, listOf("key"), rawKeySigner(rootPrivate.copyOf().adoptAsSecret(), primitives), proof, primitives)
        }
        assertNull(signRootAction(Action.CHAIN_READ, listOf(userAddress), rawKeySigner(rootPrivate.copyOf().adoptAsSecret(), primitives), primitives = primitives).pinProof)
    }
}
