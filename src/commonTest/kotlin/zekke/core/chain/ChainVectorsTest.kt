package zekke.core.chain

import zekke.core.encoding.bytesToHex
import zekke.core.encoding.uncompressedPointToSpkiBase64
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ChainVectorsTest {
    private val userAddress = TestVectors.string("seed_and_user_address", "user_address")
    private fun genesis(index: Int, field: String) = TestVectors.string("device_keys", "genesis_chain", index, field)

    @Test
    fun reproducesEveryGenesisStatementFromItsFields() {
        val device = { field: String -> TestVectors.string("device_keys", "genesis_device", field) }
        val sharing = { field: String -> TestVectors.string("device_keys", "genesis_sharing_keys", field) }
        assertEquals(
            genesis(0, "statement"),
            buildStatement(
                userAddress, 1, ZERO_HASH, EventType.DEVICE_ADD,
                listOf(device("device_id"), device("signing_public_key_spki"), device("x25519_public_key"), genesis(0, "statement").split('|')[8], device("scopes")),
            ),
        )
        assertEquals(
            genesis(1, "statement"),
            buildStatement(userAddress, 2, genesis(0, "event_hash"), EventType.SHARING_KEYS, listOf(sharing("generation"), sharing("x25519_public_key"), genesis(1, "statement").split('|')[7])),
        )
        assertEquals(
            genesis(2, "statement"),
            buildStatement(userAddress, 3, genesis(1, "event_hash"), EventType.KEYRING_ROTATE, listOf(formatRotations(parseRotations(device("genesis_keyring_rotation"))))),
        )
    }

    @Test
    fun reproducesEveryEventHash() {
        for (index in 0 until 3) {
            assertEquals(genesis(index, "event_hash"), eventHash(genesis(index, "statement"), genesis(index, "signer"), genesis(index, "signature_base64"), primitives))
        }
    }

    @Test
    fun replaysTheRecordedGenesisFromTheRootKey() {
        val state = ChainState.replay(userAddress, TestVectors.string("device_keys", "root_wrap", "root_public_key"), vectorGenesis(), primitives)
        assertEquals(3, state.seq)
        assertEquals(genesis(2, "event_hash"), state.head)
        assertEquals(listOf(TestVectors.string("device_keys", "genesis_device", "device_id")), state.activeDevicesWith(Scope.SECRETS))
        assertEquals(1, state.generations[Scope.SHARING])
        assertEquals(TestVectors.string("device_keys", "genesis_sharing_keys", "x25519_public_key"), state.currentSharingKeys()?.keys?.x25519PublicKey)
    }

    @Test
    fun refusesTheRecordedGenesisUnderAnotherRootKey() {
        val other = uncompressedPointToSpkiBase64(primitives.ecdsaP256.publicKey(TestVectors.hex("device_keys", "genesis_device", "signing_private_key_hex")))
        assertFailsWith<InvalidChainException> { ChainState.replay(userAddress, other, vectorGenesis(), primitives) }
    }

    @Test
    fun theVectorRootKeyIsTheOneTheSeedDerives() {
        assertEquals(TestVectors.string("device_keys", "root_wrap", "root_public_key"), vectorRoot().signing.publicKeySpkiBase64)
    }

    @Test
    fun theGenesisMlKemKeyIsTheOneItsSeedDerives() {
        val keyPair = primitives.mlKem768.keyPairFromSeed(TestVectors.hex("device_keys", "genesis_device", "mlkem_seed_hex"))
        assertEquals(TestVectors.string("device_keys", "genesis_device", "mlkem_public_key_sha256"), bytesToHex(primitives.sha2.sha256(keyPair.publicKey)))
    }
}
