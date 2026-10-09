package zekke.core.chain

import zekke.core.keyrings.BatchAuthor
import zekke.core.keyrings.buildRotation
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProofPathTest {
    @Test
    fun aRootAnnouncedGenesisProofVerifies() {
        val genesis = genesisWith(testDevice(ALL))
        val keys = sharingKeysFromState(genesis.replay())!!
        verifyProofPath(genesis.root.userAddress, genesis.root.signing.publicKeySpkiBase64, keys, listOf(genesis.events[1]), primitives)
    }

    @Test
    fun aRotationAnnouncedByADeviceVerifiesThroughThatDevicesDeviceAdd() {
        val first = testDevice(ALL)
        val genesis = genesisWith(first)
        val state = genesis.replay()
        val rotation = buildRotation(state, BatchAuthor(first.id, first.signer), placeholderRootWrapper, listOf(Scope.SHARING), primitives)
        val rotated = stored(rotation.batch.events, 4)
        val keys = sharingKeysFromState(state)!!
        val root = genesis.root
        assertEquals(2, keys.generation)

        verifyProofPath(root.userAddress, root.signing.publicKeySpkiBase64, keys, listOf(genesis.events[0], rotated[1]), primitives)

        assertFailsWith<InvalidChainException> {
            verifyProofPath(root.userAddress, testDevice(ALL).declaration.signingPublicKey, keys, listOf(genesis.events[0], rotated[1]), primitives)
        }
        val error = assertFailsWith<InvalidChainException> {
            verifyProofPath(
                root.userAddress,
                root.signing.publicKeySpkiBase64,
                PublishedSharingKeys(keys.generation, first.declaration.x25519PublicKey, keys.mlkemPublicKey),
                listOf(genesis.events[0], rotated[1]),
                primitives,
            )
        }
        assertEquals(true, "not the ones" in error.message.orEmpty())
        assertFailsWith<InvalidChainException> { verifyProofPath(root.userAddress, root.signing.publicKeySpkiBase64, keys, listOf(rotated[1]), primitives) }
    }
}
