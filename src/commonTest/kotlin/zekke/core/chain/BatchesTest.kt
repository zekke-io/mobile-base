package zekke.core.chain

import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.keyrings.BatchAuthor
import zekke.core.keyrings.GrantsAdminException
import zekke.core.keyrings.KeyNotGrantedException
import zekke.core.keyrings.LinkedKek
import zekke.core.keyrings.SelfRemovalException
import zekke.core.keyrings.buildDeviceLink
import zekke.core.keyrings.buildDeviceRemoval
import zekke.core.keyrings.buildEnrolment
import zekke.core.keyrings.buildGenesis
import zekke.core.keyrings.buildRotation
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BatchesTest {
    @Test
    fun aGenesisVerifiesAsABatchAndReplaysFromTheRootKey() {
        val first = testDevice(ALL)
        val genesis = genesisWith(first)
        assertEquals(3, genesis.replay().seq)
        assertEquals(KEYRING_SCOPES, genesis.built.created.map { it.scope })
    }

    @Test
    fun aGenesisWrapsEveryGenerationToTheRootAndTheDeviceAndSealsTheSharingMaterial() {
        val first = testDevice(ALL)
        val built = genesisWith(first).built
        assertEquals(12, built.batch.wraps.size)
        assertTrue(built.batch.wraps.all { it.recipient == ROOT_SIGNER || it.recipient == first.id })
        assertEquals(1, built.batch.materials.size)
        assertEquals(1, built.batch.materials[0].generation)
    }

    @Test
    fun aGenesisRefusesAFirstDeviceWithoutAdmin() {
        val root = vectorRoot()
        val error = assertFailsWith<InvalidChainException> {
            buildGenesis(root.userAddress, root.signing.publicKeySpkiBase64, rootSigner(root), placeholderRootWrapper, testDevice(listOf(Scope.SECRETS, Scope.NOTES)).declaration, primitives)
        }
        assertTrue("admin" in error.message.orEmpty())
    }

    @Test
    fun theEnrolmentDigestIsOverTheStatementsJoinedByNewlines() {
        val events = genesisWith(testDevice(ALL)).built.batch.events
        assertEquals(bytesToHex(primitives.sha2.sha256(utf8ToBytes(events.joinToString("\n") { it.statement }))), batchDigest(events, primitives))
    }

    @Test
    fun removingAnotherDeviceRotatesEveryKeyringItHeldAndWrapsToExactlyTheRemainingHolders() {
        val first = testDevice(ALL)
        val second = testDevice(ALL)
        val third = testDevice(listOf(Scope.ADMIN, Scope.NOTES))
        val genesis = genesisWith(first)
        val state = genesis.replay()
        enrolByRoot(state, rootSigner(genesis.root), second)
        enrolByRoot(state, rootSigner(genesis.root), third)

        val built = buildDeviceRemoval(state, BatchAuthor(first.id, first.signer), placeholderRootWrapper, listOf(second.id), primitives)

        assertEquals(KEYRING_SCOPES, built.created.map { it.scope })
        assertEquals(listOf(ROOT_SIGNER, first.id, third.id).sorted(), built.batch.wraps.filter { it.scope == Scope.NOTES }.map { it.recipient }.sorted())
        assertEquals(listOf(ROOT_SIGNER, first.id).sorted(), built.batch.wraps.filter { it.scope == Scope.SECRETS }.map { it.recipient }.sorted())
        assertEquals(1, built.batch.materials.size)
        assertEquals(2, state.generations[Scope.SHARING])
    }

    @Test
    fun aDeviceDoesNotRemoveItselfThroughARemoval() {
        val first = testDevice(ALL)
        val state = genesisWith(first).replay()
        assertFailsWith<SelfRemovalException> { buildDeviceRemoval(state, BatchAuthor(first.id, first.signer), placeholderRootWrapper, listOf(first.id), primitives) }
    }

    @Test
    fun aPlainRotationOfOneScopeNeedsNoSharingKeys() {
        val first = testDevice(ALL)
        val state = genesisWith(first).replay()
        val built = buildRotation(state, BatchAuthor(first.id, first.signer), placeholderRootWrapper, listOf(Scope.SECRETS), primitives)
        assertEquals(1, built.batch.events.size)
        assertEquals(2, built.batch.wraps.size)
        assertEquals(2, state.generations[Scope.SECRETS])
    }

    @Test
    fun anEnrolmentWithThePhraseAddsAFullDeviceAndMayRemoveOthersInTheSameBatch() {
        val first = testDevice(ALL)
        val lost = testDevice(ALL)
        val genesis = genesisWith(first)
        val state = genesis.replay()
        enrolByRoot(state, rootSigner(genesis.root), lost)
        val phone = testDevice(ALL)
        val built = buildEnrolment(state, rootSigner(genesis.root), placeholderRootWrapper, phone.declaration, listOf(first.id, lost.id), primitives)
        assertEquals(listOf(phone.id), state.activeDeviceIds())
        assertEquals(KEYRING_SCOPES, built.created.map { it.scope })
        assertTrue(built.batch.wraps.all { it.recipient == ROOT_SIGNER || it.recipient == phone.id })
    }

    @Test
    fun aStoredChainWithARemovalAndItsRotationReplays() {
        val first = testDevice(ALL)
        val second = testDevice(ALL)
        val genesis = genesisWith(first)
        val live = genesis.replay()
        val added = enrolByRoot(live, rootSigner(genesis.root), second)
        val removal = buildDeviceRemoval(live, BatchAuthor(first.id, first.signer), placeholderRootWrapper, listOf(second.id), primitives)
        val all = genesis.events + stored(listOf(added), 4) + stored(removal.batch.events, 5)
        val replayed = ChainState.replay(genesis.root.userAddress, genesis.root.signing.publicKeySpkiBase64, all, primitives)
        assertEquals(live.head, replayed.head)
        assertEquals(listOf(first.id), replayed.activeDeviceIds())
    }

    @Test
    fun aFullDeviceLinksALimitedDeviceWithAWrapOfEachGrantedGeneration() {
        val first = testDevice(ALL)
        val state = genesisWith(first).replay()
        val browser = testDevice(listOf(Scope.PASSWORDS, Scope.SECRETS, Scope.NOTES))
        val keks = listOf(Scope.PASSWORDS, Scope.SECRETS, Scope.NOTES).map { LinkedKek(it, 1, generateScopeKek(primitives)) }
        val batch = buildDeviceLink(state, BatchAuthor(first.id, first.signer), browser.declaration, keks, primitives)
        assertEquals(1, batch.events.size)
        assertEquals(3, batch.wraps.size)
        assertTrue(batch.wraps.all { it.recipient == browser.id })
        assertEquals(setOf(Scope.PASSWORDS, Scope.SECRETS, Scope.NOTES), state.devices.getValue(browser.id).scopes)
    }

    @Test
    fun aDeviceNeverLinksAFullDevice() {
        val first = testDevice(ALL)
        val state = genesisWith(first).replay()
        val headBefore = state.head
        assertFailsWith<GrantsAdminException> { buildDeviceLink(state, BatchAuthor(first.id, first.signer), testDevice(ALL).declaration, emptyList(), primitives) }
        assertEquals(headBefore, state.head)
    }

    @Test
    fun aLinkRefusesAKeyOfAScopeItDoesNotGrant() {
        val first = testDevice(ALL)
        val state = genesisWith(first).replay()
        val extension = testDevice(listOf(Scope.PASSWORDS))
        assertFailsWith<KeyNotGrantedException> {
            buildDeviceLink(state, BatchAuthor(first.id, first.signer), extension.declaration, listOf(LinkedKek(Scope.NOTES, 1, generateScopeKek(primitives))), primitives)
        }
    }
}
