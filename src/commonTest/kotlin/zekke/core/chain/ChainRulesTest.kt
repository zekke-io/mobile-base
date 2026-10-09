package zekke.core.chain

import zekke.core.keyrings.BatchAuthor
import zekke.core.keyrings.buildSelfRemoval
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith

class ChainRulesTest {
    private class TwoDevices(val genesis: Genesis, val first: TestDevice, val second: TestDevice, val state: ChainState, val events: List<StoredChainEvent>)

    private fun twoDevices(): TwoDevices {
        val first = testDevice(ALL)
        val second = testDevice(ALL)
        val genesis = genesisWith(first)
        val state = genesis.replay()
        val added = enrolByRoot(state, rootSigner(genesis.root), second)
        return TwoDevices(genesis, first, second, state, genesis.events + stored(listOf(added), 4))
    }

    private fun refused(fragment: String, block: () -> Unit) {
        val error = assertFailsWith<InvalidChainException> { block() }
        assertContains(error.message.orEmpty(), fragment)
    }

    @Test
    fun aWrongSequence() {
        val (state, first) = twoDevices().let { it.state to it.first }
        refused("sequence") { state.applyBatch(listOf(signedBy(state, first, EventType.KEYRING_ROTATE, listOf("secrets=2"), seq = state.seq + 2))) }
    }

    @Test
    fun aWrongHead() {
        val (state, first) = twoDevices().let { it.state to it.first }
        refused("head") { state.applyBatch(listOf(signedBy(state, first, EventType.KEYRING_ROTATE, listOf("secrets=2"), head = "f".repeat(64)))) }
    }

    @Test
    fun aStoredEventWhoseHashIsNotItsOwn() {
        val devices = twoDevices()
        val tampered = devices.events.mapIndexed { index, event ->
            if (index == 1) StoredChainEvent(event.statement, event.signer, event.signature, event.seq, "a".repeat(64)) else event
        }
        assertFailsWith<InvalidChainException> {
            ChainState.replay(devices.genesis.root.userAddress, devices.genesis.root.signing.publicKeySpkiBase64, tampered, primitives)
        }
    }

    @Test
    fun aRemovedSigner() {
        val devices = twoDevices()
        val state = devices.state
        buildSelfRemoval(state, BatchAuthor(devices.second.id, devices.second.signer), primitives)
        refused("not an active device") { state.applyBatch(listOf(signedBy(state, devices.second, EventType.DEVICE_REMOVE, listOf(devices.first.id)))) }
    }

    @Test
    fun aDeviceGrantingAScopeItLacks() {
        val first = testDevice(ALL)
        val limitedAdmin = testDevice(listOf(Scope.ADMIN, Scope.NOTES))
        val genesis = genesisWith(first)
        val state = genesis.replay()
        enrolByRoot(state, rootSigner(genesis.root), limitedAdmin)
        val third = testDevice(listOf(Scope.SECRETS, Scope.NOTES))
        refused("scope it lacks") { state.applyBatch(listOf(signedBy(state, limitedAdmin, EventType.DEVICE_ADD, deviceAddFields(third.declaration)))) }
    }

    @Test
    fun aNarrowingThatWidens() {
        val first = testDevice(ALL)
        val narrow = testDevice(listOf(Scope.NOTES))
        val genesis = genesisWith(first)
        val state = genesis.replay()
        enrolByRoot(state, rootSigner(genesis.root), narrow)
        refused("only narrow") { state.applyBatch(listOf(signedBy(state, first, EventType.DEVICE_SCOPES, listOf(narrow.id, "notes,files")))) }
    }

    @Test
    fun aRemovalOfAnotherDeviceWithoutRotatingWhatItLost() {
        val devices = twoDevices()
        refused("without a rotation") { devices.state.applyBatch(listOf(signedBy(devices.state, devices.first, EventType.DEVICE_REMOVE, listOf(devices.second.id)))) }
    }

    @Test
    fun aSharingRotationWithoutItsKeys() {
        val devices = twoDevices()
        refused("without announcing its keys") { devices.state.applyBatch(listOf(signedBy(devices.state, devices.first, EventType.KEYRING_ROTATE, listOf("sharing=2")))) }
    }

    @Test
    fun aLimitedDeviceSigningAnythingButItsOwnRemoval() {
        val first = testDevice(ALL)
        val limited = testDevice(listOf(Scope.NOTES))
        val genesis = genesisWith(first)
        val state = genesis.replay()
        enrolByRoot(state, rootSigner(genesis.root), limited)
        refused("admin") { state.applyBatch(listOf(signedBy(state, limited, EventType.KEYRING_ROTATE, listOf("notes=2")))) }
    }

    @Test
    fun aRotationListOutOfOrderOrRepeated() {
        for (field in listOf("notes=2,secrets=2", "notes=2,notes=3", "vault=2", "notes=0", "notes=x", "")) {
            assertFailsWith<InvalidChainException>(field) { parseRotations(field) }
        }
    }

    @Test
    fun aFieldContainingTheSeparator() {
        refused("\"|\"") { buildStatement("a".repeat(64), 1, ZERO_HASH, EventType.DEVICE_REMOVE, listOf("x|y")) }
    }
}
