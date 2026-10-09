package zekke.core.chain

import zekke.core.device.deviceDeclaration
import zekke.core.device.deviceSigner
import zekke.core.device.generateDeviceKeys
import zekke.core.keys.RootKeys
import zekke.core.keys.deriveRootKeys
import zekke.core.keyrings.BuiltBatch
import zekke.core.keyrings.RootWrapper
import zekke.core.keyrings.buildGenesis
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import zekke.core.scopes.FULL_DEVICE_SCOPES
import zekke.core.scopes.Scope
import zekke.core.signing.Signer
import zekke.core.signing.rawKeySigner

internal val ALL: List<Scope> = FULL_DEVICE_SCOPES

internal val placeholderRootWrapper = RootWrapper { "AQ".padEnd(64, 'A') }

internal class TestDevice(val declaration: DeviceKeysDeclaration, val signer: Signer) {
    val id: String get() = declaration.deviceId
}

internal fun testDevice(scopes: List<Scope>): TestDevice {
    val keys = generateDeviceKeys(primitives = primitives)
    return TestDevice(deviceDeclaration(keys, scopes), deviceSigner(keys, primitives))
}

internal fun vectorRoot(): RootKeys = deriveRootKeys(TestVectors.secret("seed_and_user_address", "seed_hex"), primitives)

internal fun rootSigner(root: RootKeys): Signer = rawKeySigner(root.signing.privateKey, primitives)

internal fun stored(events: List<ChainEvent>, from: Int = 1): List<StoredChainEvent> = events.mapIndexed { index, event ->
    StoredChainEvent(event.statement, event.signer, event.signature, from + index, eventHash(event.statement, event.signer, event.signature, primitives))
}

internal class Genesis(val root: RootKeys, val built: BuiltBatch, val events: List<StoredChainEvent>) {
    fun replay(): ChainState = ChainState.replay(root.userAddress, root.signing.publicKeySpkiBase64, events, primitives)
}

internal fun genesisWith(first: TestDevice): Genesis {
    val root = vectorRoot()
    val built = buildGenesis(root.userAddress, root.signing.publicKeySpkiBase64, rootSigner(root), placeholderRootWrapper, first.declaration, primitives)
    return Genesis(root, built, stored(built.batch.events))
}

internal fun enrolByRoot(state: ChainState, signer: Signer, device: TestDevice): ChainEvent {
    val statement = buildStatement(state.userAddress, state.seq + 1, state.head, EventType.DEVICE_ADD, deviceAddFields(device.declaration))
    val event = signStatement(statement, ROOT_SIGNER, signer)
    state.applyBatch(listOf(event))
    return event
}

internal fun signedBy(state: ChainState, device: TestDevice, type: EventType, fields: List<String>, seq: Int = state.seq + 1, head: String = state.head): ChainEvent =
    signStatement(buildStatement(state.userAddress, seq, head, type, fields), device.id, device.signer)

internal fun vectorGenesis(): List<StoredChainEvent> = (0 until 3).map { index ->
    StoredChainEvent(
        TestVectors.string("device_keys", "genesis_chain", index, "statement"),
        TestVectors.string("device_keys", "genesis_chain", index, "signer"),
        TestVectors.string("device_keys", "genesis_chain", index, "signature_base64"),
        index + 1,
        TestVectors.string("device_keys", "genesis_chain", index, "event_hash"),
    )
}
