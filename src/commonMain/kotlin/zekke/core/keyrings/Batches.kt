package zekke.core.keyrings

import zekke.core.chain.ChainEvent
import zekke.core.chain.ChainState
import zekke.core.chain.DeviceKeysDeclaration
import zekke.core.chain.EventType
import zekke.core.chain.ROOT_SIGNER
import zekke.core.chain.buildStatement
import zekke.core.chain.deviceAddFields
import zekke.core.chain.eventHash
import zekke.core.chain.formatRotations
import zekke.core.chain.signStatement
import zekke.core.encoding.bytesToBase64
import zekke.core.memory.SecretBytes
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import zekke.core.scopes.formatScopeList
import zekke.core.scopes.keyringScopesOf
import zekke.core.signing.Signer

class KeyringWrap(val scope: Scope, val generation: Int, val recipient: String, val wrappedKey: String)

class KeyringMaterial(val generation: Int, val sealedMaterial: String) {
    val scope: Scope get() = Scope.SHARING
}

class DeviceBatch(val events: List<ChainEvent>, val wraps: List<KeyringWrap>, val materials: List<KeyringMaterial>)

class CreatedGeneration(val scope: Scope, val generation: Int, val kek: SecretBytes, val sharingKeys: SharingKeyPair? = null)

class BuiltBatch(val batch: DeviceBatch, val created: List<CreatedGeneration>)

fun interface RootWrapper {
    fun wrap(kek: SecretBytes): String
}

class BatchAuthor(val name: String, val signer: Signer)

class GrantsAdminException : IllegalArgumentException("a device links limited devices only: only the phrase makes a full device")

class KeyNotGrantedException(scope: Scope) : IllegalArgumentException("the linked device does not hold ${scope.wire}")

class SelfRemovalException : IllegalArgumentException("a device leaving on its own uses buildSelfRemoval")

class EmptyRotationException : IllegalArgumentException("a rotation names at least one keyring scope")

private class PlannedEvent(val type: EventType, val fields: List<String>)

private class RotationPlan(val planned: List<PlannedEvent>, val created: List<CreatedGeneration>)

class LinkedKek(val scope: Scope, val generation: Int, val kek: SecretBytes)

internal class BatchBuilder(private val primitives: Primitives) {
    private fun signEvents(state: ChainState, author: BatchAuthor, planned: List<PlannedEvent>): List<ChainEvent> {
        var seq = state.seq
        var head = state.head
        return planned.map { event ->
            seq += 1
            val statement = buildStatement(state.userAddress, seq, head, event.type, event.fields)
            val signed = signStatement(statement, author.name, author.signer)
            head = eventHash(signed.statement, signed.signer, signed.signature, primitives)
            signed
        }
    }

    private fun wrapGeneration(state: ChainState, created: CreatedGeneration, wrapForRoot: RootWrapper): List<KeyringWrap> {
        val wraps = mutableListOf(KeyringWrap(created.scope, created.generation, ROOT_SIGNER, wrapForRoot.wrap(created.kek)))
        for (deviceId in state.activeDevicesWith(created.scope)) {
            val device = state.devices[deviceId] ?: continue
            wraps += KeyringWrap(
                created.scope,
                created.generation,
                deviceId,
                wrapKekForDevice(created.kek, state.userAddress, DeviceRecipient(deviceId, device.x25519PublicKey, device.mlkemPublicKey), primitives),
            )
        }
        return wraps
    }

    private fun assemble(
        state: ChainState,
        author: BatchAuthor,
        planned: List<PlannedEvent>,
        created: List<CreatedGeneration>,
        wrapForRoot: RootWrapper,
    ): BuiltBatch {
        try {
            val events = signEvents(state, author, planned)
            state.applyBatch(events)
            val wraps = mutableListOf<KeyringWrap>()
            val materials = mutableListOf<KeyringMaterial>()
            for (generation in created) {
                wraps += wrapGeneration(state, generation, wrapForRoot)
                generation.sharingKeys?.let { materials += KeyringMaterial(generation.generation, sealSharingMaterial(generation.kek, it, primitives)) }
            }
            return BuiltBatch(DeviceBatch(events, wraps, materials), created)
        } catch (error: Throwable) {
            zeroCreated(created)
            throw error
        }
    }

    private fun newGeneration(scope: Scope, generation: Int): CreatedGeneration = CreatedGeneration(
        scope = scope,
        generation = generation,
        kek = generateScopeKek(primitives),
        sharingKeys = if (scope == Scope.SHARING) generateSharingKeys(primitives) else null,
    )

    private fun sharingKeysEvent(generation: CreatedGeneration): PlannedEvent {
        val keys = generation.sharingKeys ?: error("a sharing generation carries its keys")
        return PlannedEvent(
            EventType.SHARING_KEYS,
            listOf(generation.generation.toString(), bytesToBase64(keys.x25519PublicKey), bytesToBase64(keys.mlkemPublicKey)),
        )
    }

    private fun rotationPlan(state: ChainState, scopes: Collection<Scope>): RotationPlan {
        val ordered = KEYRING_SCOPES.filter { it in scopes }
        if (ordered.isEmpty()) return RotationPlan(emptyList(), emptyList())
        val created = ordered.map { newGeneration(it, (state.generations[it] ?: 0) + 1) }
        val planned = mutableListOf(PlannedEvent(EventType.KEYRING_ROTATE, listOf(formatRotations(created.associate { it.scope to it.generation }))))
        created.firstOrNull { it.scope == Scope.SHARING }?.let { planned += sharingKeysEvent(it) }
        return RotationPlan(planned, created)
    }

    fun buildGenesis(
        userAddress: String,
        rootPublicKey: String,
        root: Signer,
        wrapForRoot: RootWrapper,
        device: DeviceKeysDeclaration,
    ): BuiltBatch {
        val state = ChainState(userAddress, rootPublicKey, primitives)
        val created = KEYRING_SCOPES.map { newGeneration(it, 1) }
        val planned = listOf(
            PlannedEvent(EventType.DEVICE_ADD, deviceAddFields(device)),
            sharingKeysEvent(created.first { it.scope == Scope.SHARING }),
            PlannedEvent(EventType.KEYRING_ROTATE, listOf(formatRotations(KEYRING_SCOPES.associateWith { 1 }))),
        )
        return assemble(state, BatchAuthor(ROOT_SIGNER, root), planned, created, wrapForRoot)
    }

    fun buildEnrolment(
        state: ChainState,
        root: Signer,
        wrapForRoot: RootWrapper,
        device: DeviceKeysDeclaration,
        removeDeviceIds: List<String> = emptyList(),
    ): BuiltBatch {
        val lost = removeDeviceIds.flatMap { keyringScopesOf(state.devices[it]?.scopes.orEmpty()) }.toSet()
        val rotation = rotationPlan(state, lost)
        val planned = listOf(PlannedEvent(EventType.DEVICE_ADD, deviceAddFields(device))) +
            removeDeviceIds.map { PlannedEvent(EventType.DEVICE_REMOVE, listOf(it)) } +
            rotation.planned
        return assemble(state, BatchAuthor(ROOT_SIGNER, root), planned, rotation.created, wrapForRoot)
    }

    fun buildDeviceRemoval(
        state: ChainState,
        author: BatchAuthor,
        wrapForRoot: RootWrapper,
        removeDeviceIds: List<String>,
    ): BuiltBatch {
        if (author.name in removeDeviceIds) throw SelfRemovalException()
        val lost = removeDeviceIds.flatMap { keyringScopesOf(state.devices[it]?.scopes.orEmpty()) }.toSet()
        val rotation = rotationPlan(state, lost)
        val planned = removeDeviceIds.map { PlannedEvent(EventType.DEVICE_REMOVE, listOf(it)) } + rotation.planned
        return assemble(state, author, planned, rotation.created, wrapForRoot)
    }

    fun buildRotation(state: ChainState, author: BatchAuthor, wrapForRoot: RootWrapper, scopes: List<Scope>): BuiltBatch {
        val rotation = rotationPlan(state, scopes)
        if (rotation.planned.isEmpty()) throw EmptyRotationException()
        return assemble(state, author, rotation.planned, rotation.created, wrapForRoot)
    }

    fun buildSelfRemoval(state: ChainState, author: BatchAuthor): DeviceBatch {
        val events = signEvents(state, author, listOf(PlannedEvent(EventType.DEVICE_REMOVE, listOf(author.name))))
        state.applyBatch(events)
        return DeviceBatch(events, emptyList(), emptyList())
    }

    fun buildDeviceLink(state: ChainState, author: BatchAuthor, device: DeviceKeysDeclaration, keks: List<LinkedKek>): DeviceBatch {
        if (Scope.ADMIN in device.scopes) throw GrantsAdminException()
        val granted = device.scopes.toSet()
        keks.firstOrNull { it.scope !in granted }?.let { throw KeyNotGrantedException(it.scope) }
        val events = signEvents(state, author, listOf(PlannedEvent(EventType.DEVICE_ADD, deviceAddFields(device))))
        state.applyBatch(events)
        val recipient = DeviceRecipient(device.deviceId, device.x25519PublicKey, device.mlkemPublicKey)
        val wraps = keks.map { KeyringWrap(it.scope, it.generation, device.deviceId, wrapKekForDevice(it.kek, state.userAddress, recipient, primitives)) }
        return DeviceBatch(events, wraps, emptyList())
    }
}

fun zeroCreated(created: List<CreatedGeneration>) {
    for (generation in created) {
        generation.kek.zero()
        zeroSharingKeys(generation.sharingKeys)
    }
}

fun fullDeviceScopes(): String = formatScopeList(listOf(Scope.ADMIN) + KEYRING_SCOPES)

fun buildGenesis(
    userAddress: String,
    rootPublicKey: String,
    root: Signer,
    wrapForRoot: RootWrapper,
    device: DeviceKeysDeclaration,
    primitives: Primitives = platformPrimitives(),
): BuiltBatch = BatchBuilder(primitives).buildGenesis(userAddress, rootPublicKey, root, wrapForRoot, device)

fun buildEnrolment(
    state: ChainState,
    root: Signer,
    wrapForRoot: RootWrapper,
    device: DeviceKeysDeclaration,
    removeDeviceIds: List<String> = emptyList(),
    primitives: Primitives = platformPrimitives(),
): BuiltBatch = BatchBuilder(primitives).buildEnrolment(state, root, wrapForRoot, device, removeDeviceIds)

fun buildDeviceRemoval(
    state: ChainState,
    author: BatchAuthor,
    wrapForRoot: RootWrapper,
    removeDeviceIds: List<String>,
    primitives: Primitives = platformPrimitives(),
): BuiltBatch = BatchBuilder(primitives).buildDeviceRemoval(state, author, wrapForRoot, removeDeviceIds)

fun buildRotation(
    state: ChainState,
    author: BatchAuthor,
    wrapForRoot: RootWrapper,
    scopes: List<Scope>,
    primitives: Primitives = platformPrimitives(),
): BuiltBatch = BatchBuilder(primitives).buildRotation(state, author, wrapForRoot, scopes)

fun buildSelfRemoval(state: ChainState, author: BatchAuthor, primitives: Primitives = platformPrimitives()): DeviceBatch =
    BatchBuilder(primitives).buildSelfRemoval(state, author)

fun buildDeviceLink(
    state: ChainState,
    author: BatchAuthor,
    device: DeviceKeysDeclaration,
    keks: List<LinkedKek>,
    primitives: Primitives = platformPrimitives(),
): DeviceBatch = BatchBuilder(primitives).buildDeviceLink(state, author, device, keks)
