package zekke.core.keyrings

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.api.wireJson
import zekke.core.chain.ChainEvent
import zekke.core.chain.StoredChainEvent
import zekke.core.memory.SecretBytes
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope
import zekke.core.session.KeyringEntry
import zekke.core.session.MissingGenerationException
import zekke.core.session.SessionKeystore

@Serializable
class ChainEventWire(
    val statement: String,
    val signer: String,
    val signature: String,
    val seq: Int? = null,
    @SerialName("event_hash") val eventHash: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
) {
    fun toStored(): StoredChainEvent = StoredChainEvent(
        statement,
        signer,
        signature,
        seq ?: error("a stored chain event carries its seq"),
        eventHash ?: error("a stored chain event carries its hash"),
    )
}

fun ChainEvent.toWire(): ChainEventWire = ChainEventWire(statement, signer, signature)

@Serializable
class KeyringWrapWire(val scope: String, val generation: Int, val recipient: String, @SerialName("wrapped_key") val wrappedKey: String)

@Serializable
class KeyringMaterialWire(val scope: String, val generation: Int, @SerialName("sealed_material") val sealedMaterial: String)

@Serializable
class DeviceBatchWire(val events: List<ChainEventWire>, val wraps: List<KeyringWrapWire>, val materials: List<KeyringMaterialWire>)

fun KeyringWrap.toWire(): KeyringWrapWire = KeyringWrapWire(scope.wire, generation, recipient, wrappedKey)

fun DeviceBatch.toWire(): DeviceBatchWire = DeviceBatchWire(
    events = events.map { it.toWire() },
    wraps = wraps.map { it.toWire() },
    materials = materials.map { KeyringMaterialWire(it.scope.wire, it.generation, it.sealedMaterial) },
)

@Serializable
class KeyringGenerationRecord(
    val scope: String,
    val generation: Int,
    @SerialName("wrapped_key") val wrappedKey: String? = null,
    @SerialName("sealed_material") val sealedMaterial: String? = null,
)

@Serializable
class KeyringsRecord(val current: Map<String, Int> = emptyMap(), val generations: List<KeyringGenerationRecord> = emptyList())

@Serializable
class DeviceRecordOnServer(
    val id: String,
    @SerialName("signing_public_key") val signingPublicKey: String,
    @SerialName("encryption_public_key_x25519") val x25519PublicKey: String,
    @SerialName("encryption_public_key_mlkem") val mlkemPublicKey: String,
    val scopes: String,
    @SerialName("created_at") val createdAt: String,
)

@Serializable
class DevicesRecord(val devices: List<DeviceRecordOnServer> = emptyList(), val head: Int = 0)

class OpenedKeyrings(val entries: List<KeyringEntry>, val current: Map<Scope, Int>)

suspend fun fetchKeyrings(api: ZekkeApi): KeyringsRecord =
    api.request(Method.GET, "/keyrings", token = api.tokens.require()).decode(KeyringsRecord.serializer())

fun currentFrom(record: KeyringsRecord): Map<Scope, Int> =
    record.current.mapNotNull { (name, generation) -> Scope.fromWire(name)?.takeIf { it.isKeyring }?.let { it to generation } }.toMap()

fun openDeviceKeyrings(
    record: KeyringsRecord,
    userAddress: String,
    device: DeviceSecrets,
    skip: (Scope, Int) -> Boolean = { _, _ -> false },
    primitives: Primitives = platformPrimitives(),
): List<KeyringEntry> = record.generations.mapNotNull { generation ->
    val scope = Scope.fromWire(generation.scope)?.takeIf { it.isKeyring } ?: return@mapNotNull null
    if (skip(scope, generation.generation)) return@mapNotNull null
    val wrapped = generation.wrappedKey ?: throw MissingGenerationException(scope, generation.generation)
    KeyringEntry(scope, generation.generation, openDeviceWrap(wrapped, userAddress, device, primitives), generation.sealedMaterial)
}

fun openRootKeyrings(record: KeyringsRecord, rootWrapKey: SecretBytes, primitives: Primitives = platformPrimitives()): List<KeyringEntry> =
    record.generations.mapNotNull { generation ->
        val scope = Scope.fromWire(generation.scope)?.takeIf { it.isKeyring } ?: return@mapNotNull null
        val wrapped = generation.wrappedKey ?: throw MissingGenerationException(scope, generation.generation)
        KeyringEntry(scope, generation.generation, openRootWrap(rootWrapKey, wrapped, primitives), generation.sealedMaterial)
    }

suspend fun refreshKeyrings(api: ZekkeApi, session: SessionKeystore, primitives: Primitives = platformPrimitives()) {
    val record = fetchKeyrings(api)
    val entries = openDeviceKeyrings(record, session.userAddress, session.deviceSecrets(), { scope, generation -> session.hasKek(scope, generation) }, primitives)
    session.addKeyrings(entries, currentFrom(record))
}

suspend fun loadKeyrings(api: ZekkeApi, userAddress: String, device: DeviceSecrets, primitives: Primitives = platformPrimitives()): OpenedKeyrings {
    val record = fetchKeyrings(api)
    return OpenedKeyrings(openDeviceKeyrings(record, userAddress, device, primitives = primitives), currentFrom(record))
}

suspend fun postOwnWraps(api: ZekkeApi, wraps: List<KeyringWrap>) {
    if (wraps.isEmpty()) return
    val body = buildJsonObject { put("wraps", wireJson.encodeToJsonElement(ListSerializer(KeyringWrapWire.serializer()), wraps.map { it.toWire() })) }
    api.request(Method.POST, "/keyrings/wraps", body = body, token = api.tokens.require())
}

suspend fun fetchChain(api: ZekkeApi, after: Int = 0): List<StoredChainEvent> {
    val response = api.request(Method.GET, "/devices/chain", token = api.tokens.require(), query = mapOf("after" to after.toString()))
    if (response.data == null) return emptyList()
    return response.decode(ListSerializer(ChainEventWire.serializer())).map { it.toStored() }
}

suspend fun listDevices(api: ZekkeApi): DevicesRecord {
    val response = api.request(Method.GET, "/devices", token = api.tokens.require())
    return if (response.data == null) DevicesRecord() else response.decode(DevicesRecord.serializer())
}

suspend fun applyDeviceBatch(api: ZekkeApi, batch: DeviceBatch): DevicesRecord {
    val body = buildJsonObject { put("batch", wireJson.encodeToJsonElement(DeviceBatchWire.serializer(), batch.toWire())) }
    val response = api.request(Method.POST, "/devices/batch", body = body, token = api.tokens.require())
    return if (response.data == null) DevicesRecord() else response.decode(DevicesRecord.serializer())
}

suspend fun <T> withCurrentGeneration(api: ZekkeApi, session: SessionKeystore, attempt: suspend () -> T): T {
    try {
        return attempt()
    } catch (error: ApiError) {
        if (!error.isStaleKeyGeneration) throw error
    }
    refreshKeyrings(api, session)
    return attempt()
}
