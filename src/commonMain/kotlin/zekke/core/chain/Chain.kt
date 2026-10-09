package zekke.core.chain

import zekke.core.encoding.P256_SPKI_BASE64_LENGTH
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.spkiBase64ToUncompressedPoint
import zekke.core.encoding.utf8ToBytes
import zekke.core.primitives.MlKem768
import zekke.core.primitives.PrimitiveFailureException
import zekke.core.primitives.Primitives
import zekke.core.primitives.X25519
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.InvalidScopeListException
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import zekke.core.scopes.formatScopeList
import zekke.core.scopes.keyringScopesOf
import zekke.core.scopes.parseScopeList
import zekke.core.signing.Signer
import zekke.core.signing.signPayload
import zekke.core.signing.verifyPayload

const val CHAIN_VERSION = "Cryple-Chain-v1"
val ZERO_HASH: String = "0".repeat(64)
const val ROOT_SIGNER = "root"
const val GENESIS_LENGTH = 3

private const val SEPARATOR = "|"
private val CANONICAL_ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
private val POSITIVE_DECIMAL = Regex("^[1-9][0-9]*$")

enum class EventType(val wire: String) {
    DEVICE_ADD("device-add"),
    DEVICE_REMOVE("device-remove"),
    DEVICE_SCOPES("device-scopes"),
    KEYRING_ROTATE("keyring-rotate"),
    SHARING_KEYS("sharing-keys"),
}

open class ChainEvent(val statement: String, val signer: String, val signature: String)

class StoredChainEvent(statement: String, signer: String, signature: String, val seq: Int, val eventHash: String) :
    ChainEvent(statement, signer, signature)

class DeviceKeysDeclaration(
    val deviceId: String,
    val signingPublicKey: String,
    val x25519PublicKey: String,
    val mlkemPublicKey: String,
    val scopes: List<Scope>,
)

data class SharingPublicKeys(val x25519PublicKey: String, val mlkemPublicKey: String)

class ChainDevice(
    val signingPublicKey: String,
    val x25519PublicKey: String,
    val mlkemPublicKey: String,
    var scopes: Set<Scope>,
    var active: Boolean,
)

class CurrentSharingKeys(val generation: Int, val keys: SharingPublicKeys)

class PublishedSharingKeys(val generation: Int, val x25519PublicKey: String, val mlkemPublicKey: String)

class InvalidChainException(message: String) : IllegalStateException("invalid account event: $message")

private fun invalid(message: String) = InvalidChainException(message)

fun eventHash(statement: String, signer: String, signatureBase64: String, primitives: Primitives = platformPrimitives()): String =
    bytesToHex(primitives.sha2.sha256(utf8ToBytes(listOf(statement, signer, signatureBase64).joinToString(SEPARATOR))))

fun buildStatement(userAddress: String, seq: Int, prev: String, type: EventType, fields: List<String>): String {
    val parts = listOf(CHAIN_VERSION, userAddress, seq.toString(), prev, type.wire) + fields
    if (parts.any { SEPARATOR in it }) throw invalid("a statement field contains \"|\"")
    return parts.joinToString(SEPARATOR)
}

fun deviceAddFields(device: DeviceKeysDeclaration): List<String> = listOf(
    device.deviceId,
    device.signingPublicKey,
    device.x25519PublicKey,
    device.mlkemPublicKey,
    formatScopeList(device.scopes),
)

fun formatRotations(rotations: Map<Scope, Int>): String {
    val pairs = KEYRING_SCOPES.mapNotNull { scope -> rotations[scope]?.let { "${scope.wire}=$it" } }
    if (pairs.isEmpty()) throw invalid("keyring-rotate names no scope")
    return pairs.joinToString(",")
}

fun parseRotations(field: String): Map<Scope, Int> {
    if (field.isEmpty()) throw invalid("keyring-rotate names no scope")
    val rotations = LinkedHashMap<Scope, Int>()
    for (pair in field.split(',')) {
        val parts = pair.split('=')
        val scope = if (parts.size == 2) Scope.fromWire(parts[0]) else null
        if (scope == null || !scope.isKeyring) throw invalid("keyring-rotate names an unknown keyring scope")
        rotations[scope] = parseGeneration(parts[1])
    }
    try {
        parseScopeList(rotations.keys.joinToString(",") { it.wire })
    } catch (_: InvalidScopeListException) {
        throw invalid("keyring-rotate scopes are not in canonical order")
    }
    if (rotations.size != field.split(',').size) throw invalid("keyring-rotate scopes are not in canonical order")
    return rotations
}

fun parseGeneration(value: String): Int {
    if (!POSITIVE_DECIMAL.matches(value)) throw invalid("generation is not a positive decimal")
    return value.toIntOrNull() ?: throw invalid("generation is not a positive decimal")
}

fun batchDigest(events: List<ChainEvent>, primitives: Primitives = platformPrimitives()): String =
    bytesToHex(primitives.sha2.sha256(utf8ToBytes(events.joinToString("\n") { it.statement })))

fun signStatement(statement: String, signerName: String, signer: Signer): ChainEvent =
    ChainEvent(statement, signerName, signPayload(statement, signer))

private fun verifyEventSignature(publicKeySpki: String, event: ChainEvent, primitives: Primitives): Boolean {
    val point = try {
        spkiBase64ToUncompressedPoint(publicKeySpki)
    } catch (_: IllegalArgumentException) {
        return false
    }
    return verifyPayload(event.statement, event.signature, point, primitives)
}

private fun isCanonicalBase64(value: String, length: Int): Boolean = try {
    val raw = base64ToBytes(value)
    raw.size == length && bytesToBase64(raw) == value
} catch (_: IllegalArgumentException) {
    false
}

fun validateX25519PublicKey(value: String) {
    if (!isCanonicalBase64(value, X25519.KEY_BYTES)) throw invalid("x25519 key is not 32 bytes of canonical base64")
}

fun validateMlkemPublicKey(value: String, primitives: Primitives = platformPrimitives()) {
    if (!isCanonicalBase64(value, MlKem768.PUBLIC_KEY_BYTES)) {
        throw invalid("ml-kem key is not a canonical base64 ML-KEM-768 encapsulation key")
    }
    try {
        val encapsulation = primitives.mlKem768.encapsulate(base64ToBytes(value))
        encapsulation.sharedSecret.fill(0)
    } catch (_: PrimitiveFailureException) {
        throw invalid("ml-kem key is not a valid ML-KEM-768 encapsulation key")
    }
}

fun validateSigningPublicKey(value: String) {
    if (value.length != P256_SPKI_BASE64_LENGTH) throw invalid("signing key is not a base64 SPKI P-256 key")
    try {
        spkiBase64ToUncompressedPoint(value)
    } catch (_: IllegalArgumentException) {
        throw invalid("signing key is not a base64 SPKI P-256 key")
    }
}

private class ParsedStatement(val type: String, val fields: List<String>)

private class BatchTally {
    val rotated = LinkedHashMap<Scope, MutableList<Int>>()
    val announced = mutableListOf<Int>()
    val lost = LinkedHashMap<String, MutableSet<Scope>>()
}

class ChainState(val userAddress: String, val rootKey: String, private val primitives: Primitives = platformPrimitives()) {
    var seq: Int = 0
        private set
    var head: String = ZERO_HASH
        private set
    val devices: MutableMap<String, ChainDevice> = LinkedHashMap()
    val generations: MutableMap<Scope, Int> = LinkedHashMap()
    val sharingKeys: MutableMap<Int, SharingPublicKeys> = LinkedHashMap()

    companion object {
        fun replay(
            userAddress: String,
            rootKey: String,
            events: List<StoredChainEvent>,
            primitives: Primitives = platformPrimitives(),
        ): ChainState = ChainState(userAddress, rootKey, primitives).also { it.appendStored(events) }
    }

    fun appendStored(events: List<StoredChainEvent>) {
        var run = mutableListOf<StoredChainEvent>()
        for (event in events) {
            if (run.isNotEmpty() && run.last().signer != event.signer) {
                applyRun(run)
                run = mutableListOf()
            }
            run.add(event)
        }
        if (run.isNotEmpty()) applyRun(run)
    }

    private fun applyRun(run: List<StoredChainEvent>) {
        val tally = BatchTally()
        for (event in run) {
            if (event.seq != seq + 1) throw invalid("stored event ${event.seq} is out of sequence")
            apply(event, tally, replay = true)
            if (event.eventHash != head) throw invalid("stored event ${event.seq} carries a hash that does not match it")
        }
        checkTally(tally, replay = true)
    }

    fun applyBatch(events: List<ChainEvent>) {
        if (events.isEmpty()) throw invalid("a batch needs at least one event")
        if (seq == 0 && events.size != GENESIS_LENGTH) throw invalid("the genesis is exactly $GENESIS_LENGTH events")
        val tally = BatchTally()
        for (event in events) apply(event, tally, replay = false)
        checkTally(tally, replay = false)
    }

    private fun checkTally(tally: BatchTally, replay: Boolean) {
        val sharingRotations = tally.rotated[Scope.SHARING].orEmpty()
        for (generation in tally.announced) {
            if (generation !in sharingRotations) {
                throw invalid("sharing keys for generation $generation without rotating sharing to it")
            }
        }
        for (generation in sharingRotations) {
            if (generation !in tally.announced) throw invalid("sharing rotated to $generation without announcing its keys")
        }
        for ((deviceId, lost) in tally.lost) {
            for (scope in keyringScopesOf(lost)) {
                if (scope !in tally.rotated) throw invalid("device $deviceId lost ${scope.wire} without a rotation of it")
            }
        }
        if (!replay) {
            for ((scope, rotations) in tally.rotated) {
                if (rotations.size != 1) throw invalid("${scope.wire} is rotated twice in one batch")
            }
        }
    }

    fun currentSharingKeys(): CurrentSharingKeys? {
        val generation = generations[Scope.SHARING] ?: return null
        val keys = sharingKeys[generation] ?: return null
        return CurrentSharingKeys(generation, keys)
    }

    fun activeDevicesWith(scope: Scope): List<String> =
        devices.filter { (_, device) -> device.active && scope in device.scopes }.keys.sorted()

    fun activeDeviceIds(): List<String> = devices.filter { it.value.active }.keys.toList()

    private fun apply(event: ChainEvent, tally: BatchTally, replay: Boolean) {
        val parsed = parse(event.statement)
        val signerDevice = signerDevice(event.signer)
        val signingKey = signerDevice?.signingPublicKey ?: rootKey

        if (!verifyEventSignature(signingKey, event, primitives)) throw invalid("signature does not verify")

        checkGenesisOrder(parsed, event.signer)

        when (parsed.type) {
            EventType.DEVICE_ADD.wire -> applyDeviceAdd(parsed.fields, signerDevice)
            EventType.DEVICE_REMOVE.wire -> applyDeviceRemove(parsed.fields, event.signer, signerDevice, tally)
            EventType.DEVICE_SCOPES.wire -> applyDeviceScopes(parsed.fields, signerDevice, tally)
            EventType.KEYRING_ROTATE.wire -> applyKeyringRotate(parsed.fields, signerDevice, tally)
            EventType.SHARING_KEYS.wire -> applySharingKeys(parsed.fields, signerDevice, tally, replay)
            else -> throw invalid("unknown event type \"${parsed.type}\"")
        }

        seq += 1
        head = eventHash(event.statement, event.signer, event.signature, primitives)
    }

    private fun parse(text: String): ParsedStatement {
        val parts = text.split(SEPARATOR)
        if (parts.size < 5) throw invalid("statement has too few fields")
        if (parts[0] != CHAIN_VERSION) throw invalid("unknown statement version")
        if (parts[1] != userAddress) throw invalid("statement names another account")
        if (parts[2] != (seq + 1).toString()) throw invalid("statement sequence is not ${seq + 1}")
        if (parts[3] != head) throw invalid("statement does not follow the chain head")
        return ParsedStatement(parts[4], parts.drop(5))
    }

    private fun signerDevice(signer: String): ChainDevice? {
        if (signer == ROOT_SIGNER) return null
        val device = devices[signer]
        if (device == null || !device.active) throw invalid("signer is not an active device")
        return device
    }

    private fun checkGenesisOrder(parsed: ParsedStatement, signer: String) {
        if (seq >= GENESIS_LENGTH) return
        if (signer != ROOT_SIGNER) throw invalid("the genesis is signed by the root")
        val expected = listOf(EventType.DEVICE_ADD, EventType.SHARING_KEYS, EventType.KEYRING_ROTATE)[seq]
        if (parsed.type != expected.wire) throw invalid("genesis event ${seq + 1} must be ${expected.wire}")
    }

    private fun applyDeviceAdd(fields: List<String>, signerDevice: ChainDevice?) {
        if (fields.size != 5) throw invalid("device-add takes 5 fields")
        requireAdmin(signerDevice)
        val (id, signingKey, x25519Key, mlkemKey, scopeList) = fields
        if (!CANONICAL_ID.matches(id)) throw invalid("device id is not a canonical UUID")
        if (id in devices) throw invalid("device id was already used on this account")
        validateSigningPublicKey(signingKey)
        validateX25519PublicKey(x25519Key)
        validateMlkemPublicKey(mlkemKey, primitives)

        val scopes = parseScopes(scopeList)
        if (seq == 0 && Scope.ADMIN !in scopes) throw invalid("the first device must hold admin")
        if (signerDevice != null && !signerDevice.scopes.containsAll(scopes)) throw invalid("a device cannot grant a scope it lacks")

        devices[id] = ChainDevice(signingKey, x25519Key, mlkemKey, scopes, active = true)
    }

    private fun applyDeviceRemove(fields: List<String>, signer: String, signerDevice: ChainDevice?, tally: BatchTally) {
        if (fields.size != 1) throw invalid("device-remove takes 1 field")
        val id = fields[0]
        val device = devices[id]
        if (device == null || !device.active) throw invalid("device-remove names no active device")
        device.active = false
        if (signer == id) return
        requireAdmin(signerDevice)
        mergeLost(tally, id, device.scopes)
    }

    private fun applyDeviceScopes(fields: List<String>, signerDevice: ChainDevice?, tally: BatchTally) {
        if (fields.size != 2) throw invalid("device-scopes takes 2 fields")
        requireAdmin(signerDevice)
        val (id, list) = fields
        val device = devices[id]
        if (device == null || !device.active) throw invalid("device-scopes names no active device")
        val narrowed = parseScopes(list)
        if (!(device.scopes.containsAll(narrowed) && device.scopes.size > narrowed.size)) throw invalid("device-scopes may only narrow")
        val lost = device.scopes - narrowed
        device.scopes = narrowed
        mergeLost(tally, id, lost)
    }

    private fun applyKeyringRotate(fields: List<String>, signerDevice: ChainDevice?, tally: BatchTally) {
        if (fields.size != 1) throw invalid("keyring-rotate takes 1 field")
        requireAdmin(signerDevice)
        val rotations = parseRotations(fields[0])
        if (seq == 2 && rotations.size != KEYRING_SCOPES.size) throw invalid("the genesis rotation sets every keyring scope")
        for ((scope, generation) in rotations) {
            val next = (generations[scope] ?: 0) + 1
            if (generation != next) throw invalid("${scope.wire} must rotate to generation $next")
        }
        for ((scope, generation) in rotations) {
            generations[scope] = generation
            tally.rotated.getOrPut(scope) { mutableListOf() }.add(generation)
        }
    }

    private fun applySharingKeys(fields: List<String>, signerDevice: ChainDevice?, tally: BatchTally, replay: Boolean) {
        if (fields.size != 3) throw invalid("sharing-keys takes 3 fields")
        requireAdmin(signerDevice)
        val generation = parseGeneration(fields[0])
        val current = generations[Scope.SHARING] ?: 0
        val rotatedHere = tally.rotated[Scope.SHARING].orEmpty()
        if (seq == 1) {
            if (generation != 1) throw invalid("the genesis sharing keys are generation 1")
        } else if (generation != current || generation !in rotatedHere) {
            throw invalid(
                if (replay) "sharing keys for an unexpected generation"
                else "sharing keys must follow a rotation of sharing in the same batch",
            )
        }
        if (generation in sharingKeys) throw invalid("sharing keys for generation $generation were already announced")
        validateX25519PublicKey(fields[1])
        validateMlkemPublicKey(fields[2], primitives)
        sharingKeys[generation] = SharingPublicKeys(fields[1], fields[2])
        tally.announced.add(generation)
    }
}

private fun requireAdmin(signerDevice: ChainDevice?) {
    if (signerDevice != null && Scope.ADMIN !in signerDevice.scopes) throw invalid("signing device does not hold admin")
}

private fun parseScopes(list: String): Set<Scope> = try {
    parseScopeList(list).toSet()
} catch (_: InvalidScopeListException) {
    throw invalid("scopes are not a canonical list")
}

private fun mergeLost(tally: BatchTally, deviceId: String, scopes: Iterable<Scope>) {
    tally.lost.getOrPut(deviceId) { mutableSetOf() }.addAll(scopes)
}

private class ProofSigner(val key: String, val admin: Boolean)

fun verifyProofPath(
    userAddress: String,
    rootPublicKey: String,
    sharingKeys: PublishedSharingKeys,
    proof: List<StoredChainEvent>,
    primitives: Primitives = platformPrimitives(),
) {
    if (proof.isEmpty()) throw invalid("the proof path is empty")
    val signers = HashMap<String, ProofSigner>()
    var previousSeq = 0

    for ((index, event) in proof.withIndex()) {
        val parts = event.statement.split(SEPARATOR)
        if (parts.size < 5 || parts[0] != CHAIN_VERSION) throw invalid("a proof statement is malformed")
        if (parts[1] != userAddress) throw invalid("a proof statement names another account")
        val seq = parts[2].toIntOrNull()
        if (seq == null || seq <= previousSeq || seq != event.seq) throw invalid("the proof path is out of order")
        previousSeq = seq

        val signer = if (event.signer == ROOT_SIGNER) ProofSigner(rootPublicKey, admin = true) else signers[event.signer]
        if (signer == null) throw invalid("a proof event is signed by a device the path never added")
        if (index == 0 && event.signer != ROOT_SIGNER) throw invalid("the proof path does not start at the root")
        if (!signer.admin) throw invalid("a proof event is signed by a device without admin")
        if (!verifyEventSignature(signer.key, event, primitives)) throw invalid("a proof signature does not verify")
        if (event.eventHash != eventHash(event.statement, event.signer, event.signature, primitives)) {
            throw invalid("a proof event carries a hash that does not match it")
        }

        val type = parts[4]
        val fields = parts.drop(5)
        if (index == proof.size - 1) {
            if (type != EventType.SHARING_KEYS.wire || fields.size != 3) throw invalid("the proof path does not end at a sharing-keys event")
            if (parseGeneration(fields[0]) != sharingKeys.generation ||
                fields[1] != sharingKeys.x25519PublicKey ||
                fields[2] != sharingKeys.mlkemPublicKey
            ) {
                throw invalid("the published sharing keys are not the ones the proof announces")
            }
            return
        }
        if (type != EventType.DEVICE_ADD.wire || fields.size != 5) throw invalid("a proof path step is not a device-add")
        signers[fields[0]] = ProofSigner(fields[1], admin = Scope.ADMIN in parseScopes(fields[4]))
    }
}

fun sharingKeysFromState(state: ChainState): PublishedSharingKeys? =
    state.currentSharingKeys()?.let { PublishedSharingKeys(it.generation, it.keys.x25519PublicKey, it.keys.mlkemPublicKey) }
