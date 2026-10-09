package zekke.core.device

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope
import zekke.core.scopes.formatScopeList
import zekke.core.scopes.parseScopeList
import zekke.core.sealed.MalformedSealedBlobException
import zekke.core.sealed.SealedBlobAuthenticationException
import zekke.core.sealed.UnsupportedSealedVersionException
import zekke.core.sealed.openBytes
import zekke.core.sealed.sealBytes

class DeviceRecord(
    val deviceId: String,
    val registrationId: String,
    val salt: String,
    val sealed: String,
    val userAddress: String,
    val rootPublicKey: String,
    val scopes: String,
    val signingPublicKey: String,
    val x25519PublicKey: String,
    val mlkemPublicKey: String,
)

class DeviceIdentity(val userAddress: String, val rootPublicKey: String, val scopes: List<Scope>)

class WrongDevicePinException : IllegalStateException("the device material did not open under this PIN")

class DeviceRecordFormatException(message: String) : IllegalArgumentException(message)

fun sealDeviceRecord(
    keys: DeviceKeys,
    identity: DeviceIdentity,
    registrationId: String,
    salt: ByteArray,
    wrapKey: SecretBytes,
    primitives: Primitives = platformPrimitives(),
): DeviceRecord {
    val sealed = sealableMaterial(keys).use { material -> material.withBytes { sealBytes(it, wrapKey, primitives) } }
    return DeviceRecord(
        deviceId = keys.deviceId,
        registrationId = registrationId,
        salt = bytesToBase64(salt),
        sealed = bytesToBase64(sealed),
        userAddress = identity.userAddress,
        rootPublicKey = identity.rootPublicKey,
        scopes = formatScopeList(identity.scopes),
        signingPublicKey = keys.signingPublicKey,
        x25519PublicKey = bytesToBase64(keys.x25519PublicKey),
        mlkemPublicKey = bytesToBase64(keys.mlkemPublicKey),
    )
}

fun openDeviceRecord(record: DeviceRecord, wrapKey: SecretBytes, primitives: Primitives = platformPrimitives()): DeviceKeys {
    val material = try {
        openBytes(base64ToBytes(record.sealed), wrapKey, primitives).adoptAsSecret()
    } catch (_: SealedBlobAuthenticationException) {
        throw WrongDevicePinException()
    } catch (_: MalformedSealedBlobException) {
        throw DeviceMaterialException("the sealed device material is malformed")
    } catch (_: UnsupportedSealedVersionException) {
        throw DeviceMaterialException("the sealed device material has an unknown version")
    }
    material.use {
        if (material.size != DEVICE_MATERIAL_BYTES) throw DeviceMaterialException("the sealed device material has an unexpected length")
        val keys = deviceKeysFromMaterial(
            deviceId = record.deviceId,
            signingPrivateKey = material.copyOfRange(0, SIGNING_PRIVATE_KEY_BYTES),
            x25519PrivateKey = material.copyOfRange(SIGNING_PRIVATE_KEY_BYTES, SIGNING_PRIVATE_KEY_BYTES + X25519_PRIVATE_BYTES),
            mlkemSeed = material.copyOfRange(SIGNING_PRIVATE_KEY_BYTES + X25519_PRIVATE_BYTES, DEVICE_MATERIAL_BYTES),
            primitives = primitives,
        )
        val matches = keys.signingPublicKey == record.signingPublicKey &&
            bytesToBase64(keys.x25519PublicKey) == record.x25519PublicKey &&
            bytesToBase64(keys.mlkemPublicKey) == record.mlkemPublicKey
        if (!matches) {
            zeroDeviceKeys(keys)
            throw DeviceMaterialException("the sealed device material does not match the record's public keys")
        }
        return keys
    }
}

fun recordIdentity(record: DeviceRecord): DeviceIdentity =
    DeviceIdentity(record.userAddress, record.rootPublicKey, parseScopeList(record.scopes))

private val RECORD_FIELDS = listOf(
    "device_id", "registration_id", "salt", "sealed", "user_address", "root_public_key",
    "scopes", "signing_public_key", "x25519_public_key", "mlkem_public_key",
)

fun encodeDeviceRecord(record: DeviceRecord): ByteArray = buildJsonObject {
    put("device_id", JsonPrimitive(record.deviceId))
    put("registration_id", JsonPrimitive(record.registrationId))
    put("salt", JsonPrimitive(record.salt))
    put("sealed", JsonPrimitive(record.sealed))
    put("user_address", JsonPrimitive(record.userAddress))
    put("root_public_key", JsonPrimitive(record.rootPublicKey))
    put("scopes", JsonPrimitive(record.scopes))
    put("signing_public_key", JsonPrimitive(record.signingPublicKey))
    put("x25519_public_key", JsonPrimitive(record.x25519PublicKey))
    put("mlkem_public_key", JsonPrimitive(record.mlkemPublicKey))
}.toString().encodeToByteArray()

fun decodeDeviceRecord(bytes: ByteArray): DeviceRecord {
    val json: JsonObject = try {
        Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    } catch (_: IllegalArgumentException) {
        throw DeviceRecordFormatException("the device record is not a JSON object")
    } catch (_: CharacterCodingException) {
        throw DeviceRecordFormatException("the device record is not UTF-8")
    }
    if (json.keys != RECORD_FIELDS.toSet()) throw DeviceRecordFormatException("the device record does not have exactly its fields")
    val field = { name: String ->
        val value = json.getValue(name).jsonPrimitive
        if (!value.isString) throw DeviceRecordFormatException("$name is not a string")
        value.content
    }
    return DeviceRecord(
        deviceId = field("device_id"),
        registrationId = field("registration_id"),
        salt = field("salt"),
        sealed = field("sealed"),
        userAddress = field("user_address"),
        rootPublicKey = field("root_public_key"),
        scopes = field("scopes"),
        signingPublicKey = field("signing_public_key"),
        x25519PublicKey = field("x25519_public_key"),
        mlkemPublicKey = field("mlkem_public_key"),
    )
}

interface DeviceVault {
    fun store(record: ByteArray)
    fun load(): ByteArray?
    fun delete()
}

class MemoryDeviceVault : DeviceVault {
    private var stored: ByteArray? = null

    override fun store(record: ByteArray) {
        stored = record.copyOf()
    }

    override fun load(): ByteArray? = stored?.copyOf()

    override fun delete() {
        stored = null
    }
}

fun saveDeviceRecord(vault: DeviceVault, record: DeviceRecord) = vault.store(encodeDeviceRecord(record))

fun loadDeviceRecord(vault: DeviceVault): DeviceRecord? = vault.load()?.let(::decodeDeviceRecord)
