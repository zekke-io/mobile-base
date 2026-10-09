package zekke.core.keyrings

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.pqxdh.PqxdhContext
import zekke.core.pqxdh.PqxdhUsage
import zekke.core.pqxdh.RecipientKeys
import zekke.core.pqxdh.RecipientSecrets
import zekke.core.pqxdh.X25519Agreement
import zekke.core.pqxdh.deviceRecipientSlot
import zekke.core.pqxdh.pqxdhUnwrap
import zekke.core.pqxdh.pqxdhWrap
import zekke.core.primitives.MlKem768
import zekke.core.primitives.Primitives
import zekke.core.primitives.X25519
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope
import zekke.core.sealed.openBytes
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.sealBytes
import zekke.core.sealed.sealBytesWithIv
import zekke.core.sealed.sealSecretBlob

const val SCOPE_KEK_BYTES = 32
const val SHARE_SUBKEY_BYTES = 32
const val SHARE_SUBKEY_INFO_PREFIX = "Cryple-Share-v1|"

private const val SHARING_MATERIAL_BYTES = X25519.KEY_BYTES + MlKem768.SEED_BYTES
private val EMPTY_SALT = ByteArray(0)

class KeyringException(message: String) : IllegalStateException(message)

fun generateScopeKek(primitives: Primitives = platformPrimitives()): SecretBytes =
    primitives.secureRandom.nextBytes(SCOPE_KEK_BYTES).adoptAsSecret()

fun wrapKekForRoot(rootWrapKey: SecretBytes, kek: SecretBytes, primitives: Primitives = platformPrimitives()): String =
    sealSecretBlob(kek, rootWrapKey, primitives)

internal fun wrapKekForRootWithIv(rootWrapKey: SecretBytes, kek: SecretBytes, iv: ByteArray, primitives: Primitives): String =
    bytesToBase64(kek.withBytes { sealBytesWithIv(it, rootWrapKey, iv, primitives) })

fun openRootWrap(rootWrapKey: SecretBytes, wrapped: String, primitives: Primitives = platformPrimitives()): SecretBytes =
    assertKek(openSecretBlob(wrapped, rootWrapKey, primitives))

class DeviceRecipient(val deviceId: String, val x25519PublicKey: String, val mlkemPublicKey: String)

fun deviceRecipientKeys(device: DeviceRecipient): RecipientKeys =
    RecipientKeys(base64ToBytes(device.x25519PublicKey), base64ToBytes(device.mlkemPublicKey))

fun deviceKeyringContext(userAddress: String, deviceId: String): PqxdhContext =
    PqxdhContext(PqxdhUsage.DEVICE_KEYRING, userAddress, deviceRecipientSlot(userAddress, deviceId))

fun wrapKekForDevice(
    kek: SecretBytes,
    userAddress: String,
    device: DeviceRecipient,
    primitives: Primitives = platformPrimitives(),
): String = pqxdhWrap(kek, deviceRecipientKeys(device), deviceKeyringContext(userAddress, device.deviceId), primitives)

class DeviceSecrets(val deviceId: String, val x25519: X25519Agreement, val mlkemSecretKey: SecretBytes)

fun openDeviceWrap(
    wrapped: String,
    userAddress: String,
    device: DeviceSecrets,
    primitives: Primitives = platformPrimitives(),
): SecretBytes = assertKek(
    pqxdhUnwrap(
        wrapped,
        RecipientSecrets(device.x25519, device.mlkemSecretKey),
        deviceKeyringContext(userAddress, device.deviceId),
        primitives,
    ),
)

private fun assertKek(kek: SecretBytes): SecretBytes {
    if (kek.size != SCOPE_KEK_BYTES) {
        kek.zero()
        throw KeyringException("a scope KEK is $SCOPE_KEK_BYTES bytes")
    }
    return kek
}

class SharingKeyPair(
    val x25519PrivateKey: SecretBytes,
    val x25519PublicKey: ByteArray,
    val mlkemSeed: SecretBytes,
    val mlkemSecretKey: SecretBytes,
    val mlkemPublicKey: ByteArray,
)

fun sharingKeysFromMaterial(
    x25519PrivateKey: SecretBytes,
    mlkemSeed: SecretBytes,
    primitives: Primitives = platformPrimitives(),
): SharingKeyPair {
    if (x25519PrivateKey.size != X25519.KEY_BYTES || mlkemSeed.size != MlKem768.SEED_BYTES) {
        throw KeyringException("sharing material is an X25519 key and a 64-byte ML-KEM seed")
    }
    val keyPair = mlkemSeed.withBytes { primitives.mlKem768.keyPairFromSeed(it) }
    return SharingKeyPair(
        x25519PrivateKey = x25519PrivateKey,
        x25519PublicKey = x25519PrivateKey.withBytes { primitives.x25519.publicKey(it) },
        mlkemSeed = mlkemSeed,
        mlkemSecretKey = keyPair.secretKey.adoptAsSecret(),
        mlkemPublicKey = keyPair.publicKey,
    )
}

fun generateSharingKeys(primitives: Primitives = platformPrimitives()): SharingKeyPair = sharingKeysFromMaterial(
    primitives.secureRandom.nextBytes(X25519.KEY_BYTES).adoptAsSecret(),
    primitives.secureRandom.nextBytes(MlKem768.SEED_BYTES).adoptAsSecret(),
    primitives,
)

fun zeroSharingKeys(keys: SharingKeyPair?) {
    if (keys != null) zeroSecrets(keys.x25519PrivateKey, keys.mlkemSeed, keys.mlkemSecretKey)
}

fun sealSharingMaterial(sharingKek: SecretBytes, keys: SharingKeyPair, primitives: Primitives = platformPrimitives()): String {
    val material = keys.x25519PrivateKey.withBytes { x25519 -> keys.mlkemSeed.withBytes { seed -> concatBytes(x25519, seed) } }
    try {
        return bytesToBase64(sealBytes(material, sharingKek, primitives))
    } finally {
        zeroBytes(material)
    }
}

fun openSharingMaterial(sharingKek: SecretBytes, sealed: String, primitives: Primitives = platformPrimitives()): SharingKeyPair {
    val material = openBytes(base64ToBytes(sealed), sharingKek, primitives)
    try {
        if (material.size != SHARING_MATERIAL_BYTES) throw KeyringException("sharing material has the wrong length")
        return sharingKeysFromMaterial(
            material.copyOfRange(0, X25519.KEY_BYTES).adoptAsSecret(),
            material.copyOfRange(X25519.KEY_BYTES, SHARING_MATERIAL_BYTES).adoptAsSecret(),
            primitives,
        )
    } finally {
        zeroBytes(material)
    }
}

fun deriveShareSubkey(connectionKey: SecretBytes, scope: Scope, primitives: Primitives = platformPrimitives()): SecretBytes =
    connectionKey.withBytes {
        primitives.hkdf.sha256(it, EMPTY_SALT, utf8ToBytes(SHARE_SUBKEY_INFO_PREFIX + scope.wire), SHARE_SUBKEY_BYTES)
    }.adoptAsSecret()
