package zekke.core.device

import zekke.core.chain.DeviceKeysDeclaration
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.concatBytes
import zekke.core.encoding.uncompressedPointToSpkiBase64
import zekke.core.encoding.zeroBytes
import zekke.core.keyrings.DeviceSecrets
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.pqxdh.X25519Agreement
import zekke.core.pqxdh.rawX25519Agreement
import zekke.core.primitives.MlKem768
import zekke.core.primitives.P256Scalar
import zekke.core.primitives.Primitives
import zekke.core.primitives.X25519
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope
import zekke.core.signing.Signer
import zekke.core.signing.rawKeySigner

const val SIGNING_PRIVATE_KEY_BYTES = P256Scalar.BYTES
const val X25519_PRIVATE_BYTES = X25519.KEY_BYTES
const val MLKEM_SEED_BYTES = MlKem768.SEED_BYTES
const val DEVICE_MATERIAL_BYTES = SIGNING_PRIVATE_KEY_BYTES + X25519_PRIVATE_BYTES + MLKEM_SEED_BYTES

class DeviceMaterialException(message: String) : IllegalStateException(message)

class DeviceKeys(
    val deviceId: String,
    val signingPrivateKey: SecretBytes,
    val signingPublicKey: String,
    val x25519PrivateKey: SecretBytes,
    val x25519PublicKey: ByteArray,
    val mlkemSeed: SecretBytes,
    val mlkemSecretKey: SecretBytes,
    val mlkemPublicKey: ByteArray,
)

fun generateDeviceId(primitives: Primitives = platformPrimitives()): String {
    val bytes = primitives.secureRandom.nextBytes(16)
    bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x40).toByte()
    bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte()
    val hex = bytesToHex(bytes)
    return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
}

private fun generateSigningPrivateKey(primitives: Primitives): SecretBytes {
    while (true) {
        val candidate = primitives.secureRandom.nextBytes(SIGNING_PRIVATE_KEY_BYTES)
        if (P256Scalar.isValidPrivateKey(candidate)) return candidate.adoptAsSecret()
        zeroBytes(candidate)
    }
}

fun deviceKeysFromMaterial(
    deviceId: String,
    signingPrivateKey: SecretBytes,
    x25519PrivateKey: SecretBytes,
    mlkemSeed: SecretBytes,
    primitives: Primitives = platformPrimitives(),
): DeviceKeys {
    if (signingPrivateKey.size != SIGNING_PRIVATE_KEY_BYTES || x25519PrivateKey.size != X25519_PRIVATE_BYTES || mlkemSeed.size != MLKEM_SEED_BYTES) {
        throw DeviceMaterialException("device material is a P-256 key, an X25519 key and a 64-byte ML-KEM seed")
    }
    val signingPoint = signingPrivateKey.withBytes { primitives.ecdsaP256.publicKey(it) }
    val keyPair = mlkemSeed.withBytes { primitives.mlKem768.keyPairFromSeed(it) }
    return DeviceKeys(
        deviceId = deviceId,
        signingPrivateKey = signingPrivateKey,
        signingPublicKey = uncompressedPointToSpkiBase64(signingPoint),
        x25519PrivateKey = x25519PrivateKey,
        x25519PublicKey = x25519PrivateKey.withBytes { primitives.x25519.publicKey(it) },
        mlkemSeed = mlkemSeed,
        mlkemSecretKey = keyPair.secretKey.adoptAsSecret(),
        mlkemPublicKey = keyPair.publicKey,
    )
}

fun generateDeviceKeys(deviceId: String? = null, primitives: Primitives = platformPrimitives()): DeviceKeys =
    deviceKeysFromMaterial(
        deviceId = deviceId ?: generateDeviceId(primitives),
        signingPrivateKey = generateSigningPrivateKey(primitives),
        x25519PrivateKey = primitives.secureRandom.nextBytes(X25519_PRIVATE_BYTES).adoptAsSecret(),
        mlkemSeed = primitives.secureRandom.nextBytes(MLKEM_SEED_BYTES).adoptAsSecret(),
        primitives = primitives,
    )

fun deviceDeclaration(keys: DeviceKeys, scopes: List<Scope>): DeviceKeysDeclaration = DeviceKeysDeclaration(
    deviceId = keys.deviceId,
    signingPublicKey = keys.signingPublicKey,
    x25519PublicKey = bytesToBase64(keys.x25519PublicKey),
    mlkemPublicKey = bytesToBase64(keys.mlkemPublicKey),
    scopes = scopes,
)

fun deviceSigner(keys: DeviceKeys, primitives: Primitives = platformPrimitives()): Signer =
    rawKeySigner(keys.signingPrivateKey, primitives)

fun deviceX25519Agreement(keys: DeviceKeys, primitives: Primitives = platformPrimitives()): X25519Agreement =
    rawX25519Agreement(keys.x25519PrivateKey, primitives)

fun deviceSecrets(keys: DeviceKeys, primitives: Primitives = platformPrimitives()): DeviceSecrets =
    DeviceSecrets(keys.deviceId, deviceX25519Agreement(keys, primitives), keys.mlkemSecretKey)

fun sealableMaterial(keys: DeviceKeys): SecretBytes =
    keys.signingPrivateKey.withBytes { signing ->
        keys.x25519PrivateKey.withBytes { x25519 ->
            keys.mlkemSeed.withBytes { seed -> concatBytes(signing, x25519, seed) }
        }
    }.adoptAsSecret()

fun zeroDeviceKeys(keys: DeviceKeys?) {
    if (keys != null) zeroSecrets(keys.signingPrivateKey, keys.x25519PrivateKey, keys.mlkemSeed, keys.mlkemSecretKey)
}
