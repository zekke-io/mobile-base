package zekke.core.oprf

import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.primitives.Argon2idParameters
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.signing.PinProofSigner

const val PIN_LEAF_PREFIX = "Cryple-PIN-v1|"
const val DEVICE_CONFIRM_PREFIX = "Cryple-PIN-v1|device-confirm|"
const val DEVICE_SALT_BYTES = 32
const val PIN_LEAF_BYTES = 32

val ARGON2ID_PARAMETERS = Argon2idParameters(iterations = 3, memoryKib = 65536, parallelism = 1, outputLength = 32)

private val EMPTY_SALT = ByteArray(0)

enum class PinLeafLabel(val label: String) {
    DEVICE_WRAP("device-wrap"),
    DEVICE_CONFIRM("device-confirm"),
    ACCOUNT_PROOF("account-proof"),
}

class DevicePinKeys(val wrapKey: SecretBytes, val confirmSeed: SecretBytes, val confirmPublicKey: String)

class AccountProofKey(val seed: SecretBytes, val publicKey: String)

fun stretchPin(pin: CharArray, salt: ByteArray, primitives: Primitives = platformPrimitives()): SecretBytes =
    pinInput(pin).use { input -> input.withBytes { primitives.argon2id.hash(it, salt, ARGON2ID_PARAMETERS) }.adoptAsSecret() }

fun pinIkm(oprfOutput: SecretBytes, argon: SecretBytes): SecretBytes {
    require(oprfOutput.size == OPRF_OUTPUT_BYTES && argon.size == ARGON2ID_PARAMETERS.outputLength) {
        "the PIN key material is an OPRF output and an Argon2id output"
    }
    return oprfOutput.withBytes { output -> argon.withBytes { concatBytes(output, it) } }.adoptAsSecret()
}

fun pinLeaf(ikm: SecretBytes, label: PinLeafLabel, primitives: Primitives = platformPrimitives()): SecretBytes =
    ikm.withBytes { primitives.hkdf.sha256(it, EMPTY_SALT, utf8ToBytes(PIN_LEAF_PREFIX + label.label), PIN_LEAF_BYTES) }.adoptAsSecret()

fun ed25519PublicKey(seed: SecretBytes, primitives: Primitives = platformPrimitives()): String =
    bytesToBase64(seed.withBytes { primitives.ed25519.publicKey(it) })

fun deriveDevicePinKeys(
    oprfOutput: SecretBytes,
    pin: CharArray,
    salt: ByteArray,
    primitives: Primitives = platformPrimitives(),
): DevicePinKeys {
    var argon: SecretBytes? = null
    var ikm: SecretBytes? = null
    try {
        argon = stretchPin(pin, salt, primitives)
        ikm = pinIkm(oprfOutput, argon)
        val wrapKey = pinLeaf(ikm, PinLeafLabel.DEVICE_WRAP, primitives)
        val confirmSeed = pinLeaf(ikm, PinLeafLabel.DEVICE_CONFIRM, primitives)
        return DevicePinKeys(wrapKey, confirmSeed, ed25519PublicKey(confirmSeed, primitives))
    } finally {
        zeroSecrets(argon, ikm, oprfOutput)
    }
}

fun zeroDevicePinKeys(keys: DevicePinKeys?) {
    if (keys != null) zeroSecrets(keys.wrapKey, keys.confirmSeed)
}

fun deviceConfirmMessage(registrationId: String, attemptId: String): String =
    "$DEVICE_CONFIRM_PREFIX$registrationId|$attemptId"

fun signDeviceConfirmation(
    confirmSeed: SecretBytes,
    registrationId: String,
    attemptId: String,
    primitives: Primitives = platformPrimitives(),
): String {
    val message = utf8ToBytes(deviceConfirmMessage(registrationId, attemptId))
    return bytesToBase64(confirmSeed.withBytes { primitives.ed25519.sign(it, message) })
}

fun deriveAccountProofKey(
    oprfOutput: SecretBytes,
    pin: CharArray,
    userAddress: String,
    primitives: Primitives = platformPrimitives(),
): AccountProofKey {
    var argon: SecretBytes? = null
    var ikm: SecretBytes? = null
    try {
        argon = stretchPin(pin, utf8ToBytes(userAddress), primitives)
        ikm = pinIkm(oprfOutput, argon)
        val seed = pinLeaf(ikm, PinLeafLabel.ACCOUNT_PROOF, primitives)
        return AccountProofKey(seed, ed25519PublicKey(seed, primitives))
    } finally {
        zeroSecrets(argon, ikm, oprfOutput)
    }
}

fun zeroAccountProofKey(key: AccountProofKey?) {
    if (key != null) zeroSecrets(key.seed)
}

fun proofSigner(key: AccountProofKey, primitives: Primitives = platformPrimitives()): PinProofSigner =
    PinProofSigner { digest -> key.seed.withBytes { primitives.ed25519.sign(it, digest) } }

fun generateDeviceSalt(primitives: Primitives = platformPrimitives()): ByteArray =
    primitives.secureRandom.nextBytes(DEVICE_SALT_BYTES)
