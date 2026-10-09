package zekke.core.oprf

import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
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

class DevicePinKeys(val wrapKey: ByteArray, val confirmSeed: ByteArray, val confirmPublicKey: String)

class AccountProofKey(val seed: ByteArray, val publicKey: String)

fun stretchPin(pin: CharArray, salt: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray {
    val input = pinInput(pin)
    try {
        return primitives.argon2id.hash(input, salt, ARGON2ID_PARAMETERS)
    } finally {
        zeroBytes(input)
    }
}

fun pinIkm(oprfOutput: ByteArray, argon: ByteArray): ByteArray {
    require(oprfOutput.size == OPRF_OUTPUT_BYTES && argon.size == ARGON2ID_PARAMETERS.outputLength) {
        "the PIN key material is an OPRF output and an Argon2id output"
    }
    return concatBytes(oprfOutput, argon)
}

fun pinLeaf(ikm: ByteArray, label: PinLeafLabel, primitives: Primitives = platformPrimitives()): ByteArray =
    primitives.hkdf.sha256(ikm, EMPTY_SALT, utf8ToBytes(PIN_LEAF_PREFIX + label.label), PIN_LEAF_BYTES)

fun ed25519PublicKey(seed: ByteArray, primitives: Primitives = platformPrimitives()): String =
    bytesToBase64(primitives.ed25519.publicKey(seed))

fun deriveDevicePinKeys(
    oprfOutput: ByteArray,
    pin: CharArray,
    salt: ByteArray,
    primitives: Primitives = platformPrimitives(),
): DevicePinKeys {
    val argon = stretchPin(pin, salt, primitives)
    val ikm = pinIkm(oprfOutput, argon)
    try {
        val wrapKey = pinLeaf(ikm, PinLeafLabel.DEVICE_WRAP, primitives)
        val confirmSeed = pinLeaf(ikm, PinLeafLabel.DEVICE_CONFIRM, primitives)
        return DevicePinKeys(wrapKey, confirmSeed, ed25519PublicKey(confirmSeed, primitives))
    } finally {
        zeroBytes(argon, ikm, oprfOutput)
    }
}

fun zeroDevicePinKeys(keys: DevicePinKeys?) {
    if (keys != null) zeroBytes(keys.wrapKey, keys.confirmSeed)
}

fun deviceConfirmMessage(registrationId: String, attemptId: String): String =
    "$DEVICE_CONFIRM_PREFIX$registrationId|$attemptId"

fun signDeviceConfirmation(
    confirmSeed: ByteArray,
    registrationId: String,
    attemptId: String,
    primitives: Primitives = platformPrimitives(),
): String = bytesToBase64(primitives.ed25519.sign(confirmSeed, utf8ToBytes(deviceConfirmMessage(registrationId, attemptId))))

fun deriveAccountProofKey(
    oprfOutput: ByteArray,
    pin: CharArray,
    userAddress: String,
    primitives: Primitives = platformPrimitives(),
): AccountProofKey {
    val argon = stretchPin(pin, utf8ToBytes(userAddress), primitives)
    val ikm = pinIkm(oprfOutput, argon)
    try {
        val seed = pinLeaf(ikm, PinLeafLabel.ACCOUNT_PROOF, primitives)
        return AccountProofKey(seed, ed25519PublicKey(seed, primitives))
    } finally {
        zeroBytes(argon, ikm, oprfOutput)
    }
}

fun zeroAccountProofKey(key: AccountProofKey?) {
    if (key != null) zeroBytes(key.seed)
}

fun proofSigner(key: AccountProofKey, primitives: Primitives = platformPrimitives()): PinProofSigner =
    PinProofSigner { digest -> primitives.ed25519.sign(key.seed, digest) }

fun generateDeviceSalt(primitives: Primitives = platformPrimitives()): ByteArray =
    primitives.secureRandom.nextBytes(DEVICE_SALT_BYTES)
