package zekke.core.signing

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.primitives.EcdsaP256
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

const val CHALLENGE_BYTES = 32
const val SIGNATURE_BYTES = EcdsaP256.SIGNATURE_BYTES
const val FRESHNESS_WINDOW_SECONDS = 300

open class SignatureEnvelope(val challenge: String, val timestamp: Long, val signature: String)

class RootActionEnvelope(challenge: String, timestamp: Long, signature: String, val pinProof: String?) :
    SignatureEnvelope(challenge, timestamp, signature)

fun interface Signer {
    fun signBytes(message: ByteArray): ByteArray
}

fun interface PinProofSigner {
    fun signDigest(digest: ByteArray): ByteArray
}

class WrongSignerException(action: Action) :
    IllegalArgumentException("${action.label} is signed by the ${action.signer.name.lowercase()}, not by this signer")

class PinProofNotAllowedException(action: Action) : IllegalArgumentException("${action.label} never carries a PIN proof")

fun rawKeySigner(privateKey: ByteArray, primitives: Primitives = platformPrimitives()): Signer =
    Signer { message -> primitives.ecdsaP256.sign(privateKey, message) }

fun createChallenge(primitives: Primitives = platformPrimitives()): String =
    bytesToHex(primitives.secureRandom.nextBytes(CHALLENGE_BYTES))

@OptIn(ExperimentalTime::class)
fun currentTimestamp(): Long = Clock.System.now().epochSeconds

fun buildAuthPayload(challenge: String, timestamp: Long): String = "$challenge:$timestamp"

fun buildActionPayload(challenge: String, timestamp: Long, action: Action, args: List<String>): String =
    (listOf(challenge, timestamp.toString(), action.label) + normalizeActionArgs(action, args)).joinToString(":")

fun payloadDigest(payload: String, primitives: Primitives = platformPrimitives()): ByteArray =
    primitives.sha2.sha256(utf8ToBytes(payload))

fun signPayload(payload: String, signer: Signer): String {
    val signature = signer.signBytes(utf8ToBytes(payload))
    check(signature.size == SIGNATURE_BYTES) { "expected a $SIGNATURE_BYTES-byte IEEE P1363 signature, got ${signature.size}" }
    return bytesToBase64(signature)
}

fun verifyPayload(
    payload: String,
    signatureBase64: String,
    publicKeyUncompressed: ByteArray,
    primitives: Primitives = platformPrimitives(),
): Boolean {
    val signature = try {
        base64ToBytes(signatureBase64)
    } catch (_: IllegalArgumentException) {
        return false
    }
    if (signature.size != SIGNATURE_BYTES) return false
    return primitives.ecdsaP256.verify(publicKeyUncompressed, utf8ToBytes(payload), signature)
}

fun signAuthEnvelope(
    signer: Signer,
    primitives: Primitives = platformPrimitives(),
    clock: () -> Long = ::currentTimestamp,
): SignatureEnvelope {
    val challenge = createChallenge(primitives)
    val timestamp = clock()
    return SignatureEnvelope(challenge, timestamp, signPayload(buildAuthPayload(challenge, timestamp), signer))
}

fun signActionEnvelope(
    action: Action,
    args: List<String>,
    device: Signer,
    primitives: Primitives = platformPrimitives(),
    clock: () -> Long = ::currentTimestamp,
): SignatureEnvelope {
    if (action.signer != SignerRole.DEVICE) throw WrongSignerException(action)
    val challenge = createChallenge(primitives)
    val timestamp = clock()
    val payload = buildActionPayload(challenge, timestamp, action, args)
    return SignatureEnvelope(challenge, timestamp, signPayload(payload, device))
}

fun signRootAction(
    action: Action,
    args: List<String>,
    root: Signer,
    pinProof: PinProofSigner? = null,
    primitives: Primitives = platformPrimitives(),
    clock: () -> Long = ::currentTimestamp,
): RootActionEnvelope {
    if (action.signer != SignerRole.ROOT) throw WrongSignerException(action)
    if (pinProof != null && !action.pinProof) throw PinProofNotAllowedException(action)
    val challenge = createChallenge(primitives)
    val timestamp = clock()
    val payload = buildActionPayload(challenge, timestamp, action, args)
    val signature = signPayload(payload, root)
    val proof = pinProof?.let { bytesToBase64(it.signDigest(payloadDigest(payload, primitives))) }
    return RootActionEnvelope(challenge, timestamp, signature, proof)
}
