package zekke.core.pairing

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.api.assertCanonicalUuid
import zekke.core.account.verifyOwnChain
import zekke.core.chain.DeviceKeysDeclaration
import zekke.core.chain.validateMlkemPublicKey
import zekke.core.chain.validateSigningPublicKey
import zekke.core.chain.validateX25519PublicKey
import zekke.core.encoding.utf8ToBytes
import zekke.core.items.ItemContext
import zekke.core.keyrings.BatchAuthor
import zekke.core.keyrings.LinkedKek
import zekke.core.keyrings.applyDeviceBatch
import zekke.core.keyrings.buildDeviceLink
import zekke.core.keyrings.fetchChain
import zekke.core.keyrings.refreshKeyrings
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope

const val PAIRING_LABEL = "Cryple-Pairing-v1"
const val PAIRING_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
const val PAIRING_CODE_LENGTH = 8
val EXTENSION_SCOPES: List<Scope> = listOf(Scope.PASSWORDS)

class MalformedPairingCodeException : IllegalArgumentException("a pairing code is 8 characters, letters and digits")

class PairingNotClaimedException : IllegalStateException("nothing has claimed this pairing yet")

object PairingStatus {
    const val OPEN = "open"
    const val CLAIMED = "claimed"
    const val LINKED = "linked"
    const val CANCELLED = "cancelled"
    const val EXPIRED = "expired"
}

class PairingParties(
    val code: String,
    val userAddress: String,
    val rootPublicKey: String,
    val deviceId: String,
    val signingPublicKey: String,
    val x25519PublicKey: String,
    val mlkemPublicKey: String,
)

fun normalisePairingCode(typed: String): String {
    val normalised = StringBuilder()
    for (character in typed.uppercase()) {
        if (character == '-' || character == ' ') continue
        val mapped = when (character) {
            'I', 'L' -> '1'
            'O' -> '0'
            else -> character
        }
        if (mapped !in PAIRING_CODE_ALPHABET) throw MalformedPairingCodeException()
        normalised.append(mapped)
    }
    if (normalised.length != PAIRING_CODE_LENGTH) throw MalformedPairingCodeException()
    return normalised.toString()
}

fun formatPairingCode(code: String): String = normalisePairingCode(code).let { "${it.substring(0, 4)}-${it.substring(4)}" }

fun pairingFingerprint(parties: PairingParties, primitives: Primitives = platformPrimitives()): String {
    val input = listOf(
        PAIRING_LABEL,
        normalisePairingCode(parties.code),
        parties.userAddress,
        parties.rootPublicKey,
        parties.deviceId,
        parties.signingPublicKey,
        parties.x25519PublicKey,
        parties.mlkemPublicKey,
    ).joinToString("|")
    val digest = primitives.sha2.sha256(utf8ToBytes(input))
    val number = ((digest[0].toLong() and 0xff) shl 24 or ((digest[1].toLong() and 0xff) shl 16) or
        ((digest[2].toLong() and 0xff) shl 8) or (digest[3].toLong() and 0xff)) % 1_000_000
    return number.toString().padStart(6, '0')
}

fun displayFingerprint(fingerprint: String): String = "${fingerprint.substring(0, 3)} ${fingerprint.substring(3)}"

@Serializable
class OpenedPairing(val id: String, val code: String, @SerialName("expires_at") val expiresAt: String)

@Serializable
class PairingRecord(
    val id: String,
    val status: String,
    @SerialName("device_id") val deviceId: String? = null,
    @SerialName("signing_public_key") val signingPublicKey: String? = null,
    @SerialName("x25519_public_key") val x25519PublicKey: String? = null,
    @SerialName("mlkem_public_key") val mlkemPublicKey: String? = null,
    @SerialName("expires_at") val expiresAt: String = "",
)

@Serializable
class ClaimedPairing(
    @SerialName("claim_id") val claimId: String,
    @SerialName("user_address") val userAddress: String,
    @SerialName("root_public_key") val rootPublicKey: String,
    val username: String? = null,
    @SerialName("expires_at") val expiresAt: String = "",
)

@Serializable
private class ClaimStatus(val status: String)

class ClaimedDevice(val deviceId: String, val signingPublicKey: String, val x25519PublicKey: String, val mlkemPublicKey: String)

suspend fun openPairing(api: ZekkeApi): OpenedPairing =
    api.request(Method.POST, "/devices/pairings", token = api.tokens.require()).decode(OpenedPairing.serializer())

suspend fun getPairing(api: ZekkeApi, id: String): PairingRecord =
    api.request(Method.GET, "/devices/pairings/${assertCanonicalUuid(id)}", token = api.tokens.require()).decode(PairingRecord.serializer())

suspend fun completePairing(api: ZekkeApi, id: String, deviceId: String) {
    api.request(
        Method.POST,
        "/devices/pairings/${assertCanonicalUuid(id)}/complete",
        body = buildJsonObject { put("device_id", assertCanonicalUuid(deviceId)) },
        token = api.tokens.require(),
    )
}

suspend fun cancelPairing(api: ZekkeApi, id: String) {
    api.request(Method.DELETE, "/devices/pairings/${assertCanonicalUuid(id)}", token = api.tokens.require())
}

suspend fun claimPairing(api: ZekkeApi, code: String, device: ClaimedDevice): ClaimedPairing =
    api.request(
        Method.POST,
        "/pairings/claim",
        body = buildJsonObject {
            put("code", formatPairingCode(code))
            put("device_id", assertCanonicalUuid(device.deviceId))
            put("signing_public_key", device.signingPublicKey)
            put("x25519_public_key", device.x25519PublicKey)
            put("mlkem_public_key", device.mlkemPublicKey)
        },
    ).decode(ClaimedPairing.serializer())

suspend fun claimStatus(api: ZekkeApi, claimId: String): String =
    api.request(Method.GET, "/pairings/${assertCanonicalUuid(claimId)}").decode(ClaimStatus.serializer()).status

fun claimedDevice(pairing: PairingRecord, primitives: Primitives = platformPrimitives()): ClaimedDevice {
    val deviceId = pairing.deviceId
    val signing = pairing.signingPublicKey
    val x25519 = pairing.x25519PublicKey
    val mlkem = pairing.mlkemPublicKey
    if (pairing.status != PairingStatus.CLAIMED || deviceId == null || signing == null || x25519 == null || mlkem == null) {
        throw PairingNotClaimedException()
    }
    validateSigningPublicKey(signing)
    validateX25519PublicKey(x25519)
    validateMlkemPublicKey(mlkem, primitives)
    return ClaimedDevice(assertCanonicalUuid(deviceId), signing, x25519, mlkem)
}

fun ownerFingerprint(context: ItemContext, code: String, device: ClaimedDevice): String = pairingFingerprint(
    PairingParties(
        code,
        context.session.userAddress,
        context.session.rootPublicKey,
        device.deviceId,
        device.signingPublicKey,
        device.x25519PublicKey,
        device.mlkemPublicKey,
    ),
    context.primitives,
)

private suspend fun passwordsKeks(context: ItemContext): List<LinkedKek> {
    val session = context.session
    val current = session.currentGeneration(Scope.PASSWORDS)
    return (1..current).map { generation ->
        if (!session.hasKek(Scope.PASSWORDS, generation)) refreshKeyrings(context.api, session, context.primitives)
        LinkedKek(Scope.PASSWORDS, generation, session.kek(Scope.PASSWORDS, generation))
    }
}

suspend fun linkClaimedDevice(context: ItemContext, pairingId: String, device: ClaimedDevice) {
    val session = context.session
    val state = verifyOwnChain(session.userAddress, session.rootPublicKey, session.deviceId, fetchChain(context.api), context.primitives)
    val batch = buildDeviceLink(
        state,
        BatchAuthor(session.deviceId, session.signer()),
        DeviceKeysDeclaration(device.deviceId, device.signingPublicKey, device.x25519PublicKey, device.mlkemPublicKey, EXTENSION_SCOPES),
        passwordsKeks(context),
        context.primitives,
    )
    applyDeviceBatch(context.api, batch)
    completePairing(context.api, pairingId, device.deviceId)
}
