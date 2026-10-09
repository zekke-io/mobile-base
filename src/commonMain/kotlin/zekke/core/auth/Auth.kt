package zekke.core.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.SessionGrant
import zekke.core.api.ZekkeApi
import zekke.core.api.wireJson
import zekke.core.chain.StoredChainEvent
import zekke.core.chain.batchDigest
import zekke.core.keyrings.ChainEventWire
import zekke.core.keyrings.DeviceBatch
import zekke.core.keyrings.DeviceBatchWire
import zekke.core.keyrings.DeviceRecordOnServer
import zekke.core.keyrings.KeyringsRecord
import zekke.core.keyrings.toWire
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.signing.Action
import zekke.core.signing.PinProofSigner
import zekke.core.signing.RootActionEnvelope
import zekke.core.signing.SignatureEnvelope
import zekke.core.signing.Signer
import zekke.core.signing.signAuthEnvelope
import zekke.core.signing.signRootAction

enum class AuthEndpoint(val path: String) {
    SIGN_UP("/sign-up"),
    SIGN_IN("/sign-in"),
    ENROL("/devices/enrol"),
    ENROL_CHAIN("/devices/enrol/chain"),
}

class AuthRejectedException(val endpoint: AuthEndpoint, val diagnostic: String) : Exception("${endpoint.path} rejected the credentials")

private const val SIGN_UP_DIAGNOSTIC =
    "The root signature did not verify, the challenge was stale, or this address already belongs to an account " +
        "under another root key or with another genesis device. A retry must resend the same genesis."

private const val SIGN_IN_DIAGNOSTIC =
    "Deliberately ambiguous: an unknown or removed device and a bad signature return the same 404."

private const val ENROL_DIAGNOSTIC =
    "Any root or proof failure is a uniform 404: no account for this phrase, a wrong phrase, or a Paranoid account " +
        "whose PIN proof was missing or wrong."

class SignUpOutcome(val grant: SessionGrant, val created: Boolean)

class RootChainAnswer(val chain: List<StoredChainEvent>, val devices: List<DeviceRecordOnServer>)

class EnrolAnswer(val grant: SessionGrant, val chain: List<StoredChainEvent>, val rootKeyrings: KeyringsRecord)

@Serializable
private class RootChainWire(val chain: List<ChainEventWire> = emptyList(), val devices: List<DeviceRecordOnServer> = emptyList())

@Serializable
private class EnrolWire(
    @SerialName("access_token") val accessToken: String,
    @SerialName("device_id") val deviceId: String,
    val chain: List<ChainEventWire> = emptyList(),
    @SerialName("root_keyrings") val rootKeyrings: KeyringsRecord = KeyringsRecord(),
)

internal fun JsonObjectBuilder.putEnvelope(envelope: SignatureEnvelope) {
    put("challenge", envelope.challenge)
    put("timestamp", envelope.timestamp)
    put("signature", envelope.signature)
    if (envelope is RootActionEnvelope) envelope.pinProof?.let { put("pin_proof", it) }
}

internal fun batchJson(batch: DeviceBatch) = wireJson.encodeToJsonElement(DeviceBatchWire.serializer(), batch.toWire())

private suspend fun <T> rejectingAuth(endpoint: AuthEndpoint, diagnostic: String, call: suspend () -> T): T = try {
    call()
} catch (error: ApiError) {
    if (error.isAuthEndpointRejection) throw AuthRejectedException(endpoint, diagnostic)
    throw error
}

suspend fun signUpWithGenesis(
    api: ZekkeApi,
    userAddress: String,
    rootPublicKey: String,
    root: Signer,
    batch: DeviceBatch,
    primitives: Primitives = platformPrimitives(),
): SignUpOutcome {
    val envelope = signAuthEnvelope(root, primitives)
    val body: JsonObject = buildJsonObject {
        put("user_address", userAddress)
        put("public_key", rootPublicKey)
        putEnvelope(envelope)
        put("batch", batchJson(batch))
    }
    return rejectingAuth(AuthEndpoint.SIGN_UP, SIGN_UP_DIAGNOSTIC) {
        val response = api.request(Method.POST, AuthEndpoint.SIGN_UP.path, body = body)
        val grant = response.decode(SessionGrant.serializer())
        api.tokens.set(grant.accessToken)
        SignUpOutcome(grant, created = response.status == 201)
    }
}

suspend fun signInDevice(api: ZekkeApi, deviceId: String, signer: Signer, primitives: Primitives = platformPrimitives()): SessionGrant {
    val envelope = signAuthEnvelope(signer, primitives)
    val body = buildJsonObject {
        put("device_id", deviceId)
        putEnvelope(envelope)
    }
    return rejectingAuth(AuthEndpoint.SIGN_IN, SIGN_IN_DIAGNOSTIC) {
        val grant = api.request(Method.POST, AuthEndpoint.SIGN_IN.path, body = body).decode(SessionGrant.serializer())
        api.tokens.set(grant.accessToken)
        grant
    }
}

suspend fun readChainWithRoot(
    api: ZekkeApi,
    userAddress: String,
    root: Signer,
    pinProof: PinProofSigner? = null,
    primitives: Primitives = platformPrimitives(),
): RootChainAnswer {
    val envelope = signRootAction(Action.CHAIN_READ, listOf(userAddress), root, pinProof, primitives)
    val body = buildJsonObject {
        put("user_address", userAddress)
        putEnvelope(envelope)
    }
    return rejectingAuth(AuthEndpoint.ENROL_CHAIN, ENROL_DIAGNOSTIC) {
        val response = api.request(Method.POST, AuthEndpoint.ENROL_CHAIN.path, body = body)
        val wire = if (response.data == null) RootChainWire() else response.decode(RootChainWire.serializer())
        RootChainAnswer(wire.chain.map { it.toStored() }, wire.devices)
    }
}

suspend fun enrolWithRoot(
    api: ZekkeApi,
    userAddress: String,
    root: Signer,
    batch: DeviceBatch,
    pinProof: PinProofSigner? = null,
    primitives: Primitives = platformPrimitives(),
): EnrolAnswer {
    val envelope = signRootAction(Action.DEVICE_ENROL, listOf(userAddress, batchDigest(batch.events, primitives)), root, pinProof, primitives)
    val body = buildJsonObject {
        put("user_address", userAddress)
        putEnvelope(envelope)
        put("batch", batchJson(batch))
    }
    return rejectingAuth(AuthEndpoint.ENROL, ENROL_DIAGNOSTIC) {
        val wire = api.request(Method.POST, AuthEndpoint.ENROL.path, body = body).decode(EnrolWire.serializer())
        api.tokens.set(wire.accessToken)
        EnrolAnswer(SessionGrant(wire.accessToken, wire.deviceId), wire.chain.map { it.toStored() }, wire.rootKeyrings)
    }
}
