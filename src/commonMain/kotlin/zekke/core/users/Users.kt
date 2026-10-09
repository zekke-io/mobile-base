package zekke.core.users

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.api.assertCanonicalUuid
import zekke.core.auth.putEnvelope
import zekke.core.keyrings.ChainEventWire
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.signing.Action
import zekke.core.signing.PinProofSigner
import zekke.core.signing.Signer
import zekke.core.signing.signActionEnvelope
import zekke.core.signing.signRootAction

private val USER_ADDRESS = Regex("^[0-9a-f]{64}$")
val USERNAME_PATTERN = Regex("^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$")

class MalformedUsernameException(value: String) : IllegalArgumentException("\"$value\" is not a valid username")

fun normalizeUsername(value: String): String = value.trim().lowercase()

fun isUsername(value: String): Boolean = USERNAME_PATTERN.matches(value)

@Serializable
class PlanRecord(
    val code: String,
    val state: String,
    @SerialName("paid_until") val paidUntil: String? = null,
    val renews: Boolean = false,
    @SerialName("grace_ends_at") val graceEndsAt: String? = null,
    @SerialName("storage_quota_bytes") val storageQuotaBytes: Long = 0,
    @SerialName("retention_days") val retentionDays: Int = 0,
    val features: List<String> = emptyList(),
)

@Serializable
class AccountRecord(
    @SerialName("user_address") val userAddress: String,
    val username: String,
    val uuid: String,
    val paranoid: Boolean,
    @SerialName("retention_days") val retentionDays: Int = 0,
    @SerialName("created_at") val createdAt: String,
    val plan: PlanRecord? = null,
)

@Serializable
class UsernameResolution(val uuid: String, val username: String)

@Serializable
class PublishedSharingKeysWire(
    val generation: Int,
    @SerialName("encryption_public_key_x25519") val x25519PublicKey: String,
    @SerialName("encryption_public_key_mlkem") val mlkemPublicKey: String,
)

@Serializable
class PublicKeysRecord(
    val uuid: String,
    @SerialName("user_address") val userAddress: String,
    @SerialName("root_public_key") val rootPublicKey: String,
    @SerialName("sharing_keys") val sharingKeys: PublishedSharingKeysWire,
    val proof: List<ChainEventWire>,
)

@Serializable
private class UsernameAnswer(val username: String)

suspend fun getMe(api: ZekkeApi): AccountRecord =
    api.request(Method.GET, "/users/me", token = api.tokens.require()).decode(AccountRecord.serializer())

suspend fun lookupUsername(api: ZekkeApi, userAddress: String): String {
    require(USER_ADDRESS.matches(userAddress)) { "user_address must be 64 lowercase hex characters" }
    return api.request(Method.GET, "/users/lookup", query = mapOf("address" to userAddress)).decode(UsernameAnswer.serializer()).username
}

suspend fun updateUsername(api: ZekkeApi, device: Signer, username: String, primitives: Primitives = platformPrimitives()): String {
    val claimed = normalizeUsername(username)
    if (!isUsername(claimed)) throw MalformedUsernameException(username)
    val envelope = signActionEnvelope(Action.USERNAME_UPDATE, listOf(claimed), device, primitives)
    api.request(
        Method.PUT,
        "/users/username",
        body = buildJsonObject {
            put("username", claimed)
            putEnvelope(envelope)
        },
        token = api.tokens.require(),
    )
    return claimed
}

suspend fun resolveUsername(api: ZekkeApi, username: String): UsernameResolution? {
    val wanted = normalizeUsername(username)
    if (!isUsername(wanted)) return null
    return try {
        api.request(Method.GET, "/users/resolve", query = mapOf("username" to wanted), token = api.tokens.require())
            .decode(UsernameResolution.serializer())
    } catch (error: ApiError) {
        if (error.status == 404) null else throw error
    }
}

suspend fun getPublicKeys(api: ZekkeApi, uuid: String): PublicKeysRecord =
    api.request(Method.GET, "/users/${assertCanonicalUuid(uuid, "uuid")}/public-keys", token = api.tokens.require())
        .decode(PublicKeysRecord.serializer())

suspend fun deleteAccount(
    api: ZekkeApi,
    userAddress: String,
    root: Signer,
    pinProof: PinProofSigner? = null,
    primitives: Primitives = platformPrimitives(),
) {
    val envelope = signRootAction(Action.ACCOUNT_DELETE, listOf(userAddress), root, pinProof, primitives)
    api.request(Method.DELETE, "/users", body = buildJsonObject { putEnvelope(envelope) }, token = api.tokens.require())
}
