package zekke.core.secrets

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.add
import zekke.core.api.Method
import zekke.core.api.assertCanonicalUuid
import zekke.core.feed.FeedScope
import zekke.core.feed.Outbox
import zekke.core.items.ItemContext
import zekke.core.items.ItemTooLargeException
import zekke.core.items.ScopeDeks
import zekke.core.items.WrappedDek
import zekke.core.items.canonicalSelection
import zekke.core.items.generateDek
import zekke.core.items.itemIdOrNew
import zekke.core.items.signedBody
import zekke.core.items.utf8Length
import zekke.core.keyrings.withCurrentGeneration
import zekke.core.scopes.Scope
import zekke.core.sealed.sealText
import zekke.core.signing.Action

const val MAX_SECRET_PLAINTEXT_BYTES = 700 * 1024
const val SECRET_VERSION = "v1"

@Serializable
class SecretRecord(
    val id: String,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val version: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("updated_at") val updatedAt: String,
    @SerialName("deleted_at") val deletedAt: String? = null,
)

@Serializable
class SecretMetaRecord(
    val id: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    @SerialName("ciphertext_sha256") val ciphertextSha256: String,
    @SerialName("ciphertext_bytes") val ciphertextBytes: Long,
    val version: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("updated_at") val updatedAt: String,
)

@Serializable
class SecretDeleteResult(val requested: Int, val deleted: Int)

@Serializable
class SecretPurgeResult(val requested: Int, val purged: Int)

class CreateSecretResult(val secret: SecretRecord, val created: Boolean)

class SealedSecret(val id: String, val ciphertext: String, val wrapped: WrappedDek) {
    val body: JsonObject
        get() = buildJsonObject {
            put("id", id)
            put("ciphertext", ciphertext)
            put("wrapped_dek", wrapped.wrappedDek)
            put("key_generation", wrapped.keyGeneration)
            put("version", SECRET_VERSION)
        }
}

fun secretDeks(context: ItemContext): ScopeDeks = ScopeDeks(context, Scope.SECRETS)

private fun requireWithinBudget(plaintext: String) {
    val bytes = utf8Length(plaintext)
    if (bytes > MAX_SECRET_PLAINTEXT_BYTES) throw ItemTooLargeException(bytes, MAX_SECRET_PLAINTEXT_BYTES)
}

fun sealSecret(context: ItemContext, plaintext: String, id: String? = null): SealedSecret {
    requireWithinBudget(plaintext)
    val itemId = itemIdOrNew(id, context.primitives)
    return generateDek(context.primitives).use { dek ->
        SealedSecret(itemId, sealText(plaintext, dek, context.primitives), secretDeks(context).wrap(dek))
    }
}

suspend fun createSecret(context: ItemContext, plaintext: String, id: String? = null): CreateSecretResult {
    requireWithinBudget(plaintext)
    val itemId = itemIdOrNew(id, context.primitives)
    return generateDek(context.primitives).use { dek ->
        val ciphertext = sealText(plaintext, dek, context.primitives)
        val response = withCurrentGeneration(context.api, context.session) {
            val sealed = SealedSecret(itemId, ciphertext, secretDeks(context).wrap(dek))
            context.api.request(Method.POST, "/secrets", body = sealed.body, token = context.api.tokens.require())
        }
        CreateSecretResult(response.decode(SecretRecord.serializer()), response.status == 201)
    }
}

fun queueSecret(context: ItemContext, outbox: Outbox, plaintext: String, id: String? = null): String {
    val sealed = sealSecret(context, plaintext, id)
    outbox.enqueue(sealed.id, FeedScope.SECRETS, Method.POST, "/secrets", sealed.body, sealed.wrapped.keyGeneration)
    return sealed.id
}

suspend fun listSecretsMeta(context: ItemContext): List<SecretMetaRecord> {
    val response = context.api.request(Method.GET, "/secrets", token = context.api.tokens.require(), query = mapOf("fields" to "meta"))
    return if (response.data == null) emptyList() else response.decode(ListSerializer(SecretMetaRecord.serializer()))
}

suspend fun listSecrets(context: ItemContext): List<SecretRecord> {
    val response = context.api.request(Method.GET, "/secrets", token = context.api.tokens.require())
    return if (response.data == null) emptyList() else response.decode(ListSerializer(SecretRecord.serializer()))
}

suspend fun getSecret(context: ItemContext, id: String): SecretRecord =
    context.api.request(Method.GET, "/secrets/${assertCanonicalUuid(id)}", token = context.api.tokens.require())
        .decode(SecretRecord.serializer())

suspend fun openSecret(context: ItemContext, secret: SecretRecord): String =
    secretDeks(context).openText(secret.ciphertext, secret.wrappedDek, secret.keyGeneration)

suspend fun deleteSecret(context: ItemContext, id: String) {
    val canonical = assertCanonicalUuid(id)
    val body = signedBody(context, Action.SECRET_DELETE, listOf(canonical))
    context.api.request(Method.DELETE, "/secrets/$canonical", body = body, token = context.api.tokens.require())
}

suspend fun deleteSecrets(context: ItemContext, ids: List<String>): SecretDeleteResult {
    val normalized = canonicalSelection(Action.SECRET_DELETE, ids)
    val body = signedBody(context, Action.SECRET_DELETE, normalized) { putJsonArray("ids") { normalized.forEach { add(it) } } }
    return context.api.request(Method.DELETE, "/secrets", body = body, token = context.api.tokens.require())
        .decode(SecretDeleteResult.serializer())
}

suspend fun listDeletedSecrets(context: ItemContext): List<SecretRecord> {
    val response = context.api.request(Method.GET, "/secrets/deleted", token = context.api.tokens.require())
    return if (response.data == null) emptyList() else response.decode(ListSerializer(SecretRecord.serializer()))
}

suspend fun restoreSecret(context: ItemContext, id: String): SecretRecord =
    context.api.request(Method.POST, "/secrets/${assertCanonicalUuid(id)}/restore", token = context.api.tokens.require())
        .decode(SecretRecord.serializer())

suspend fun purgeSecrets(context: ItemContext, ids: List<String>): SecretPurgeResult {
    val normalized = canonicalSelection(Action.SECRET_PURGE, ids)
    val body = signedBody(context, Action.SECRET_PURGE, normalized) { putJsonArray("ids") { normalized.forEach { add(it) } } }
    return context.api.request(Method.DELETE, "/secrets/deleted", body = body, token = context.api.tokens.require())
        .decode(SecretPurgeResult.serializer())
}
