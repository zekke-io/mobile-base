package zekke.core.credentials

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
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

const val MAX_CREDENTIAL_PLAINTEXT_BYTES = 24 * 1024
const val CREDENTIAL_VERSION = "v1"
const val CREDENTIAL_SYNC_PAGE_SIZE = 200
const val PURGE_KEEP_LAST = 1

@Serializable
class CredentialRevision(
    @SerialName("credential_id") val credentialId: String,
    @SerialName("revision_id") val revisionId: String,
    val seq: Long,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val version: String,
    @SerialName("created_at") val createdAt: String,
    val deleted: Boolean = false,
)

@Serializable
class CredentialMeta(
    @SerialName("credential_id") val credentialId: String,
    @SerialName("revision_id") val revisionId: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    @SerialName("created_at") val createdAt: String,
)

@Serializable
class CredentialSyncPage(
    val revisions: List<CredentialRevision> = emptyList(),
    val cursor: Long = 0,
    @SerialName("has_more") val hasMore: Boolean = false,
)

@Serializable
class CredentialDeleteResult(val requested: Int, val tombstoned: Int)

@Serializable
class CredentialPruneResult(val pruned: Int)

class WriteCredentialResult(val revision: CredentialRevision, val created: Boolean)

class DeletedCredential(val credentialId: String, val deletedAt: String, val lastLive: CredentialRevision)

class SealedCredential(val credentialId: String, val revisionId: String, val ciphertext: String, val wrapped: WrappedDek) {
    val body: JsonObject
        get() = buildJsonObject {
            put("credential_id", credentialId)
            put("revision_id", revisionId)
            put("ciphertext", ciphertext)
            put("wrapped_dek", wrapped.wrappedDek)
            put("key_generation", wrapped.keyGeneration)
            put("version", CREDENTIAL_VERSION)
        }
}

fun credentialDeks(context: ItemContext): ScopeDeks = ScopeDeks(context, Scope.PASSWORDS)

private fun requireWithinBudget(plaintext: String) {
    val bytes = utf8Length(plaintext)
    if (bytes > MAX_CREDENTIAL_PLAINTEXT_BYTES) throw ItemTooLargeException(bytes, MAX_CREDENTIAL_PLAINTEXT_BYTES)
}

fun sealCredential(context: ItemContext, plaintext: String, credentialId: String? = null, revisionId: String? = null): SealedCredential {
    requireWithinBudget(plaintext)
    val credential = itemIdOrNew(credentialId, context.primitives)
    val revision = itemIdOrNew(revisionId, context.primitives)
    return generateDek(context.primitives).use { dek ->
        SealedCredential(credential, revision, sealText(plaintext, dek, context.primitives), credentialDeks(context).wrap(dek))
    }
}

suspend fun writeCredential(
    context: ItemContext,
    plaintext: String,
    credentialId: String? = null,
    revisionId: String? = null,
): WriteCredentialResult {
    requireWithinBudget(plaintext)
    val credential = itemIdOrNew(credentialId, context.primitives)
    val revision = itemIdOrNew(revisionId, context.primitives)
    return generateDek(context.primitives).use { dek ->
        val ciphertext = sealText(plaintext, dek, context.primitives)
        val response = withCurrentGeneration(context.api, context.session) {
            val sealed = SealedCredential(credential, revision, ciphertext, credentialDeks(context).wrap(dek))
            context.api.request(Method.POST, "/credentials", body = sealed.body, token = context.api.tokens.require())
        }
        WriteCredentialResult(response.decode(CredentialRevision.serializer()), response.status == 201)
    }
}

fun queueCredential(context: ItemContext, outbox: Outbox, plaintext: String, credentialId: String? = null): SealedCredential {
    val sealed = sealCredential(context, plaintext, credentialId)
    outbox.enqueue(sealed.revisionId, FeedScope.PASSWORDS, Method.POST, "/credentials", sealed.body, sealed.wrapped.keyGeneration)
    return sealed
}

suspend fun listCredentials(context: ItemContext): List<CredentialRevision> {
    val response = context.api.request(Method.GET, "/credentials", token = context.api.tokens.require())
    return if (response.data == null) emptyList() else response.decode(ListSerializer(CredentialRevision.serializer()))
}

suspend fun listCredentialsMeta(context: ItemContext): List<CredentialMeta> {
    val response = context.api.request(Method.GET, "/credentials", token = context.api.tokens.require(), query = mapOf("fields" to "meta"))
    return if (response.data == null) emptyList() else response.decode(ListSerializer(CredentialMeta.serializer()))
}

suspend fun getCredential(context: ItemContext, credentialId: String): CredentialRevision =
    context.api.request(Method.GET, "/credentials/${assertCanonicalUuid(credentialId)}", token = context.api.tokens.require())
        .decode(CredentialRevision.serializer())

suspend fun syncCredentials(context: ItemContext, cursor: Long = 0, limit: Int = CREDENTIAL_SYNC_PAGE_SIZE): CredentialSyncPage =
    context.api.request(
        Method.GET,
        "/credentials/sync",
        token = context.api.tokens.require(),
        query = mapOf("cursor" to cursor.toString(), "limit" to limit.toString()),
    ).decode(CredentialSyncPage.serializer())

suspend fun syncAllRevisions(context: ItemContext): List<CredentialRevision> {
    val revisions = mutableListOf<CredentialRevision>()
    var cursor = 0L
    while (true) {
        val page = syncCredentials(context, cursor)
        revisions += page.revisions
        if (!page.hasMore || page.cursor <= cursor) return revisions
        cursor = page.cursor
    }
}

suspend fun listRevisions(context: ItemContext, credentialId: String): List<CredentialRevision> {
    val response = context.api.request(
        Method.GET,
        "/credentials/${assertCanonicalUuid(credentialId)}/revisions",
        token = context.api.tokens.require(),
    )
    return if (response.data == null) emptyList() else response.decode(ListSerializer(CredentialRevision.serializer()))
}

fun deletedCredentials(revisions: List<CredentialRevision>): List<DeletedCredential> =
    revisions.groupBy { it.credentialId }.mapNotNull { (credentialId, list) ->
        val ordered = list.sortedByDescending { it.seq }
        val latest = ordered.first()
        val lastLive = ordered.firstOrNull { !it.deleted }
        if (latest.deleted && lastLive != null) DeletedCredential(credentialId, latest.createdAt, lastLive) else null
    }.sortedByDescending { it.deletedAt }

suspend fun openCredential(context: ItemContext, revision: CredentialRevision): String =
    credentialDeks(context).openText(revision.ciphertext, revision.wrappedDek, revision.keyGeneration)

suspend fun restoreCredential(context: ItemContext, deleted: DeletedCredential): WriteCredentialResult =
    writeCredential(context, openCredential(context, deleted.lastLive), credentialId = deleted.credentialId)

suspend fun deleteCredential(context: ItemContext, credentialId: String) {
    val canonical = assertCanonicalUuid(credentialId)
    val body = signedBody(context, Action.CREDENTIAL_DELETE, listOf(canonical))
    context.api.request(Method.DELETE, "/credentials/$canonical", body = body, token = context.api.tokens.require())
}

suspend fun deleteCredentials(context: ItemContext, credentialIds: List<String>): CredentialDeleteResult {
    val normalized = canonicalSelection(Action.CREDENTIAL_DELETE, credentialIds)
    val body = signedBody(context, Action.CREDENTIAL_DELETE, normalized) { putJsonArray("ids") { normalized.forEach { add(it) } } }
    return context.api.request(Method.DELETE, "/credentials", body = body, token = context.api.tokens.require())
        .decode(CredentialDeleteResult.serializer())
}

suspend fun pruneCredential(context: ItemContext, credentialId: String, keepLast: Int): CredentialPruneResult {
    val canonical = assertCanonicalUuid(credentialId)
    val body = signedBody(context, Action.CREDENTIAL_PRUNE, listOf(canonical, keepLast.toString())) { put("keep_last", keepLast) }
    return context.api.request(Method.POST, "/credentials/$canonical/prune", body = body, token = context.api.tokens.require())
        .decode(CredentialPruneResult.serializer())
}

suspend fun purgeDeletedCredential(context: ItemContext, deleted: DeletedCredential): CredentialPruneResult =
    pruneCredential(context, deleted.credentialId, PURGE_KEEP_LAST)
