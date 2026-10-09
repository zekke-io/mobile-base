package zekke.core.credentials

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.add
import zekke.core.api.wireJson
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Replica
import zekke.core.feed.ReplicaItem
import zekke.core.items.ItemContext

enum class SiteMatch(val wire: String) { DOMAIN("domain"), HOST("host") }

class CredentialPayload(
    val site: String,
    val username: String,
    val password: String,
    val note: String? = null,
    val urls: List<String> = emptyList(),
    val match: SiteMatch? = null,
    val extra: JsonObject = JsonObject(emptyMap()),
)

class MalformedCredentialPayloadException : IllegalArgumentException("this credential was not written as a site, a username and a password")

private val KNOWN_FIELDS = setOf("site", "username", "password", "note", "urls", "match")

fun encodeCredentialPayload(payload: CredentialPayload): String {
    val others = payload.urls.map { it.trim() }.filter { it.isNotEmpty() }
    val encoded = buildJsonObject {
        for ((key, value) in payload.extra) if (key !in KNOWN_FIELDS) put(key, value)
        put("site", payload.site)
        put("username", payload.username)
        put("password", payload.password)
        if (!payload.note.isNullOrEmpty()) put("note", payload.note)
        if (others.isNotEmpty()) putJsonArray("urls") { others.forEach { add(it) } }
        if (payload.match == SiteMatch.HOST) put("match", SiteMatch.HOST.wire)
    }
    return wireJson.encodeToString(JsonObject.serializer(), encoded)
}

private fun JsonElement?.stringOrNull(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.content

fun decodeCredentialPayload(plaintext: String): CredentialPayload {
    val parsed = try {
        wireJson.parseToJsonElement(plaintext) as? JsonObject
    } catch (_: SerializationException) {
        null
    } ?: throw MalformedCredentialPayloadException()
    val site = parsed["site"].stringOrNull()
    val username = parsed["username"].stringOrNull()
    val password = parsed["password"].stringOrNull()
    if (site == null || username == null || password == null) throw MalformedCredentialPayloadException()
    val note = parsed["note"]?.let { it.stringOrNull() ?: throw MalformedCredentialPayloadException() }
    val urls = parsed["urls"]?.let { element ->
        val array = element as? JsonArray ?: throw MalformedCredentialPayloadException()
        array.map { it.stringOrNull() ?: throw MalformedCredentialPayloadException() }
    } ?: emptyList()
    val match = parsed["match"]?.let { element ->
        val wire = element.stringOrNull()
        SiteMatch.entries.firstOrNull { it.wire == wire } ?: throw MalformedCredentialPayloadException()
    }
    val extra = JsonObject(parsed.filterKeys { it !in KNOWN_FIELDS })
    return CredentialPayload(site, username, password, note, urls, match, extra)
}

class PasswordRow(
    val id: String,
    val revisionId: String,
    val seq: Long,
    val site: String,
    val username: String,
    val password: String,
    val note: String,
    val changedAt: String,
    val readable: Boolean,
    val payload: CredentialPayload?,
)

class DeletedPasswordRow(val id: String, val site: String, val username: String, val readable: Boolean, val deletedAt: String, val deleted: DeletedCredential)

class PasswordsView(val rows: List<PasswordRow>, val deleted: List<DeletedPasswordRow>)

class OpenedCredential(val record: CredentialRevision, val plaintext: String?)

fun buildPasswordRows(opened: List<OpenedCredential>): List<PasswordRow> =
    opened.map(::toPasswordRow).sortedWith(compareBy<PasswordRow> { it.site.lowercase() }.thenBy { it.username.lowercase() })

private fun toPasswordRow(entry: OpenedCredential): PasswordRow {
    val payload = entry.plaintext?.let {
        try {
            decodeCredentialPayload(it)
        } catch (_: MalformedCredentialPayloadException) {
            null
        }
    }
    return PasswordRow(
        id = entry.record.credentialId,
        revisionId = entry.record.revisionId,
        seq = entry.record.seq,
        site = payload?.site ?: "",
        username = payload?.username ?: "",
        password = payload?.password ?: "",
        note = payload?.note ?: "",
        changedAt = entry.record.createdAt,
        readable = payload != null,
        payload = payload,
    )
}

fun currentRevisions(revisions: List<CredentialRevision>): List<CredentialRevision> =
    revisions.groupBy { it.credentialId }.values.map { list -> list.maxBy { it.seq } }.filter { !it.deleted }

fun credentialHistory(revisions: List<CredentialRevision>, credentialId: String): List<CredentialRevision> =
    revisions.filter { it.credentialId == credentialId && !it.deleted }.sortedByDescending { it.seq }

fun siteLabel(site: String): String {
    val trimmed = site.trim()
    if (trimmed.isEmpty()) return trimmed
    val afterScheme = trimmed.substringAfter("://", trimmed)
    val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }
    val host = authority.substringAfterLast('@').let { if (it.startsWith("[")) it.substringBefore(']') + "]" else it.substringBefore(':') }
    if (host.isEmpty() || host.any { it.isWhitespace() }) return trimmed
    return host.lowercase().removePrefix("www.")
}

fun credentialRevisions(items: List<ReplicaItem>): List<CredentialRevision> =
    items.map { wireJson.decodeFromJsonElement(CredentialRevision.serializer(), it.item) }

suspend fun openCredentialRevisions(context: ItemContext, revisions: List<CredentialRevision>): List<OpenedCredential> {
    val deks = credentialDeks(context)
    deks.refreshForGenerations(revisions.map { it.keyGeneration }.toSet())
    return revisions.map { OpenedCredential(it, deks.openHeldTextOrNull(it.ciphertext, it.wrappedDek, it.keyGeneration)) }
}

suspend fun passwordsView(context: ItemContext, items: List<ReplicaItem>): PasswordsView {
    val revisions = credentialRevisions(items)
    val rows = buildPasswordRows(openCredentialRevisions(context, currentRevisions(revisions)))
    val deleted = deletedCredentials(revisions)
    val openedLastLive = openCredentialRevisions(context, deleted.map { it.lastLive }).associateBy { it.record.revisionId }
    val deletedRows = deleted.map { entry ->
        val row = toPasswordRow(openedLastLive.getValue(entry.lastLive.revisionId))
        DeletedPasswordRow(entry.credentialId, row.site, row.username, row.readable, entry.deletedAt, entry)
    }
    return PasswordsView(rows, deletedRows)
}

suspend fun passwordsView(context: ItemContext, replica: Replica): PasswordsView =
    passwordsView(context, replica.items(FeedScope.PASSWORDS, ItemTypes.CREDENTIAL))
