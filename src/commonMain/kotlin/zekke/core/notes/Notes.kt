package zekke.core.notes

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
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
import zekke.core.api.collectPages
import zekke.core.feed.FeedScope
import zekke.core.feed.Outbox
import zekke.core.items.ItemContext
import zekke.core.items.ItemTooLargeException
import zekke.core.items.ScopeDeks
import zekke.core.items.WrappedDek
import zekke.core.items.canonicalSelection
import zekke.core.items.codePointCount
import zekke.core.items.generateDek
import zekke.core.items.itemIdOrNew
import zekke.core.items.signedBody
import zekke.core.keyrings.withCurrentGeneration
import zekke.core.memory.SecretBytes
import zekke.core.scopes.Scope
import zekke.core.sealed.sealText
import zekke.core.signing.Action

const val NOTE_VERSION = "v1"
const val MAX_NOTE_CHARACTERS = 5000
const val MAX_NOTE_CIPHERTEXT_CHARACTERS = 32768
const val NOTE_FETCH_CONCURRENCY = 6

@Serializable
class NoteRecord(
    val id: String,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val version: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("updated_at") val updatedAt: String,
)

@Serializable
class NoteMetaRecord(
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
class NoteDeleteResult(val requested: Int, val deleted: Int)

class CreateNoteResult(val note: NoteRecord, val created: Boolean)

fun noteDeks(context: ItemContext): ScopeDeks = ScopeDeks(context, Scope.NOTES)

fun noteCharacterCount(text: String): Int = codePointCount(toPlainText(text))

private fun requireWithinCharacterLimit(text: String) {
    val characters = noteCharacterCount(text)
    if (characters > MAX_NOTE_CHARACTERS) throw ItemTooLargeException(characters, MAX_NOTE_CHARACTERS, "characters")
}

private fun requireWithinCiphertextCeiling(ciphertext: String): String {
    if (ciphertext.length > MAX_NOTE_CIPHERTEXT_CHARACTERS) {
        throw ItemTooLargeException(ciphertext.length, MAX_NOTE_CIPHERTEXT_CHARACTERS, "ciphertext characters")
    }
    return ciphertext
}

private fun noteBody(id: String?, ciphertext: String, wrapped: WrappedDek, version: String): JsonObject = buildJsonObject {
    if (id != null) put("id", id)
    put("ciphertext", ciphertext)
    put("wrapped_dek", wrapped.wrappedDek)
    put("key_generation", wrapped.keyGeneration)
    put("version", version)
}

private fun sealNoteText(context: ItemContext, plaintext: String, dek: SecretBytes): String {
    requireWithinCharacterLimit(plaintext)
    return requireWithinCiphertextCeiling(sealText(plaintext, dek, context.primitives))
}

suspend fun createNote(context: ItemContext, plaintext: String, id: String? = null): CreateNoteResult {
    requireWithinCharacterLimit(plaintext)
    val itemId = itemIdOrNew(id, context.primitives)
    return generateDek(context.primitives).use { dek ->
        val ciphertext = sealNoteText(context, plaintext, dek)
        val response = withCurrentGeneration(context.api, context.session) {
            val body = noteBody(itemId, ciphertext, noteDeks(context).wrap(dek), NOTE_VERSION)
            context.api.request(Method.POST, "/notes", body = body, token = context.api.tokens.require())
        }
        CreateNoteResult(response.decode(NoteRecord.serializer()), response.status == 201)
    }
}

private fun editWrap(context: ItemContext, note: NoteRecord, dek: SecretBytes): WrappedDek {
    val current = context.session.currentGeneration(Scope.NOTES)
    return if (note.keyGeneration == current) WrappedDek(note.wrappedDek, note.keyGeneration) else noteDeks(context).wrap(dek)
}

suspend fun updateNote(context: ItemContext, note: NoteRecord, plaintext: String): NoteRecord {
    requireWithinCharacterLimit(plaintext)
    val id = assertCanonicalUuid(note.id)
    return noteDeks(context).unwrap(note.wrappedDek, note.keyGeneration).use { dek ->
        val ciphertext = sealNoteText(context, plaintext, dek)
        val response = withCurrentGeneration(context.api, context.session) {
            val body = noteBody(null, ciphertext, editWrap(context, note, dek), note.version.ifEmpty { NOTE_VERSION })
            context.api.request(Method.PUT, "/notes/$id", body = body, token = context.api.tokens.require())
        }
        response.decode(NoteRecord.serializer())
    }
}

suspend fun saveNote(context: ItemContext, plaintext: String, id: String, record: NoteRecord? = null): NoteRecord {
    if (record != null) return updateNote(context, record, plaintext)
    val result = createNote(context, plaintext, id)
    return if (result.created) result.note else updateNote(context, result.note, plaintext)
}

class QueuedNote(val id: String, val wrappedDek: String, val keyGeneration: Int)

fun queueNewNote(context: ItemContext, outbox: Outbox, plaintext: String, id: String? = null): QueuedNote {
    val itemId = itemIdOrNew(id, context.primitives)
    return generateDek(context.primitives).use { dek ->
        val ciphertext = sealNoteText(context, plaintext, dek)
        val wrapped = noteDeks(context).wrap(dek)
        outbox.enqueue(itemId, FeedScope.NOTES, Method.POST, "/notes", noteBody(itemId, ciphertext, wrapped, NOTE_VERSION), wrapped.keyGeneration)
        QueuedNote(itemId, wrapped.wrappedDek, wrapped.keyGeneration)
    }
}

suspend fun queueNoteEdit(context: ItemContext, outbox: Outbox, id: String, wrappedDek: String, keyGeneration: Int, version: String, plaintext: String) {
    val canonical = assertCanonicalUuid(id)
    noteDeks(context).unwrap(wrappedDek, keyGeneration).use { dek ->
        val ciphertext = sealNoteText(context, plaintext, dek)
        val current = context.session.currentGeneration(Scope.NOTES)
        val wrapped = if (keyGeneration == current) WrappedDek(wrappedDek, keyGeneration) else noteDeks(context).wrap(dek)
        outbox.enqueue(canonical, FeedScope.NOTES, Method.PUT, "/notes/$canonical", noteBody(null, ciphertext, wrapped, version.ifEmpty { NOTE_VERSION }), wrapped.keyGeneration)
    }
}

suspend fun listNotesMeta(context: ItemContext, limit: Int? = null): List<NoteMetaRecord> = collectPages { cursor ->
    val response = context.api.request(
        Method.GET,
        "/notes",
        token = context.api.tokens.require(),
        query = mapOf("limit" to limit?.toString(), "cursor" to cursor),
    )
    val page = if (response.data == null) emptyList() else response.decode(ListSerializer(NoteMetaRecord.serializer()))
    page to response.page
}

suspend fun getNote(context: ItemContext, id: String): NoteRecord =
    context.api.request(Method.GET, "/notes/${assertCanonicalUuid(id)}", token = context.api.tokens.require())
        .decode(NoteRecord.serializer())

suspend fun listNotes(context: ItemContext, limit: Int? = null): List<NoteRecord> {
    val meta = listNotesMeta(context, limit)
    val permits = Semaphore(NOTE_FETCH_CONCURRENCY)
    return coroutineScope {
        meta.map { entry -> async { permits.withPermit { getNote(context, entry.id) } } }.map { it.await() }
    }
}

suspend fun openNote(context: ItemContext, note: NoteRecord): String =
    noteDeks(context).openText(note.ciphertext, note.wrappedDek, note.keyGeneration)

suspend fun deleteNote(context: ItemContext, id: String) {
    val canonical = assertCanonicalUuid(id)
    val body = signedBody(context, Action.NOTE_DELETE, listOf(canonical))
    context.api.request(Method.DELETE, "/notes/$canonical", body = body, token = context.api.tokens.require())
}

suspend fun deleteNotes(context: ItemContext, ids: List<String>): NoteDeleteResult {
    val normalized = canonicalSelection(Action.NOTE_DELETE, ids)
    val body = signedBody(context, Action.NOTE_DELETE, normalized) { putJsonArray("ids") { normalized.forEach { add(it) } } }
    return context.api.request(Method.DELETE, "/notes", body = body, token = context.api.tokens.require())
        .decode(NoteDeleteResult.serializer())
}
