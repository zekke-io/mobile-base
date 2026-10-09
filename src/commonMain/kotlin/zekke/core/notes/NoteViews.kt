package zekke.core.notes

import zekke.core.api.wireJson
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Replica
import zekke.core.feed.ReplicaItem
import zekke.core.items.ItemContext
import zekke.core.items.codePointCount
import zekke.core.items.takeCodePoints
import zekke.core.items.utf8Length

const val NOTE_TITLE_MAX_CHARACTERS = 60
const val NOTE_THUMBNAIL_MAX_CHARACTERS = 420
const val NOTE_AUTOSAVE_DELAY_MILLIS = 2000L

private const val ELLIPSIS = "…"
private val BLANK_RUNS = Regex("\n{3,}")

private fun truncate(text: String, limit: Int): String =
    if (codePointCount(text) <= limit) text else takeCodePoints(text, limit).trimEnd() + ELLIPSIS

fun noteTitle(text: String): String? =
    parseBlocks(text).map { blockPlainText(it).trim() }.firstOrNull { it.isNotEmpty() }?.let { truncate(it, NOTE_TITLE_MAX_CHARACTERS) }

fun noteThumbnail(text: String): String =
    truncate(toDisplayText(text).replace(BLANK_RUNS, "\n\n").trim(), NOTE_THUMBNAIL_MAX_CHARACTERS)

fun noteCharactersLeft(text: String): Int = MAX_NOTE_CHARACTERS - noteCharacterCount(text)

fun isNoteWithinLimit(text: String): Boolean = noteCharactersLeft(text) >= 0

fun isNoteEmpty(text: String): Boolean = toPlainText(text).trim().isEmpty()

fun isNoteSavable(text: String, saved: String?): Boolean = !isNoteEmpty(text) && text != saved && isNoteWithinLimit(text)

class NoteTile(
    val id: String,
    val title: String?,
    val thumbnail: String,
    val bytes: Int,
    val version: String,
    val createdAt: String,
    val updatedAt: String,
    val readable: Boolean,
)

class OpenedNote(val record: NoteRecord, val plaintext: String?)

fun buildNoteTiles(opened: List<OpenedNote>): List<NoteTile> = opened.map {
    NoteTile(
        id = it.record.id,
        title = it.plaintext?.let(::noteTitle),
        thumbnail = it.plaintext?.let(::noteThumbnail) ?: "",
        bytes = utf8Length(it.record.ciphertext),
        version = it.record.version,
        createdAt = it.record.createdAt,
        updatedAt = it.record.updatedAt,
        readable = it.plaintext != null,
    )
}.sortedByDescending { it.updatedAt }

fun noteRecords(items: List<ReplicaItem>): List<NoteRecord> =
    items.map { wireJson.decodeFromJsonElement(NoteRecord.serializer(), it.item) }

suspend fun openNoteRecords(context: ItemContext, records: List<NoteRecord>): List<OpenedNote> {
    val deks = noteDeks(context)
    deks.refreshForGenerations(records.map { it.keyGeneration }.toSet())
    return records.map { OpenedNote(it, deks.openHeldTextOrNull(it.ciphertext, it.wrappedDek, it.keyGeneration)) }
}

suspend fun noteTiles(context: ItemContext, items: List<ReplicaItem>): List<NoteTile> =
    buildNoteTiles(openNoteRecords(context, noteRecords(items)))

suspend fun noteTiles(context: ItemContext, replica: Replica): List<NoteTile> =
    noteTiles(context, replica.items(FeedScope.NOTES, ItemTypes.NOTE))
