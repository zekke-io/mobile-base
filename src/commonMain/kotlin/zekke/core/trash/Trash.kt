package zekke.core.trash

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import zekke.core.api.Method
import zekke.core.api.assertCanonicalUuid
import zekke.core.files.FileManifest
import zekke.core.files.FileRecord
import zekke.core.files.fileDeks
import zekke.core.files.openManifest
import zekke.core.folders.TreeFolderRecord
import zekke.core.folders.TreeScope
import zekke.core.folders.openTreeFolderName
import zekke.core.items.ItemContext
import zekke.core.items.signedBody
import zekke.core.memory.SecretZeroedException
import zekke.core.scopes.Scope
import zekke.core.session.SessionLockedException
import zekke.core.signing.Action

@Serializable
class FileTrash(val folders: List<TreeFolderRecord> = emptyList(), val files: List<FileRecord> = emptyList())

@Serializable
class TrashChange(val requested: Int, val folders: Int, val items: Int)

@Serializable
class TrashKey(val id: String, @SerialName("wrapped_dek") val wrappedDek: String, @SerialName("key_generation") val keyGeneration: Int)

@Serializable
class TrashKeys(val folders: List<TrashKey> = emptyList(), val items: List<TrashKey> = emptyList())

enum class TrashKind { FOLDER, FILE }

class TrashEntry(
    val scope: TreeScope,
    val kind: TrashKind,
    val id: String,
    val companions: List<String>,
    val name: String?,
    val deletedAt: String,
    val itemCount: Int? = null,
    val sizeBytes: Long? = null,
    val mime: String? = null,
)

private fun purgeAction(scope: TreeScope): Action = when (scope) {
    TreeScope.DOCUMENTS -> Action.DOCUMENT_PURGE
    TreeScope.FILES -> Action.FILE_PURGE
}

private fun canonical(ids: List<String>): List<String> = ids.map { assertCanonicalUuid(it) }.toSet().sorted()

suspend fun getFileTrash(context: ItemContext): FileTrash {
    val response = context.api.request(Method.GET, "/files/trash", token = context.api.tokens.require())
    return if (response.data == null) FileTrash() else response.decode(FileTrash.serializer())
}

suspend fun getTrashKeys(context: ItemContext, scope: TreeScope): TrashKeys {
    val response = context.api.request(Method.GET, "/${scope.wire}/trash/keys", token = context.api.tokens.require())
    return if (response.data == null) TrashKeys() else response.decode(TrashKeys.serializer())
}

suspend fun restoreFromTrash(context: ItemContext, scope: TreeScope, ids: List<String>): TrashChange {
    val body = buildJsonObject { putJsonArray("ids") { canonical(ids).forEach { add(it) } } }
    return context.api.request(Method.POST, "/${scope.wire}/trash/restore", body = body, token = context.api.tokens.require())
        .decode(TrashChange.serializer())
}

suspend fun purgeFromTrash(context: ItemContext, scope: TreeScope, ids: List<String>): TrashChange {
    val sorted = canonical(ids)
    val body = signedBody(context, purgeAction(scope), sorted) { putJsonArray("ids") { sorted.forEach { add(it) } } }
    return context.api.request(Method.DELETE, "/${scope.wire}/trash", body = body, token = context.api.tokens.require())
        .decode(TrashChange.serializer())
}

private fun openTrashedManifest(context: ItemContext, record: FileRecord): FileManifest? = try {
    if (!context.session.hasKek(Scope.FILES, record.keyGeneration)) {
        null
    } else {
        fileDeks(context).unwrapHeld(record.wrappedDek, record.keyGeneration).use { openManifest(record.ciphertext, it, context.primitives) }
    }
} catch (error: SecretZeroedException) {
    throw error
} catch (error: SessionLockedException) {
    throw error
} catch (_: IllegalStateException) {
    null
} catch (_: IllegalArgumentException) {
    null
}

fun fileTrashEntries(context: ItemContext, trash: FileTrash): List<TrashEntry> {
    val folders = trash.folders.map { record ->
        TrashEntry(
            scope = TreeScope.FILES,
            kind = TrashKind.FOLDER,
            id = record.id,
            companions = emptyList(),
            name = openTreeFolderName(context, TreeScope.FILES, record.ciphertext, record.wrappedDek, record.keyGeneration),
            deletedAt = record.deletedAt ?: "",
            itemCount = record.itemCount,
        )
    }
    val opened = trash.files.map { it to openTrashedManifest(context, it) }
    val trashedIds = trash.files.map { it.id }.toSet()
    val thumbnails = opened.mapNotNull { (_, manifest) -> manifest?.thumbnailId?.takeIf { it in trashedIds } }.toSet()
    val files = opened.filter { (record, _) -> record.id !in thumbnails }.map { (record, manifest) ->
        TrashEntry(
            scope = TreeScope.FILES,
            kind = TrashKind.FILE,
            id = record.id,
            companions = listOfNotNull(manifest?.thumbnailId?.takeIf { it in thumbnails }),
            name = manifest?.name,
            deletedAt = record.deletedAt ?: "",
            sizeBytes = manifest?.size,
            mime = manifest?.mime,
        )
    }
    return (folders + files).sortedWith(compareByDescending<TrashEntry> { it.deletedAt }.thenBy { it.kind }.thenBy { it.id })
}

suspend fun listFileTrash(context: ItemContext): List<TrashEntry> {
    val trash = getFileTrash(context)
    fileDeks(context).refreshForGenerations((trash.files.map { it.keyGeneration } + trash.folders.map { it.keyGeneration }).toSet())
    return fileTrashEntries(context, trash)
}

private fun idsByScope(entries: List<TrashEntry>): Map<TreeScope, List<String>> =
    entries.groupBy { it.scope }.mapValues { (_, list) -> list.flatMap { listOf(it.id) + it.companions } }

suspend fun restoreEntries(context: ItemContext, entries: List<TrashEntry>): Int =
    idsByScope(entries).entries.sumOf { (scope, ids) -> restoreFromTrash(context, scope, ids).let { it.items + it.folders } }

suspend fun purgeEntries(context: ItemContext, entries: List<TrashEntry>): Int =
    idsByScope(entries).entries.sumOf { (scope, ids) -> purgeFromTrash(context, scope, ids).let { it.items + it.folders } }
