package zekke.core.folders

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.assertCanonicalUuid
import zekke.core.api.wireJson
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.ReplicaItem
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.generateDek
import zekke.core.items.itemIdOrNew
import zekke.core.items.signedBody
import zekke.core.scopes.Scope
import zekke.core.sealed.sealText
import zekke.core.signing.Action

const val MAX_TREE_DEPTH = 8
val TREE_RULES = FolderRules(maxDepth = MAX_TREE_DEPTH, home = false)

enum class TreeScope(val wire: String, val scope: Scope, val feedScope: FeedScope, val folderItemType: String) {
    DOCUMENTS("documents", Scope.DOCUMENTS, FeedScope.DOCUMENTS, ItemTypes.DOCUMENT_FOLDER),
    FILES("files", Scope.FILES, FeedScope.FILES, ItemTypes.FILE_FOLDER),
}

@Serializable
class TreeFolderRecord(
    val id: String,
    @SerialName("parent_id") val parentId: String? = null,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val position: Double = 0.0,
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("updated_at") val updatedAt: String = "",
    @SerialName("deleted_at") val deletedAt: String? = null,
    @SerialName("item_count") val itemCount: Int? = null,
)

class TreeFolder(
    val id: String,
    val parentId: String?,
    val name: String?,
    val position: Double,
    val createdAt: String,
    val updatedAt: String,
)

@Serializable
class FolderDeletion(val folders: Int, val items: Int)

@Serializable
class ItemsMoved(val requested: Int, val moved: Int)

enum class FolderTreeProblem { FOLDER_TOO_DEEP, FOLDER_INTO_ITSELF }

class FolderTreeProblemException(val problem: FolderTreeProblem) : IllegalArgumentException(
    if (problem == FolderTreeProblem.FOLDER_TOO_DEEP) "the folder tree would be too deep" else "a folder cannot go inside itself",
)

private suspend fun <T> translated(block: suspend () -> T): T = try {
    block()
} catch (error: ApiError) {
    throw when (error.code) {
        "FOLDER_TOO_DEEP" -> FolderTreeProblemException(FolderTreeProblem.FOLDER_TOO_DEEP)
        "FOLDER_INTO_ITSELF" -> FolderTreeProblemException(FolderTreeProblem.FOLDER_INTO_ITSELF)
        else -> error
    }
}

private fun sealName(context: ItemContext, scope: TreeScope, name: String): JsonObject {
    val trimmed = name.trim()
    if (trimmed.isEmpty() || trimmed.length > MAX_FOLDER_NAME_LENGTH) throw FolderEditException(FolderEditProblem.BAD_NAME)
    return generateDek(context.primitives).use { dek ->
        val wrapped = ScopeDeks(context, scope.scope).wrap(dek)
        buildJsonObject {
            put("ciphertext", sealText(trimmed, dek, context.primitives))
            put("wrapped_dek", wrapped.wrappedDek)
            put("key_generation", wrapped.keyGeneration)
        }
    }
}

fun openTreeFolderName(context: ItemContext, scope: TreeScope, ciphertext: String, wrappedDek: String, keyGeneration: Int): String? =
    ScopeDeks(context, scope.scope).openHeldTextOrNull(ciphertext, wrappedDek, keyGeneration)

fun treeManifest(folders: List<TreeFolder>): FolderManifest = FolderManifest(
    folders.associateTo(LinkedHashMap()) { it.id to FolderEntry(it.name ?: it.id, it.parentId, it.position, it.updatedAt) },
    emptyMap(),
)

suspend fun listTreeFolderRecords(context: ItemContext, scope: TreeScope): List<TreeFolderRecord> {
    val response = context.api.request(Method.GET, "/${scope.wire}/folders", token = context.api.tokens.require())
    return if (response.data == null) emptyList() else response.decode(ListSerializer(TreeFolderRecord.serializer()))
}

suspend fun openTreeFolders(context: ItemContext, scope: TreeScope, records: List<TreeFolderRecord>): List<TreeFolder> {
    ScopeDeks(context, scope.scope).refreshForGenerations(records.map { it.keyGeneration }.toSet())
    val folders = records.map {
        TreeFolder(it.id, it.parentId, openTreeFolderName(context, scope, it.ciphertext, it.wrappedDek, it.keyGeneration), it.position, it.createdAt, it.updatedAt)
    }
    validateFolderManifest(treeManifest(folders), TREE_RULES)
    return folders
}

suspend fun listTreeFolders(context: ItemContext, scope: TreeScope): List<TreeFolder> =
    openTreeFolders(context, scope, listTreeFolderRecords(context, scope))

suspend fun treeFoldersFromReplica(context: ItemContext, scope: TreeScope, items: List<ReplicaItem>): List<TreeFolder> =
    openTreeFolders(
        context,
        scope,
        items.map { wireJson.decodeFromJsonElement(TreeFolderRecord.serializer(), it.item) }.filter { it.deletedAt == null },
    )

suspend fun createTreeFolder(context: ItemContext, scope: TreeScope, name: String, parentId: String?, id: String? = null): TreeFolderRecord {
    val folderId = itemIdOrNew(id, context.primitives)
    val sealed = sealName(context, scope, name)
    val body = JsonObject(
        buildJsonObject {
            put("id", folderId)
            if (parentId != null) put("parent_id", assertCanonicalUuid(parentId))
        } + sealed,
    )
    return translated {
        context.api.request(Method.POST, "/${scope.wire}/folders", body = body, token = context.api.tokens.require())
            .decode(TreeFolderRecord.serializer())
    }
}

private suspend fun patchTreeFolder(context: ItemContext, scope: TreeScope, id: String, body: JsonObject): TreeFolderRecord = translated {
    context.api.request(Method.PATCH, "/${scope.wire}/folders/${assertCanonicalUuid(id)}", body = body, token = context.api.tokens.require())
        .decode(TreeFolderRecord.serializer())
}

suspend fun renameTreeFolder(context: ItemContext, scope: TreeScope, id: String, name: String): TreeFolderRecord =
    patchTreeFolder(context, scope, id, sealName(context, scope, name))

suspend fun moveTreeFolder(context: ItemContext, scope: TreeScope, id: String, parentId: String?): TreeFolderRecord =
    patchTreeFolder(
        context,
        scope,
        id,
        buildJsonObject { putJsonObject("parent") { if (parentId != null) put("id", assertCanonicalUuid(parentId)) } },
    )

suspend fun deleteTreeFolder(context: ItemContext, scope: TreeScope, id: String): FolderDeletion {
    val folderId = assertCanonicalUuid(id)
    val body = signedBody(context, Action.FOLDER_DELETE, listOf(scope.wire, folderId))
    return context.api.request(Method.DELETE, "/${scope.wire}/folders/$folderId", body = body, token = context.api.tokens.require())
        .decode(FolderDeletion.serializer())
}

suspend fun moveItemsToFolder(context: ItemContext, scope: TreeScope, itemIds: List<String>, folderId: String?): ItemsMoved {
    val body = buildJsonObject {
        putJsonArray("ids") { itemIds.forEach { add(assertCanonicalUuid(it)) } }
        if (folderId != null) put("folder_id", assertCanonicalUuid(folderId))
    }
    return translated {
        context.api.request(Method.PUT, "/${scope.wire}/folders/items", body = body, token = context.api.tokens.require())
            .decode(ItemsMoved.serializer())
    }
}

fun childrenOf(folders: List<TreeFolder>, parentId: String?): List<TreeFolder> =
    folders.filter { it.parentId == parentId }
        .sortedWith(compareBy<TreeFolder> { it.position }.thenBy { it.name ?: "" }.thenBy { it.id })

fun pathTo(folders: List<TreeFolder>, id: String?): List<TreeFolder> {
    val byId = folders.associateBy { it.id }
    val path = ArrayDeque<TreeFolder>()
    var current = id?.let { byId[it] }
    while (current != null && path.size <= MAX_TREE_DEPTH) {
        path.addFirst(current)
        current = current.parentId?.let { byId[it] }
    }
    return path.toList()
}

fun descendantsOf(folders: List<TreeFolder>, id: String): Set<String> {
    val found = linkedSetOf(id)
    var grew = true
    while (grew) {
        grew = false
        for (folder in folders) {
            if (folder.parentId != null && folder.parentId in found && found.add(folder.id)) grew = true
        }
    }
    return found
}

fun canMoveFolder(folders: List<TreeFolder>, id: String, target: String?): Boolean {
    val folder = folders.firstOrNull { it.id == id } ?: return false
    if (folder.parentId == target) return false
    if (target == null) return true
    val moving = descendantsOf(folders, id)
    if (target in moving) return false
    val base = pathTo(folders, id).size
    val height = moving.maxOf { pathTo(folders, it).size - base + 1 }
    return pathTo(folders, target).size + height <= MAX_TREE_DEPTH
}

fun canCreateIn(folders: List<TreeFolder>, parentId: String?): Boolean = pathTo(folders, parentId).size < MAX_TREE_DEPTH
