package zekke.core.folders

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put
import zekke.core.items.newItemId
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

const val FOLDER_MANIFEST_VERSION = 1
const val HOME_FOLDER_ID = "home"
const val HOME_FOLDER_NAME = "home"
const val MAX_FOLDER_NAME_LENGTH = 120

class FolderRules(val maxDepth: Int, val home: Boolean)

data class FolderEntry(
    val name: String,
    val parentId: String?,
    val position: Double,
    val updatedAt: String,
    val deletedAt: String? = null,
) {
    val isLive: Boolean get() = deletedAt == null
}

data class ItemPlacement(val folderId: String?, val updatedAt: String)

class FolderManifest(val folders: Map<String, FolderEntry>, val items: Map<String, ItemPlacement>)

class Folder(val id: String, val entry: FolderEntry) {
    val name: String get() = entry.name
    val parentId: String? get() = entry.parentId
    val position: Double get() = entry.position
}

enum class FolderManifestProblem { UNKNOWN_VERSION, MALFORMED, BAD_NAME, UNKNOWN_PARENT, CYCLE, TOO_DEEP, DELETED_PARENT, MISSING_HOME, UNKNOWN_FOLDER }

class FolderManifestInvalidException(val problem: FolderManifestProblem, val folderId: String? = null) :
    IllegalStateException("the folder manifest failed validation: ${problem.name.lowercase()}${folderId?.let { " ($it)" } ?: ""}")

enum class FolderEditProblem { BAD_NAME, UNKNOWN_FOLDER, FOLDER_EXISTS, HOME_IS_FIXED, INTO_ITSELF, TOO_DEEP }

class FolderEditException(val problem: FolderEditProblem, val folderId: String? = null) :
    IllegalArgumentException("the folder edit was refused: ${problem.name.lowercase()}${folderId?.let { " ($it)" } ?: ""}")

fun interface FolderEdit {
    fun apply(manifest: FolderManifest, rules: FolderRules): FolderManifest
}

private val manifestJson = Json { encodeDefaults = true }

@OptIn(ExperimentalTime::class)
private fun isTimestamp(value: String): Boolean = try {
    Instant.parse(value)
    true
} catch (_: IllegalArgumentException) {
    false
}

fun isoTimestamp(epochMillis: Long): String {
    val days = epochMillis.floorDiv(86_400_000L)
    val millisOfDay = epochMillis.mod(86_400_000L)
    val (year, month, day) = civilFromDays(days)
    val hours = millisOfDay / 3_600_000
    val minutes = millisOfDay / 60_000 % 60
    val seconds = millisOfDay / 1000 % 60
    val millis = millisOfDay % 1000
    fun pad(value: Long, width: Int) = value.toString().padStart(width, '0')
    return "${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}T${pad(hours, 2)}:${pad(minutes, 2)}:${pad(seconds, 2)}.${pad(millis, 3)}Z"
}

private fun civilFromDays(daysSinceEpoch: Long): Triple<Long, Long, Long> {
    val z = daysSinceEpoch + 719_468
    val era = (if (z >= 0) z else z - 146_096) / 146_097
    val dayOfEra = z - era * 146_097
    val yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36_524 - dayOfEra / 146_096) / 365
    val dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)
    val monthPrime = (5 * dayOfYear + 2) / 153
    val day = dayOfYear - (153 * monthPrime + 2) / 5 + 1
    val month = if (monthPrime < 10) monthPrime + 3 else monthPrime - 9
    val year = yearOfEra + era * 400 + if (month <= 2) 1 else 0
    return Triple(year, month, day)
}

@OptIn(ExperimentalTime::class)
fun nowTimestamp(): String = isoTimestamp(kotlin.time.Clock.System.now().toEpochMilliseconds())

private fun isFolderName(value: String): Boolean = value.trim().isNotEmpty() && value.length <= MAX_FOLDER_NAME_LENGTH

private fun JsonElement?.stringOrNull(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun JsonElement?.isFolderReference(): Boolean = this is JsonNull || (stringOrNull()?.isNotEmpty() == true)

private fun readFolder(id: String, value: JsonElement): FolderEntry {
    val record = value as? JsonObject ?: throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED, id)
    val parent = record["parent_id"]
    val position = (record["position"] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull
    val updatedAt = record["updated_at"].stringOrNull()
    val deletedAt = record["deleted_at"]
    if (!parent.isFolderReference() || position == null || position.isNaN() || position.isInfinite() ||
        updatedAt == null || !isTimestamp(updatedAt) ||
        (deletedAt != null && (deletedAt.stringOrNull()?.let(::isTimestamp) != true))
    ) {
        throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED, id)
    }
    val name = record["name"].stringOrNull()
    if (name == null || !isFolderName(name)) throw FolderManifestInvalidException(FolderManifestProblem.BAD_NAME, id)
    return FolderEntry(name, parent.stringOrNull(), position, updatedAt, deletedAt?.stringOrNull())
}

private fun readPlacement(id: String, value: JsonElement): ItemPlacement {
    val record = value as? JsonObject ?: throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED, id)
    val folder = record["folder_id"]
    val updatedAt = record["updated_at"].stringOrNull()
    if (!folder.isFolderReference() || updatedAt == null || !isTimestamp(updatedAt)) {
        throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED, id)
    }
    return ItemPlacement(folder.stringOrNull(), updatedAt)
}

fun parseFolderManifest(text: String): FolderManifest {
    val parsed = try {
        manifestJson.parseToJsonElement(text) as? JsonObject
    } catch (_: SerializationException) {
        null
    } ?: throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED)
    val version = (parsed["v"] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull
    if (version != FOLDER_MANIFEST_VERSION.toDouble()) throw FolderManifestInvalidException(FolderManifestProblem.UNKNOWN_VERSION)
    val folders = parsed["folders"] as? JsonObject ?: throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED)
    val items = parsed["items"] as? JsonObject ?: throw FolderManifestInvalidException(FolderManifestProblem.MALFORMED)
    return FolderManifest(
        folders.entries.associateTo(LinkedHashMap()) { (id, value) -> id to readFolder(id, value) },
        items.entries.associateTo(LinkedHashMap()) { (id, value) -> id to readPlacement(id, value) },
    )
}

private fun positionJson(position: Double): JsonPrimitive {
    val whole = position.toLong()
    return if (whole.toDouble() == position) JsonPrimitive(whole) else JsonPrimitive(position)
}

fun formatFolderManifest(manifest: FolderManifest): String = manifestJson.encodeToString(
    JsonObject.serializer(),
    buildJsonObject {
        put("v", FOLDER_MANIFEST_VERSION)
        put(
            "folders",
            JsonObject(
                manifest.folders.mapValues { (_, folder) ->
                    buildJsonObject {
                        put("name", folder.name)
                        put("parent_id", folder.parentId?.let(::JsonPrimitive) ?: JsonNull)
                        put("position", positionJson(folder.position))
                        put("updated_at", folder.updatedAt)
                        folder.deletedAt?.let { put("deleted_at", it) }
                    }
                },
            ),
        )
        put(
            "items",
            JsonObject(
                manifest.items.mapValues { (_, placement) ->
                    buildJsonObject {
                        put("folder_id", placement.folderId?.let(::JsonPrimitive) ?: JsonNull)
                        put("updated_at", placement.updatedAt)
                    }
                },
            ),
        )
    },
)

fun emptyFolderManifest(rules: FolderRules, at: String = nowTimestamp()): FolderManifest {
    val folders = LinkedHashMap<String, FolderEntry>()
    if (rules.home) folders[HOME_FOLDER_ID] = FolderEntry(HOME_FOLDER_NAME, null, 0.0, at)
    return FolderManifest(folders, emptyMap())
}

private fun findCycle(folders: Map<String, FolderEntry>, startId: String): List<String>? {
    val seen = HashMap<String, Int>()
    val path = mutableListOf<String>()
    var current: String? = startId
    while (current != null && current in folders) {
        seen[current]?.let { return path.subList(it, path.size).toList() }
        seen[current] = path.size
        path += current
        current = folders.getValue(current).parentId
    }
    return null
}

private fun depthOf(folders: Map<String, FolderEntry>, id: String): Int {
    var depth = 0
    var current: String? = id
    while (current != null && current in folders && depth <= folders.size) {
        depth++
        current = folders.getValue(current).parentId
    }
    return depth
}

private fun subtreeHeight(folders: Map<String, FolderEntry>, id: String, guard: Int = folders.size): Int {
    if (guard <= 0) return 1
    var height = 1
    for ((childId, child) in folders) {
        if (child.parentId == id && child.isLive) height = maxOf(height, 1 + subtreeHeight(folders, childId, guard - 1))
    }
    return height
}

private fun isLive(folders: Map<String, FolderEntry>, id: String): Boolean = folders[id]?.isLive == true

fun validateFolderManifest(manifest: FolderManifest, rules: FolderRules): FolderManifest {
    val folders = manifest.folders
    for ((id, folder) in folders) {
        if (folder.parentId != null && folder.parentId !in folders) throw FolderManifestInvalidException(FolderManifestProblem.UNKNOWN_PARENT, id)
    }
    for (id in folders.keys) {
        if (findCycle(folders, id) != null) throw FolderManifestInvalidException(FolderManifestProblem.CYCLE, id)
    }
    for ((id, folder) in folders) {
        if (!folder.isLive) continue
        if (folder.parentId != null && !isLive(folders, folder.parentId)) throw FolderManifestInvalidException(FolderManifestProblem.DELETED_PARENT, id)
        if (depthOf(folders, id) > rules.maxDepth) throw FolderManifestInvalidException(FolderManifestProblem.TOO_DEEP, id)
    }
    if (rules.home && (!isLive(folders, HOME_FOLDER_ID) || folders.getValue(HOME_FOLDER_ID).parentId != null)) {
        throw FolderManifestInvalidException(FolderManifestProblem.MISSING_HOME, HOME_FOLDER_ID)
    }
    for ((id, placement) in manifest.items) {
        if (placement.folderId != null && placement.folderId !in folders) throw FolderManifestInvalidException(FolderManifestProblem.UNKNOWN_FOLDER, id)
    }
    return manifest
}

private fun <T> later(stored: T?, local: T?, updatedAt: (T) -> String): T? = when {
    stored == null -> local
    local == null -> stored
    updatedAt(local) > updatedAt(stored) -> local
    else -> stored
}

private fun <T> mergeRecords(stored: Map<String, T>, local: Map<String, T>, updatedAt: (T) -> String): LinkedHashMap<String, T> {
    val merged = LinkedHashMap(stored)
    for ((id, entry) in local) later(merged[id], entry, updatedAt)?.let { merged[id] = it }
    return merged
}

private fun breakCycles(folders: MutableMap<String, FolderEntry>) {
    for (id in folders.keys.sorted()) {
        val cycle = findCycle(folders, id) ?: continue
        val latest = cycle.sortedWith(compareBy<String> { folders.getValue(it).updatedAt }.thenBy { it }).last()
        folders[latest] = folders.getValue(latest).copy(parentId = null)
    }
}

private fun cascadeDeletions(folders: MutableMap<String, FolderEntry>) {
    var changed = true
    while (changed) {
        changed = false
        for ((id, folder) in folders.entries.toList()) {
            if (!folder.isLive || folder.parentId == null) continue
            val parentDeletedAt = folders[folder.parentId]?.deletedAt
            if (parentDeletedAt != null) {
                folders[id] = folder.copy(deletedAt = parentDeletedAt)
                changed = true
            }
        }
    }
}

private fun liftTooDeep(folders: MutableMap<String, FolderEntry>, maxDepth: Int) {
    while (true) {
        val offender = folders.keys
            .filter { folders.getValue(it).isLive && depthOf(folders, it) > maxDepth }
            .sortedWith(compareBy<String> { depthOf(folders, it) }.thenBy { it })
            .firstOrNull() ?: return
        folders[offender] = folders.getValue(offender).copy(parentId = null)
    }
}

private fun restoreHome(folders: MutableMap<String, FolderEntry>, at: String) {
    val home = folders[HOME_FOLDER_ID]
    if (home == null) {
        folders[HOME_FOLDER_ID] = FolderEntry(HOME_FOLDER_NAME, null, 0.0, at)
    } else if (!home.isLive || home.parentId != null) {
        folders[HOME_FOLDER_ID] = FolderEntry(home.name, null, home.position, home.updatedAt)
    }
}

fun repairFolderManifest(manifest: FolderManifest, rules: FolderRules, at: String = nowTimestamp()): FolderManifest {
    val folders = LinkedHashMap(manifest.folders)
    for ((id, folder) in folders.entries.toList()) {
        if (folder.parentId != null && folder.parentId !in folders) folders[id] = folder.copy(parentId = null)
    }
    breakCycles(folders)
    if (rules.home) restoreHome(folders, at)
    cascadeDeletions(folders)
    liftTooDeep(folders, rules.maxDepth)
    val items = manifest.items.mapValuesTo(LinkedHashMap()) { (_, placement) ->
        if (placement.folderId != null && placement.folderId !in folders) placement.copy(folderId = null) else placement
    }
    return validateFolderManifest(FolderManifest(folders, items), rules)
}

fun mergeFolderManifests(stored: FolderManifest, local: FolderManifest, rules: FolderRules, at: String = nowTimestamp()): FolderManifest =
    repairFolderManifest(
        FolderManifest(mergeRecords(stored.folders, local.folders) { it.updatedAt }, mergeRecords(stored.items, local.items) { it.updatedAt }),
        rules,
        at,
    )

private fun requireLiveFolder(manifest: FolderManifest, id: String): FolderEntry =
    manifest.folders[id]?.takeIf { it.isLive } ?: throw FolderEditException(FolderEditProblem.UNKNOWN_FOLDER, id)

private fun requireName(name: String, id: String?): String {
    val trimmed = name.trim()
    if (!isFolderName(trimmed)) throw FolderEditException(FolderEditProblem.BAD_NAME, id)
    return trimmed
}

private fun nextPosition(manifest: FolderManifest, parentId: String?): Double {
    var highest = -1.0
    for (folder in manifest.folders.values) if (folder.parentId == parentId && folder.isLive) highest = maxOf(highest, folder.position)
    return highest + 1
}

private fun isWithin(folders: Map<String, FolderEntry>, id: String, ancestorId: String): Boolean {
    var current: String? = id
    var steps = 0
    while (current != null && current in folders && steps <= folders.size) {
        if (current == ancestorId) return true
        current = folders.getValue(current).parentId
        steps++
    }
    return false
}

private fun FolderManifest.withFolder(id: String, entry: FolderEntry) = FolderManifest(LinkedHashMap(folders).also { it[id] = entry }, items)

fun createFolder(name: String, parentId: String? = null, id: String = newItemId(), at: String = nowTimestamp()): FolderEdit =
    FolderEdit { manifest, rules ->
        if (id.isEmpty() || id in manifest.folders) throw FolderEditException(FolderEditProblem.FOLDER_EXISTS, id)
        val trimmed = requireName(name, id)
        if (parentId != null) requireLiveFolder(manifest, parentId)
        val depth = if (parentId == null) 1 else depthOf(manifest.folders, parentId) + 1
        if (depth > rules.maxDepth) throw FolderEditException(FolderEditProblem.TOO_DEEP, id)
        manifest.withFolder(id, FolderEntry(trimmed, parentId, nextPosition(manifest, parentId), at))
    }

fun renameFolder(id: String, name: String, at: String = nowTimestamp()): FolderEdit = FolderEdit { manifest, _ ->
    val current = requireLiveFolder(manifest, id)
    val trimmed = requireName(name, id)
    if (current.name == trimmed) manifest else manifest.withFolder(id, current.copy(name = trimmed, updatedAt = at))
}

fun moveFolder(id: String, parentId: String?, position: Double? = null, at: String = nowTimestamp()): FolderEdit =
    FolderEdit { manifest, rules ->
        val current = requireLiveFolder(manifest, id)
        if (id == HOME_FOLDER_ID && rules.home && parentId != null) throw FolderEditException(FolderEditProblem.HOME_IS_FIXED, id)
        if (parentId != null) {
            requireLiveFolder(manifest, parentId)
            if (isWithin(manifest.folders, parentId, id)) throw FolderEditException(FolderEditProblem.INTO_ITSELF, id)
        }
        val parentDepth = if (parentId == null) 0 else depthOf(manifest.folders, parentId)
        if (parentDepth + subtreeHeight(manifest.folders, id) > rules.maxDepth) throw FolderEditException(FolderEditProblem.TOO_DEEP, id)
        val target = position ?: if (current.parentId == parentId) current.position else nextPosition(manifest, parentId)
        if (current.parentId == parentId && current.position == target) {
            manifest
        } else {
            manifest.withFolder(id, current.copy(parentId = parentId, position = target, updatedAt = at))
        }
    }

fun deleteFolder(id: String, at: String = nowTimestamp()): FolderEdit = FolderEdit { manifest, rules ->
    requireLiveFolder(manifest, id)
    if (id == HOME_FOLDER_ID && rules.home) throw FolderEditException(FolderEditProblem.HOME_IS_FIXED, id)
    val folders = LinkedHashMap(manifest.folders)
    for ((folderId, folder) in manifest.folders) {
        if (folder.isLive && isWithin(manifest.folders, folderId, id)) folders[folderId] = folder.copy(updatedAt = at, deletedAt = at)
    }
    FolderManifest(folders, manifest.items)
}

fun placeItem(itemId: String, folderId: String?, at: String = nowTimestamp()): FolderEdit = FolderEdit { manifest, _ ->
    if (folderId != null) requireLiveFolder(manifest, folderId)
    val existing = manifest.items[itemId]
    if (existing != null && existing.folderId == folderId) {
        manifest
    } else {
        FolderManifest(manifest.folders, LinkedHashMap(manifest.items).also { it[itemId] = ItemPlacement(folderId, at) })
    }
}

fun forgetItems(itemIds: Collection<String>): FolderEdit = FolderEdit { manifest, _ ->
    if (itemIds.none { it in manifest.items }) manifest else FolderManifest(manifest.folders, manifest.items.filterKeys { it !in itemIds })
}

private val byPosition = compareBy<Folder> { it.position }.thenBy { it.name }.thenBy { it.id }

fun liveFolders(manifest: FolderManifest): List<Folder> =
    manifest.folders.filterValues { it.isLive }.map { (id, entry) -> Folder(id, entry) }.sortedWith(byPosition)

fun childFolders(manifest: FolderManifest, parentId: String?): List<Folder> = liveFolders(manifest).filter { it.parentId == parentId }

fun folderPath(manifest: FolderManifest, id: String): List<Folder> {
    val path = ArrayDeque<Folder>()
    var current: String? = id
    while (current != null && isLive(manifest.folders, current) && path.size < manifest.folders.size) {
        val entry = manifest.folders.getValue(current)
        path.addFirst(Folder(current, entry))
        current = entry.parentId
    }
    return path.toList()
}

fun folderOf(manifest: FolderManifest, itemId: String, rules: FolderRules): String? {
    val assigned = manifest.items[itemId]?.folderId
    if (assigned != null && isLive(manifest.folders, assigned)) return assigned
    return if (rules.home) HOME_FOLDER_ID else null
}

fun itemsIn(manifest: FolderManifest, folderId: String?, itemIds: Iterable<String>, rules: FolderRules): List<String> =
    itemIds.filter { folderOf(manifest, it, rules) == folderId }
