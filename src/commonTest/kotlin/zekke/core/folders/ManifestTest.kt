package zekke.core.folders

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ManifestTest {
    private val tabs = FolderRules(maxDepth = 1, home = true)
    private val tree = FolderRules(maxDepth = 3, home = false)
    private val t0 = "2026-10-01T00:00:00.000Z"
    private val t1 = "2026-10-02T00:00:00.000Z"
    private val t2 = "2026-10-03T00:00:00.000Z"

    private fun entry(name: String, parent: String? = null, at: String = t0, deleted: String? = null, position: Double = 0.0) =
        FolderEntry(name, parent, position, at, deleted)

    private fun manifest(vararg folders: Pair<String, FolderEntry>, items: Map<String, ItemPlacement> = emptyMap()) =
        FolderManifest(linkedMapOf(*folders), items)

    private fun problemOf(block: () -> Unit): FolderManifestProblem = assertFailsWith<FolderManifestInvalidException> { block() }.problem

    @Test
    fun writesTheWebAppsJsonAndReadsItBack() {
        val written = "{\"v\":1,\"folders\":{\"home\":{\"name\":\"home\",\"parent_id\":null,\"position\":0,\"updated_at\":\"$t0\"}," +
            "\"f1\":{\"name\":\"Work\",\"parent_id\":null,\"position\":1.5,\"updated_at\":\"$t1\",\"deleted_at\":\"$t2\"}}," +
            "\"items\":{\"i1\":{\"folder_id\":\"home\",\"updated_at\":\"$t1\"},\"i2\":{\"folder_id\":null,\"updated_at\":\"$t1\"}}}"
        val parsed = parseFolderManifest(written)
        assertEquals(written, formatFolderManifest(parsed))
        assertEquals(t2, parsed.folders.getValue("f1").deletedAt)
        assertNull(parsed.items.getValue("i2").folderId)
    }

    @Test
    fun refusesWhatIsNotAManifest() {
        assertEquals(FolderManifestProblem.MALFORMED, problemOf { parseFolderManifest("nope") })
        assertEquals(FolderManifestProblem.UNKNOWN_VERSION, problemOf { parseFolderManifest("{\"v\":2,\"folders\":{},\"items\":{}}") })
        assertEquals(FolderManifestProblem.MALFORMED, problemOf { parseFolderManifest("{\"v\":1,\"folders\":[],\"items\":{}}") })
        assertEquals(
            FolderManifestProblem.BAD_NAME,
            problemOf { parseFolderManifest("{\"v\":1,\"folders\":{\"a\":{\"name\":\"  \",\"parent_id\":null,\"position\":0,\"updated_at\":\"$t0\"}},\"items\":{}}") },
        )
        assertEquals(
            FolderManifestProblem.MALFORMED,
            problemOf { parseFolderManifest("{\"v\":1,\"folders\":{\"a\":{\"name\":\"a\",\"parent_id\":null,\"position\":\"0\",\"updated_at\":\"$t0\"}},\"items\":{}}") },
        )
        assertEquals(
            FolderManifestProblem.MALFORMED,
            problemOf { parseFolderManifest("{\"v\":1,\"folders\":{\"a\":{\"name\":\"a\",\"parent_id\":null,\"position\":0,\"updated_at\":\"yesterday\"}},\"items\":{}}") },
        )
    }

    @Test
    fun validationFindsEveryWayATreeGoesWrong() {
        assertEquals(FolderManifestProblem.CYCLE, problemOf { validateFolderManifest(manifest("a" to entry("a", "b"), "b" to entry("b", "a")), tree) })
        assertEquals(FolderManifestProblem.UNKNOWN_PARENT, problemOf { validateFolderManifest(manifest("a" to entry("a", "x")), tree) })
        assertEquals(
            FolderManifestProblem.DELETED_PARENT,
            problemOf { validateFolderManifest(manifest("a" to entry("a", deleted = t1), "b" to entry("b", "a")), tree) },
        )
        assertEquals(FolderManifestProblem.TOO_DEEP, problemOf { validateFolderManifest(manifest("home" to entry("home"), "a" to entry("a", "home")), tabs) })
        assertEquals(FolderManifestProblem.MISSING_HOME, problemOf { validateFolderManifest(manifest("a" to entry("a")), tabs) })
        assertEquals(
            FolderManifestProblem.UNKNOWN_FOLDER,
            problemOf { validateFolderManifest(manifest("home" to entry("home"), items = mapOf("i" to ItemPlacement("x", t0))), tabs) },
        )
    }

    @Test
    fun aMergeTakesTheLaterWriterPerFolderAndKeepsADeletion() {
        val stored = manifest("home" to entry("home"), "a" to entry("Work", at = t1), "b" to entry("Old", at = t0))
        val local = manifest("home" to entry("home"), "a" to entry("Job", at = t0), "b" to entry("Old", at = t2, deleted = t2))
        val merged = mergeFolderManifests(stored, local, tabs, t2)
        assertEquals("Work", merged.folders.getValue("a").name)
        assertEquals(t2, merged.folders.getValue("b").deletedAt)
    }

    @Test
    fun aMergeThatMakesACycleLiftsTheLatestMovedFolderToTheRoot() {
        val stored = manifest("a" to entry("a", "b", at = t1), "b" to entry("b", at = t0))
        val local = manifest("a" to entry("a", at = t0), "b" to entry("b", "a", at = t2))
        val merged = mergeFolderManifests(stored, local, tree, t2)
        assertNull(merged.folders.getValue("b").parentId)
        assertEquals("b", merged.folders.getValue("a").parentId)
    }

    @Test
    fun repairCascadesDeletionsRestoresHomeAndLiftsWhatIsTooDeep() {
        val repaired = repairFolderManifest(
            manifest(
                "home" to entry("home", "x", deleted = t1),
                "x" to entry("x", deleted = t1),
                "y" to entry("y", "x"),
                items = mapOf("i" to ItemPlacement("missing", t0)),
            ),
            tabs,
            t2,
        )
        assertNull(repaired.folders.getValue("home").parentId)
        assertTrue(repaired.folders.getValue("home").isLive)
        assertEquals(t1, repaired.folders.getValue("y").deletedAt)
        assertNull(repaired.items.getValue("i").folderId)
        val deep = repairFolderManifest(manifest("a" to entry("a"), "b" to entry("b", "a"), "c" to entry("c", "b"), "d" to entry("d", "c")), tree, t2)
        assertNull(deep.folders.getValue("d").parentId)
    }

    @Test
    fun editsRefuseWhatTheTreeCannotHoldAndReturnTheSameManifestWhenNothingChanges() {
        val empty = emptyFolderManifest(tabs, t0)
        val created = createFolder("  Work  ", id = "w", at = t1).apply(empty, tabs)
        assertEquals("Work", created.folders.getValue("w").name)
        assertEquals(1.0, created.folders.getValue("w").position)
        fun refused(edit: FolderEdit, on: FolderManifest = created, rules: FolderRules = tabs) =
            assertFailsWith<FolderEditException> { edit.apply(on, rules) }.problem
        assertEquals(FolderEditProblem.FOLDER_EXISTS, refused(createFolder("again", id = "w")))
        assertEquals(FolderEditProblem.TOO_DEEP, refused(createFolder("child", parentId = "w", id = "c")))
        assertEquals(FolderEditProblem.BAD_NAME, refused(renameFolder("w", " ")))
        assertEquals(FolderEditProblem.HOME_IS_FIXED, refused(deleteFolder(HOME_FOLDER_ID)))
        assertEquals(FolderEditProblem.UNKNOWN_FOLDER, refused(placeItem("i", "nowhere")))
        assertSame(created, renameFolder("w", "Work").apply(created, tabs))
        assertSame(created, forgetItems(listOf("i")).apply(created, tabs))

        val nested = manifest("a" to entry("a"), "b" to entry("b", "a"))
        assertEquals(FolderEditProblem.INTO_ITSELF, refused(moveFolder("a", "b"), nested, tree))
        val deleted = deleteFolder("a", t2).apply(nested, tree)
        assertEquals(listOf(t2, t2), deleted.folders.values.map { it.deletedAt })
    }

    @Test
    fun anItemWithoutALiveFolderResolvesToHome() {
        val m = placeItem("i1", "w", t1).apply(createFolder("Work", id = "w", at = t1).apply(emptyFolderManifest(tabs, t0), tabs), tabs)
        assertEquals("w", folderOf(m, "i1", tabs))
        assertEquals(HOME_FOLDER_ID, folderOf(m, "i2", tabs))
        val gone = deleteFolder("w", t2).apply(m, tabs)
        assertEquals(HOME_FOLDER_ID, folderOf(gone, "i1", tabs))
        assertEquals(listOf("i1", "i2"), itemsIn(gone, HOME_FOLDER_ID, listOf("i1", "i2"), tabs))
        assertEquals(listOf(HOME_FOLDER_ID), liveFolders(gone).map { it.id })
        assertEquals(listOf("a", "b"), folderPath(manifest("a" to entry("a"), "b" to entry("b", "a")), "b").map { it.id })
    }

    @Test
    fun timestampsAreWrittenAsTheBrowserWritesThem() {
        assertEquals("1970-01-01T00:00:00.000Z", isoTimestamp(0))
        assertEquals("2026-10-10T13:45:07.089Z", isoTimestamp(1_791_639_907_089))
        assertEquals("2000-02-29T23:59:59.999Z", isoTimestamp(951_868_799_999))
        assertEquals(24, nowTimestamp().length)
    }
}
