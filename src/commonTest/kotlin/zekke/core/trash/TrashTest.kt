package zekke.core.trash

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import zekke.core.files.FileRecord
import zekke.core.files.buildManifest
import zekke.core.files.sealManifest
import zekke.core.folders.FolderTreeProblem
import zekke.core.folders.FolderTreeProblemException
import zekke.core.folders.TreeFolder
import zekke.core.folders.TreeFolderRecord
import zekke.core.folders.TreeScope
import zekke.core.folders.canCreateIn
import zekke.core.folders.canMoveFolder
import zekke.core.folders.childrenOf
import zekke.core.folders.createTreeFolder
import zekke.core.folders.deleteTreeFolder
import zekke.core.folders.descendantsOf
import zekke.core.folders.listTreeFolders
import zekke.core.folders.moveTreeFolder
import zekke.core.folders.pathTo
import zekke.core.folders.FolderManifestInvalidException
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.failure
import zekke.core.items.newItemId
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.openText
import zekke.core.sealed.sealSecretBlob
import zekke.core.sealed.sealText
import zekke.core.signing.Action
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TrashTest {
    private fun folder(id: String, parent: String? = null, position: Double = 0.0) = TreeFolder(id, parent, id, position, "", "")

    @Test
    fun walksTheTreeAndOffersOnlyTheMovesTheServerWouldAccept() {
        val chain = (1..8).map { folder("f$it", if (it == 1) null else "f${it - 1}") }
        assertEquals((1..8).map { "f$it" }, pathTo(chain, "f8").map { it.id })
        assertFalse(canCreateIn(chain, "f8"))
        assertTrue(canCreateIn(chain, "f7"))
        assertEquals((3..8).map { "f$it" }.toSet(), descendantsOf(chain, "f3"))
        assertFalse(canMoveFolder(chain, "f2", "f5"))
        assertTrue(canMoveFolder(chain, "f5", null))
        val side = chain + folder("s1")
        assertFalse(canMoveFolder(side, "f1", "s1"))
        assertTrue(canMoveFolder(side, "f2", "s1"))
        assertTrue(canMoveFolder(side, "f8", "s1"))
        assertEquals(listOf("b", "a"), childrenOf(listOf(folder("a", position = 2.0), folder("b", position = 1.0)), null).map { it.id })
    }

    @Test
    fun aFolderNameIsSealedAndTheServersRefusalsAreNamed() = runTest {
        val vault = TestVault()
        val parent = newItemId(primitives)
        vault.server.answer { data(buildJsonObject { it.json.forEach { (k, v) -> put(k, v) } }, 201) }
        createTreeFolder(vault.context, TreeScope.FILES, "  Fotos  ", parent)
        val body = vault.server.sent.single().json
        assertEquals(parent, body.getValue("parent_id").jsonPrimitive.content)
        val dek = openSecretBlob(body.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.FILES, 1), primitives)
        assertEquals("Fotos", openText(body.getValue("ciphertext").jsonPrimitive.content, dek, primitives))

        vault.server.reply(failure(409, "FOLDER_INTO_ITSELF"))
        val refused = assertFailsWith<FolderTreeProblemException> { moveTreeFolder(vault.context, TreeScope.FILES, parent, newItemId(primitives)) }
        assertEquals(FolderTreeProblem.FOLDER_INTO_ITSELF, refused.problem)

        val id = newItemId(primitives)
        vault.server.reply(data(buildJsonObject { put("folders", 2); put("items", 3) }))
        deleteTreeFolder(vault.context, TreeScope.FILES, id)
        assertTrue(vault.verifies(vault.server.sent.last().json, Action.FOLDER_DELETE, listOf("files", id)))
    }

    @Test
    fun aLoopedTreeFromTheServerIsReportedNotDrawn() = runTest {
        val vault = TestVault()
        val a = newItemId(primitives)
        val b = newItemId(primitives)
        fun record(id: String, parent: String) = buildJsonObject {
            val dek = generateScopeKek(primitives)
            put("id", id)
            put("parent_id", parent)
            put("ciphertext", sealText(id, dek, primitives))
            put("wrapped_dek", sealSecretBlob(dek, vault.session.kek(Scope.FILES, 1), primitives))
            put("key_generation", 1)
            put("position", 0)
        }
        vault.server.reply(data(kotlinx.serialization.json.JsonArray(listOf(record(a, b), record(b, a)))))
        assertFailsWith<FolderManifestInvalidException> { listTreeFolders(vault.context, TreeScope.FILES) }
    }

    @Test
    fun aThumbnailTravelsWithItsFileAndAPurgeIsSignedOverSortedIds() = runTest {
        val vault = TestVault()
        val thumbnail = newItemId(primitives)
        val file = newItemId(primitives)
        fun record(id: String, name: String, thumbnailId: String? = null): FileRecord {
            val dek = generateScopeKek(primitives)
            return FileRecord(
                id = id,
                ciphertext = sealManifest(buildManifest(name, "image/jpeg", 10, thumbnailId = thumbnailId), dek, primitives),
                wrappedDek = sealSecretBlob(dek, vault.session.kek(Scope.FILES, 1), primitives),
                keyGeneration = 1,
                sizeBytes = 65_573,
                deletedAt = "2026-10-05T00:00:00Z",
            )
        }
        val folderDek = generateScopeKek(primitives)
        val trash = FileTrash(
            folders = listOf(
                TreeFolderRecord(
                    id = newItemId(primitives),
                    ciphertext = sealText("Old", folderDek, primitives),
                    wrappedDek = sealSecretBlob(folderDek, vault.session.kek(Scope.FILES, 1), primitives),
                    keyGeneration = 1,
                    deletedAt = "2026-10-06T00:00:00Z",
                    itemCount = 4,
                ),
            ),
            files = listOf(record(file, "beach.jpg", thumbnail), record(thumbnail, "thumbnail.jpg")),
        )
        val entries = fileTrashEntries(vault.context, trash)
        assertEquals(listOf("Old" to TrashKind.FOLDER, "beach.jpg" to TrashKind.FILE), entries.map { it.name to it.kind })
        assertEquals(listOf(thumbnail), entries.last().companions)
        assertEquals(4, entries.first().itemCount)

        vault.server.reply(data(buildJsonObject { put("requested", 2); put("folders", 0); put("items", 2) }))
        assertEquals(2, purgeEntries(vault.context, listOf(entries.last())))
        val body = vault.server.sent.single().json
        val sorted = listOf(file, thumbnail).sorted()
        assertEquals(sorted, body.getValue("ids").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(vault.verifies(body, Action.FILE_PURGE, sorted))
        assertEquals("/files/trash", vault.server.sent.single().path)

        vault.server.reply(data(buildJsonObject { put("requested", 2); put("folders", 0); put("items", 2) }))
        restoreEntries(vault.context, listOf(entries.last()))
        val restore = vault.server.sent.last()
        assertEquals("POST" to "/files/trash/restore", restore.method to restore.path)
        assertNull(restore.json["signature"])
        assertTrue(restore.json.getValue("ids").jsonArray.size == 2 && restore.json.jsonObject.size == 1)
    }
}
