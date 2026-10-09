package zekke.core.folders

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import zekke.core.encoding.bytesToUtf8
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.failure
import zekke.core.items.hashReceivedCiphertext
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import zekke.core.sealed.openBlob
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.sealBlob
import zekke.core.sealed.sealSecretBlob
import zekke.core.signing.Action
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FolderStoreTest {
    private val rules = ManifestScope.SECRETS.rules

    private fun TestVault.record(manifest: FolderManifest, revision: Long, generation: Int = 1) = buildJsonObject {
        val dek = generateScopeKek(primitives)
        put("scope", "secrets")
        put("ciphertext", sealBlob(formatFolderManifest(manifest).encodeToByteArray(), dek, primitives))
        put("wrapped_dek", sealSecretBlob(dek, session.kek(Scope.SECRETS, generation), primitives))
        put("key_generation", generation)
        put("revision", revision)
        put("updated_at", "2026-10-09T00:00:00Z")
    }

    private fun TestVault.opened(body: kotlinx.serialization.json.JsonObject): FolderManifest {
        val kek = session.kek(Scope.SECRETS, body.getValue("key_generation").jsonPrimitive.int)
        val plaintext = openSecretBlob(body.getValue("wrapped_dek").jsonPrimitive.content, kek, primitives).use { dek ->
            openBlob(body.getValue("ciphertext").jsonPrimitive.content, dek, primitives)
        }
        return parseFolderManifest(bytesToUtf8(plaintext))
    }

    private fun stored(revision: Long) = { request: zekke.core.items.SentRequest ->
        data(buildJsonObject {
            put("scope", "secrets")
            put("ciphertext", request.json.getValue("ciphertext"))
            put("wrapped_dek", request.json.getValue("wrapped_dek"))
            put("key_generation", request.json.getValue("key_generation"))
            put("revision", revision)
            put("updated_at", "2026-10-09T00:00:00Z")
        })
    }

    @Test
    fun aScopeWithNoManifestStartsWithHomeAndTheFirstEditSignsRevisionZero() = runTest {
        val vault = TestVault()
        val store = FolderStore(vault.context)
        vault.server.reply(failure(404, "NOT_FOUND"))
        vault.server.answer(stored(1))
        val edited = store.edit(ManifestScope.SECRETS, createFolder("Work", id = "w"))
        assertEquals(listOf(HOME_FOLDER_ID, "w"), liveFolders(edited).map { it.id })
        val put = vault.server.sent.last()
        assertEquals("PUT" to "/secrets/folders", put.method to put.path)
        assertEquals(0, put.json.getValue("expected_revision").jsonPrimitive.long)
        val digest = hashReceivedCiphertext(put.json.getValue("ciphertext").jsonPrimitive.content, primitives)
        assertTrue(vault.verifies(put.json, Action.FOLDERS_UPDATE, listOf("secrets", "0", digest)))
        assertEquals(listOf(HOME_FOLDER_ID, "w"), liveFolders(vault.opened(put.json)).map { it.id })
        assertEquals(edited, store.load(ManifestScope.SECRETS))
        assertEquals(2, vault.server.sent.size)
    }

    @Test
    fun aConflictReReadsAndAppliesTheSameEditToWhatTheOtherDeviceStored() = runTest {
        val vault = TestVault()
        val store = FolderStore(vault.context)
        val mine = emptyFolderManifest(rules, "2026-10-01T00:00:00.000Z")
        val theirs = createFolder("Theirs", id = "t", at = "2026-10-02T00:00:00.000Z").apply(mine, rules)
        vault.server.reply(data(vault.record(mine, 4)))
        store.load(ManifestScope.SECRETS)
        vault.server.reply(failure(409, "CONFLICT"), data(vault.record(theirs, 5)))
        vault.server.answer(stored(6))
        val edited = store.edit(ManifestScope.SECRETS, createFolder("Mine", id = "m"))
        assertEquals(setOf(HOME_FOLDER_ID, "t", "m"), liveFolders(edited).map { it.id }.toSet())
        assertEquals(5, vault.server.sent.last().json.getValue("expected_revision").jsonPrimitive.long)
    }

    @Test
    fun anEditThatChangesNothingWritesNothingAndAnEditThatNoLongerAppliesFails() = runTest {
        val vault = TestVault()
        val store = FolderStore(vault.context)
        vault.server.reply(data(vault.record(emptyFolderManifest(rules), 1)))
        store.load(ManifestScope.SECRETS)
        store.edit(ManifestScope.SECRETS, renameFolder(HOME_FOLDER_ID, HOME_FOLDER_NAME))
        assertEquals(1, vault.server.sent.size)
        assertFailsWith<FolderEditException> { store.edit(ManifestScope.SECRETS, deleteFolder("absent")) }
    }

    @Test
    fun aTreeThatFailsValidationIsReportedNotRendered() = runTest {
        val vault = TestVault()
        val looped = FolderManifest(
            mapOf(
                HOME_FOLDER_ID to FolderEntry(HOME_FOLDER_NAME, null, 0.0, "2026-10-01T00:00:00.000Z"),
                "a" to FolderEntry("a", "b", 1.0, "2026-10-01T00:00:00.000Z"),
                "b" to FolderEntry("b", "a", 2.0, "2026-10-01T00:00:00.000Z"),
            ),
            emptyMap(),
        )
        vault.server.reply(data(vault.record(looped, 3)))
        val problem = assertFailsWith<FolderManifestInvalidException> { FolderStore(vault.context).load(ManifestScope.SECRETS) }.problem
        assertEquals(FolderManifestProblem.CYCLE, problem)
    }

    @Test
    fun resealingMovesAnOlderGenerationForwardUnchanged() = runTest {
        val vault = TestVault(mapOf(Scope.SECRETS to 2))
        val manifest = createFolder("Work", id = "w", at = "2026-10-02T00:00:00.000Z").apply(emptyFolderManifest(rules, "2026-10-01T00:00:00.000Z"), rules)
        vault.server.reply(data(vault.record(manifest, 7, generation = 1)))
        vault.server.answer(stored(8))
        assertTrue(FolderStore(vault.context).reseal(ManifestScope.SECRETS))
        val put = vault.server.sent.last().json
        assertEquals(2, put.getValue("key_generation").jsonPrimitive.int)
        assertEquals(7, put.getValue("expected_revision").jsonPrimitive.long)
        assertEquals(formatFolderManifest(manifest), formatFolderManifest(vault.opened(put)))
        vault.server.reply(data(vault.record(manifest, 8, generation = 2)))
        assertEquals(false, FolderStore(vault.context).reseal(ManifestScope.SECRETS))
    }

    @Test
    fun lockingForgetsTheManifests() = runTest {
        val vault = TestVault()
        val store = FolderStore(vault.context)
        vault.server.reply(data(vault.record(emptyFolderManifest(rules), 1)))
        store.load(ManifestScope.SECRETS)
        vault.session.lock()
        assertNull(store.cached(ManifestScope.SECRETS))
    }
}
