package zekke.core.notes

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import zekke.core.api.wireJson
import zekke.core.feed.ReplicaItem
import zekke.core.items.EmptySelectionException
import zekke.core.items.ItemTooLargeException
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.newItemId
import zekke.core.items.storedRow
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.openText
import zekke.core.sealed.sealSecretBlob
import zekke.core.sealed.sealText
import zekke.core.signing.Action
import zekke.core.signing.verifyPayload
import zekke.core.encoding.spkiBase64ToUncompressedPoint
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NotesTest {
    private fun TestVault.opened(body: JsonObject): String {
        val kek = session.kek(Scope.NOTES, body.getValue("key_generation").jsonPrimitive.int)
        return openSecretBlob(body.getValue("wrapped_dek").jsonPrimitive.content, kek, primitives).use { dek ->
            openText(body.getValue("ciphertext").jsonPrimitive.content, dek, primitives)
        }
    }

    private fun record(body: JsonObject, id: String): NoteRecord =
        wireJson.decodeFromJsonElement(NoteRecord.serializer(), storedRow(JsonObject(body + ("id" to JsonPrimitive(id)))))

    @Test
    fun aCreateCarriesTheCallersIdTheCurrentGenerationAndNoSignature() = runTest {
        val vault = TestVault(mapOf(Scope.NOTES to 2))
        val id = newItemId(primitives)
        vault.server.answer { data(storedRow(it.json), 201) }
        val result = createNote(vault.context, "# Plans\nsee you", id)
        val sent = vault.server.sent.single()
        assertEquals("POST" to "/notes", sent.method to sent.path)
        assertEquals(id, sent.json.getValue("id").jsonPrimitive.content)
        assertEquals(2, sent.json.getValue("key_generation").jsonPrimitive.int)
        assertEquals("v1", sent.json.getValue("version").jsonPrimitive.content)
        assertFalse("signature" in sent.json || "challenge" in sent.json)
        assertEquals("# Plans\nsee you", vault.opened(sent.json))
        assertTrue(result.created)
        assertFalse(sent.body.toString().contains("see you"))
    }

    @Test
    fun countsCodePointsOfWhatTheUserSeesAndRefusesBeforeAnyRequest() = runTest {
        val vault = TestVault()
        assertEquals(5, noteCharacterCount("- [x] 🙂🙂ab\n"))
        assertEquals(MAX_NOTE_CHARACTERS, noteCharacterCount("🙂".repeat(MAX_NOTE_CHARACTERS)))
        vault.server.answer { data(storedRow(it.json), 201) }
        createNote(vault.context, "🙂".repeat(MAX_NOTE_CHARACTERS))
        assertFailsWith<ItemTooLargeException> { createNote(vault.context, "a".repeat(MAX_NOTE_CHARACTERS + 1)) }
        val markedUp = "- [ ] {{12}}a{{/}}\n".repeat(2499)
        assertTrue(noteCharacterCount(markedUp) < MAX_NOTE_CHARACTERS)
        assertFailsWith<ItemTooLargeException> { createNote(vault.context, markedUp) }
        assertEquals(1, vault.server.sent.size)
    }

    @Test
    fun anEditKeepsTheDekAndTheWrappedDekByteForByte() = runTest {
        val vault = TestVault()
        val id = newItemId(primitives)
        vault.server.answer { data(storedRow(it.json), 201) }
        val created = createNote(vault.context, "first", id).note
        vault.server.answer { data(storedRow(JsonObject(it.json + ("id" to JsonPrimitive(id))))) }
        updateNote(vault.context, created, "second")
        val put = vault.server.sent.last()
        assertEquals("PUT" to "/notes/$id", put.method to put.path)
        assertEquals(created.wrappedDek, put.json.getValue("wrapped_dek").jsonPrimitive.content)
        assertFalse("id" in put.json)
        val dek = openSecretBlob(created.wrappedDek, vault.session.kek(Scope.NOTES, 1), primitives)
        assertEquals("second", openText(put.json.getValue("ciphertext").jsonPrimitive.content, dek, primitives))
    }

    @Test
    fun anEditOfANoteWrittenUnderAnOlderGenerationReWrapsTheSameDek() = runTest {
        val vault = TestVault(mapOf(Scope.NOTES to 2))
        val dek = generateScopeKek(primitives)
        val old = buildJsonObject {
            put("ciphertext", sealText("old", dek, primitives))
            put("wrapped_dek", sealSecretBlob(dek, vault.session.kek(Scope.NOTES, 1), primitives))
            put("key_generation", 1)
            put("version", "v1")
        }
        val id = newItemId(primitives)
        vault.server.answer { data(storedRow(JsonObject(it.json + ("id" to JsonPrimitive(id))))) }
        updateNote(vault.context, record(old, id), "new")
        val put = vault.server.sent.single().json
        assertEquals(2, put.getValue("key_generation").jsonPrimitive.int)
        val rewrapped = openSecretBlob(put.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.NOTES, 2), primitives)
        assertContentEquals(dek.withBytes { it.copyOf() }, rewrapped.withBytes { it.copyOf() })
    }

    @Test
    fun aSaveAnsweredWithTheStoredRowIsFollowedByAnEditCarryingTheNewerText() = runTest {
        val vault = TestVault()
        val id = newItemId(primitives)
        val stale = buildJsonObject {
            val dek = generateScopeKek(primitives)
            put("ciphertext", sealText("older", dek, primitives))
            put("wrapped_dek", sealSecretBlob(dek, vault.session.kek(Scope.NOTES, 1), primitives))
            put("key_generation", 1)
            put("version", "v1")
        }
        vault.server.answer { data(storedRow(JsonObject(stale + ("id" to JsonPrimitive(id))))) }
        vault.server.answer { data(storedRow(JsonObject(it.json + ("id" to JsonPrimitive(id))))) }
        saveNote(vault.context, "newer", id)
        assertEquals(listOf("POST", "PUT"), vault.server.sent.map { it.method })
        val put = vault.server.sent.last().json
        assertEquals(stale.getValue("wrapped_dek"), put.getValue("wrapped_dek"))
        assertEquals("newer", vault.opened(put))

        vault.server.answer { data(storedRow(it.json), 201) }
        saveNote(vault.context, "fresh", newItemId(primitives))
        assertEquals(3, vault.server.sent.size)
    }

    @Test
    fun aBatchDeleteSignsTheSortedDistinctIdsItSends() = runTest {
        val vault = TestVault()
        val ids = listOf("ba7816bf-8f01-4fea-9411-2b4c3f5a1e77", "0c892e57-93cf-423a-a9e9-fee5a9f87681", "ba7816bf-8f01-4fea-9411-2b4c3f5a1e77")
        vault.server.reply(data(buildJsonObject { put("requested", 2); put("deleted", 1) }))
        val result = deleteNotes(vault.context, ids)
        val body = vault.server.sent.single().json
        val sorted = ids.toSet().sorted()
        assertEquals(sorted, body.getValue("ids").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(vault.verifies(body, Action.NOTE_DELETE, sorted))
        val submittedOrder = listOf(body.getValue("challenge").jsonPrimitive.content, body.getValue("timestamp").jsonPrimitive.content, "note-delete") + ids.distinct()
        assertFalse(verifyPayload(submittedOrder.joinToString(":"), body.getValue("signature").jsonPrimitive.content, spkiBase64ToUncompressedPoint(vault.device.signingPublicKey), primitives))
        assertEquals(1, result.deleted)
        assertFailsWith<EmptySelectionException> { deleteNotes(vault.context, emptyList()) }
        assertFailsWith<IllegalArgumentException> { deleteNotes(vault.context, listOf("NOT-A-UUID")) }
        assertEquals(1, vault.server.sent.size)
    }

    @Test
    fun aSingleDeleteIsTheOneElementCase() = runTest {
        val vault = TestVault()
        val id = newItemId(primitives)
        vault.server.reply(data(JsonArray(emptyList()), 200))
        deleteNote(vault.context, id)
        val sent = vault.server.sent.single()
        assertEquals("DELETE" to "/notes/$id", sent.method to sent.path)
        assertTrue(vault.verifies(sent.json, Action.NOTE_DELETE, listOf(id)))
    }

    @Test
    fun namesAndDrawsANoteFromWhatTheUserSees() {
        assertEquals("Letter to Ana", noteTitle("\n- [ ] \n# Letter to **Ana**\nbody"))
        assertNull(noteTitle("- \n- [ ] \n   "))
        assertTrue(isNoteEmpty("- \n- [ ] \n"))
        assertEquals("a".repeat(NOTE_TITLE_MAX_CHARACTERS) + "…", noteTitle("a".repeat(NOTE_TITLE_MAX_CHARACTERS + 5)))
        assertEquals("🙂".repeat(NOTE_TITLE_MAX_CHARACTERS) + "…", noteTitle("🙂".repeat(NOTE_TITLE_MAX_CHARACTERS + 1)))
        assertEquals("one\n\ntwo\n☑ done", noteThumbnail("one\n\n\n\n\ntwo\n- [x] done"))
        assertTrue(isNoteSavable("text", "other"))
        assertFalse(isNoteSavable("text", "text"))
    }

    @Test
    fun tilesComeNewestFirstAndANoteThatWillNotOpenIsUnreadable() = runTest {
        val vault = TestVault()
        fun item(text: String, updatedAt: String, key: Boolean = true): ReplicaItem {
            val dek = generateScopeKek(primitives)
            val kek = if (key) vault.session.kek(Scope.NOTES, 1) else generateScopeKek(primitives)
            val id = newItemId(primitives)
            val row = buildJsonObject {
                put("id", id)
                put("ciphertext", sealText(text, dek, primitives))
                put("wrapped_dek", sealSecretBlob(dek, kek, primitives))
                put("key_generation", 1)
                put("version", "v1")
                put("created_at", "2026-10-01T00:00:00Z")
                put("updated_at", updatedAt)
            }
            return ReplicaItem(id, 1, row)
        }
        val tiles = noteTiles(
            vault.context,
            listOf(item("older", "2026-10-02T00:00:00Z"), item("# Newest\nbody", "2026-10-03T00:00:00Z"), item("lost", "2026-10-01T00:00:00Z", key = false)),
        )
        assertEquals(listOf("Newest", "older", null), tiles.map { it.title })
        assertEquals(listOf(true, true, false), tiles.map { it.readable })
        assertEquals("Newest\nbody", tiles.first().thumbnail)
    }
}
