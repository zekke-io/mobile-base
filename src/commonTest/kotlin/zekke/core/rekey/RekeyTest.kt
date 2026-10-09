package zekke.core.rekey

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.failure
import zekke.core.items.newItemId
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import zekke.core.sealed.openBlob
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.sealBlob
import zekke.core.sealed.sealSecretBlob
import zekke.core.signing.Action
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RekeyTest {
    private fun TestVault.wrapped(id: String, generation: Int, dek: zekke.core.memory.SecretBytes = generateScopeKek(primitives), scope: Scope = Scope.SECRETS) = buildJsonObject {
        put("id", id)
        put("wrapped_dek", sealSecretBlob(dek, session.kek(scope, generation), primitives))
        put("key_generation", generation)
        put("ciphertext_sha256", "x")
        put("ciphertext_bytes", 1)
        put("version", "v1")
        put("ciphertext", "x")
        put("created_at", "t")
        put("updated_at", "t")
    }

    private fun answered(rekeyed: Int) = data(buildJsonObject { put("requested", rekeyed); put("rekeyed", rekeyed) })

    @Test
    fun keepsOnlyWhatIsBelowTheCurrentGenerationInIdOrder() {
        val items = listOf(WrappedItem("c", "w", 1), WrappedItem("a", "w", 2), WrappedItem("b", "w", 1), WrappedItem("b", "w", 1))
        assertEquals(listOf("b", "c"), staleItems(items, 2).map { it.id })
        assertTrue(staleItems(items, 1).isEmpty())
    }

    @Test
    fun secretsAreWalkedWithRecentlyDeletedAndReWrappedUnderTheCurrentGenerationWithTheSameDek() = runTest {
        val vault = TestVault(mapOf(Scope.SECRETS to 2))
        val dek = generateScopeKek(primitives)
        val stale = newItemId(primitives)
        val deleted = newItemId(primitives)
        val current = newItemId(primitives)
        vault.server.reply(data(JsonArray(listOf(vault.wrapped(stale, 1, dek), vault.wrapped(current, 2)))))
        vault.server.reply(data(JsonArray(listOf(JsonObject(vault.wrapped(deleted, 1) + ("deleted_at" to kotlinx.serialization.json.JsonPrimitive("t")))))))
        vault.server.reply(answered(2))
        val outcome = rewrapScope(vault.context, Scope.SECRETS)
        assertEquals(2, outcome.requested)
        val put = vault.server.sent.last()
        assertEquals("PUT" to "/secrets/keys", put.method to put.path)
        assertEquals(2, put.json.getValue("key_generation").jsonPrimitive.int)
        val items = put.json.getValue("items").jsonArray.map { it.jsonObject }
        val sorted = listOf(stale, deleted).sorted()
        assertEquals(sorted, items.map { it.getValue("id").jsonPrimitive.content })
        assertTrue(vault.verifies(put.json, Action.SECRET_REKEY, sorted))
        val moved = items.single { it.getValue("id").jsonPrimitive.content == stale }.getValue("wrapped_dek").jsonPrimitive.content
        assertContentEquals(dek.withBytes { it.copyOf() }, openSecretBlob(moved, vault.session.kek(Scope.SECRETS, 2), primitives).withBytes { it.copyOf() })
    }

    @Test
    fun passwordsAreWalkedByRevisionInBatchesOfAHundred() = runTest {
        val vault = TestVault(mapOf(Scope.PASSWORDS to 2))
        val revisions = (1..150).map { newItemId(primitives) }
        vault.server.reply(data(buildJsonArray {
            revisions.forEach { id ->
                addJsonObject {
                    put("credential_id", newItemId(primitives))
                    put("revision_id", id)
                    put("wrapped_dek", sealSecretBlob(generateScopeKek(primitives), vault.session.kek(Scope.PASSWORDS, 1), primitives))
                    put("key_generation", 1)
                    put("created_at", "t")
                }
            }
        }))
        vault.server.reply(answered(100), answered(50))
        val outcome = rewrapScope(vault.context, Scope.PASSWORDS)
        assertEquals(150, outcome.rekeyed)
        val puts = vault.server.sent.drop(1)
        assertEquals(listOf(100, 50), puts.map { it.json.getValue("items").jsonArray.size })
        assertTrue(puts.all { it.path == "/credentials/keys" })
        assertTrue(puts.first().json.getValue("items").jsonArray.first().jsonObject.containsKey("revision_id"))
        assertTrue(vault.verifies(puts.last().json, Action.CREDENTIAL_REKEY, revisions.sorted().drop(100)))
    }

    @Test
    fun thePreferencesAreReSealedAsTheyAreWithoutBeingRead() = runTest {
        val vault = TestVault(mapOf(Scope.DOCUMENTS to 2))
        val plaintext = "{\"version\":1,\"regional\":{\"country\":\"PT\",\"later\":true}}".encodeToByteArray()
        val dek = generateScopeKek(primitives)
        vault.server.reply(data(buildJsonObject {
            put("ciphertext", sealBlob(plaintext, dek, primitives))
            put("wrapped_dek", sealSecretBlob(dek, vault.session.kek(Scope.DOCUMENTS, 1), primitives))
            put("key_generation", 1)
            put("revision", 7)
        }))
        vault.server.reply(data(buildJsonObject {}))
        assertTrue(resealPreferences(vault.context))
        val put = vault.server.sent.last().json
        assertEquals(2, put.getValue("key_generation").jsonPrimitive.int)
        assertEquals(7, put.getValue("expected_revision").jsonPrimitive.int)
        val reopened = openSecretBlob(put.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.DOCUMENTS, 2), primitives).use {
            openBlob(put.getValue("ciphertext").jsonPrimitive.content, it, primitives)
        }
        assertContentEquals(plaintext, reopened)
        assertTrue(vault.verifies(put, Action.PREFERENCES_UPDATE, listOf("7", zekke.core.items.hashReceivedCiphertext(put.getValue("ciphertext").jsonPrimitive.content, primitives))))

        vault.server.reply(failure(404, "NOT_FOUND"))
        assertFalse(resealPreferences(vault.context))
    }
}
