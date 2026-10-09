package zekke.core.secrets

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import zekke.core.feed.ReplicaItem
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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecretsTest {
    private val idA = "0c892e57-93cf-423a-a9e9-fee5a9f87681"
    private val idB = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

    @Test
    fun theNameAndValueEnvelopeIsTheWebAppsAndRefusesAnythingElse() {
        val encoded = encodeSecretPayload(SecretPayload("Bank", "seed words \"quoted\""))
        assertEquals("{\"name\":\"Bank\",\"value\":\"seed words \\\"quoted\\\"\"}", encoded)
        assertEquals("Bank", decodeSecretPayload(encoded).name)
        assertEquals("v", decodeSecretPayload("{\"value\":\"v\",\"name\":\"n\",\"later\":1}").value)
        for (bad in listOf("not json", "[]", "{\"name\":\"n\"}", "{\"name\":1,\"value\":\"v\"}", "null")) {
            assertFailsWith<MalformedSecretPayloadException>(bad) { decodeSecretPayload(bad) }
        }
    }

    @Test
    fun aCreateSendsTheCurrentGenerationAndADekThatOpensUnderItsScopeOnly() = runTest {
        val vault = TestVault(mapOf(Scope.SECRETS to 3))
        vault.server.answer { data(storedRow(it.json), 201) }
        val result = createSecret(vault.context, encodeSecretPayload(SecretPayload("n", "v")), idA)
        val body = vault.server.sent.single().json
        assertEquals(3, body.getValue("key_generation").jsonPrimitive.int)
        val dek = openSecretBlob(body.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.SECRETS, 3), primitives)
        assertEquals("{\"name\":\"n\",\"value\":\"v\"}", openText(body.getValue("ciphertext").jsonPrimitive.content, dek, primitives))
        assertFailsWith<IllegalStateException> {
            openSecretBlob(body.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.NOTES, 1), primitives)
        }
        assertTrue(result.created)
        assertEquals(idA, result.secret.id)
    }

    @Test
    fun aReplayIsNotCreatedAndAnOversizedSecretIsRefusedLocally() = runTest {
        val vault = TestVault()
        vault.server.answer { data(storedRow(it.json)) }
        assertFalse(createSecret(vault.context, "x", idA).created)
        assertFailsWith<ItemTooLargeException> { createSecret(vault.context, "x".repeat(MAX_SECRET_PLAINTEXT_BYTES + 1)) }
        assertEquals(1, vault.server.sent.size)
    }

    @Test
    fun aDeleteAndAPurgeAreDifferentSignedActions() = runTest {
        val vault = TestVault()
        vault.server.reply(data(buildJsonObject { put("requested", 2); put("deleted", 2) }))
        vault.server.reply(data(buildJsonObject { put("requested", 1); put("purged", 1) }))
        deleteSecrets(vault.context, listOf(idB, idA))
        purgeSecrets(vault.context, listOf(idA))
        val (delete, purge) = vault.server.sent
        assertEquals("DELETE" to "/secrets", delete.method to delete.path)
        assertEquals(listOf(idA, idB), delete.json.getValue("ids").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(vault.verifies(delete.json, Action.SECRET_DELETE, listOf(idA, idB)))
        assertEquals("DELETE" to "/secrets/deleted", purge.method to purge.path)
        assertTrue(vault.verifies(purge.json, Action.SECRET_PURGE, listOf(idA)))
        assertFalse(vault.verifies(purge.json, Action.SECRET_DELETE, listOf(idA)))
    }

    @Test
    fun aRestoreIsUnsignedWithNoBody() = runTest {
        val vault = TestVault()
        vault.server.reply(data(storedRow(buildJsonObject {
            put("id", idA)
            put("ciphertext", "x")
            put("wrapped_dek", "y")
            put("key_generation", 1)
            put("version", "v1")
        })))
        restoreSecret(vault.context, idA)
        val sent = vault.server.sent.single()
        assertEquals("POST" to "/secrets/$idA/restore", sent.method to sent.path)
        assertEquals(null, sent.body)
    }

    @Test
    fun theVaultViewSplitsOnDeletedAtAndKeepsAnUnreadableRow() = runTest {
        val vault = TestVault()
        fun item(id: String, payload: String, updatedAt: String, deletedAt: String? = null, kek: Boolean = true): ReplicaItem {
            val dek = generateScopeKek(primitives)
            val row = buildJsonObject {
                put("id", id)
                put("ciphertext", sealText(payload, dek, primitives))
                put("wrapped_dek", sealSecretBlob(dek, if (kek) vault.session.kek(Scope.SECRETS, 1) else generateScopeKek(primitives), primitives))
                put("key_generation", 1)
                put("version", "v1")
                put("created_at", "2026-10-01T00:00:00Z")
                put("updated_at", updatedAt)
                if (deletedAt != null) put("deleted_at", deletedAt)
            }
            return ReplicaItem(id, 1, JsonObject(row))
        }
        val view = vaultView(
            vault.context,
            listOf(
                item(newItemId(primitives), encodeSecretPayload(SecretPayload("old", "1")), "2026-10-02T00:00:00Z"),
                item(newItemId(primitives), encodeSecretPayload(SecretPayload("new", "2")), "2026-10-03T00:00:00Z"),
                item(newItemId(primitives), "not an envelope", "2026-10-01T00:00:00Z"),
                item(newItemId(primitives), encodeSecretPayload(SecretPayload("gone", "3")), "2026-10-02T00:00:00Z", "2026-10-04T00:00:00Z"),
                item(newItemId(primitives), encodeSecretPayload(SecretPayload("lost", "4")), "2026-10-02T00:00:00Z", kek = false),
            ),
        )
        assertEquals(listOf("new", "old", "", ""), view.rows.map { it.name })
        assertEquals(listOf(true, true, false, false), view.rows.map { it.readable })
        assertEquals("2", view.rows.first().value)
        assertEquals(listOf("gone"), view.deleted.map { it.name })
        assertEquals("2026-10-04T00:00:00Z", view.deleted.single().deletedAt)
    }
}
