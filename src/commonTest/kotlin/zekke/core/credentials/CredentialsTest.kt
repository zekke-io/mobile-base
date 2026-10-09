package zekke.core.credentials

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import zekke.core.api.wireJson
import zekke.core.feed.ReplicaItem
import zekke.core.items.ItemTooLargeException
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.newItemId
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.Scope
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.sealSecretBlob
import zekke.core.sealed.sealText
import zekke.core.signing.Action
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CredentialsTest {
    private val credentialA = "0c892e57-93cf-423a-a9e9-fee5a9f87681"

    private fun revision(credentialId: String, seq: Long, deleted: Boolean = false, createdAt: String = "2026-10-0${seq}T00:00:00Z") =
        CredentialRevision(credentialId, newItemId(primitives), seq, "c", "w", 1, "v1", createdAt, deleted)

    private fun echo(body: kotlinx.serialization.json.JsonObject, status: Int = 201) = data(
        kotlinx.serialization.json.JsonObject(body + mapOf("seq" to JsonPrimitive(7), "created_at" to JsonPrimitive("2026-10-09T00:00:00Z"))),
        status,
    )

    @Test
    fun thePayloadIsTheWebAppsAndKeepsWhatItDoesNotKnow() {
        val written = "{\"later\":{\"x\":1},\"site\":\"example.com\",\"username\":\"ana\",\"password\":\"p\",\"urls\":[\"a.example.com\"],\"match\":\"host\"}"
        val payload = decodeCredentialPayload(written)
        assertEquals(listOf("a.example.com"), payload.urls)
        assertEquals(SiteMatch.HOST, payload.match)
        assertEquals(written, encodeCredentialPayload(payload))
        assertEquals(
            "{\"site\":\"s\",\"username\":\"u\",\"password\":\"p\"}",
            encodeCredentialPayload(CredentialPayload("s", "u", "p", note = "", urls = listOf("  "), match = SiteMatch.DOMAIN)),
        )
        for (bad in listOf("[]", "{\"site\":\"s\",\"username\":\"u\"}", "{\"site\":\"s\",\"username\":\"u\",\"password\":\"p\",\"note\":3}",
            "{\"site\":\"s\",\"username\":\"u\",\"password\":\"p\",\"urls\":[1]}", "{\"site\":\"s\",\"username\":\"u\",\"password\":\"p\",\"match\":\"path\"}")) {
            assertFailsWith<MalformedCredentialPayloadException>(bad) { decodeCredentialPayload(bad) }
        }
    }

    @Test
    fun aWriteIsAnAppendCarryingBothIdsUnderThePasswordsKek() = runTest {
        val vault = TestVault(mapOf(Scope.PASSWORDS to 2))
        vault.server.answer { echo(it.json) }
        vault.server.answer { echo(it.json, 200) }
        val first = writeCredential(vault.context, "{}", credentialId = credentialA)
        val replay = writeCredential(vault.context, "{}", credentialId = credentialA, revisionId = first.revision.revisionId)
        val (a, b) = vault.server.sent
        assertEquals("POST" to "/credentials", a.method to a.path)
        assertEquals(credentialA, a.json.getValue("credential_id").jsonPrimitive.content)
        assertEquals(2, a.json.getValue("key_generation").jsonPrimitive.int)
        assertEquals(a.json.getValue("revision_id"), b.json.getValue("revision_id"))
        assertTrue(first.created)
        assertFalse(replay.created)
        openSecretBlob(a.json.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.PASSWORDS, 2), primitives)
        assertFailsWith<IllegalStateException> {
            openSecretBlob(a.json.getValue("wrapped_dek").jsonPrimitive.content, vault.session.kek(Scope.SECRETS, 1), primitives)
        }
        assertFailsWith<ItemTooLargeException> { writeCredential(vault.context, "x".repeat(MAX_CREDENTIAL_PLAINTEXT_BYTES + 1)) }
    }

    @Test
    fun anEditMintsANewRevisionOfTheSameCredential() = runTest {
        val vault = TestVault()
        vault.server.answer { echo(it.json) }
        vault.server.answer { echo(it.json) }
        writeCredential(vault.context, "{}", credentialId = credentialA)
        writeCredential(vault.context, "{}", credentialId = credentialA)
        val (a, b) = vault.server.sent.map { it.json }
        assertEquals(a.getValue("credential_id"), b.getValue("credential_id"))
        assertNotEquals(a.getValue("revision_id"), b.getValue("revision_id"))
    }

    @Test
    fun eachDestructiveCallSignsExactlyWhatItDestroys() = runTest {
        val vault = TestVault()
        vault.server.reply(data(buildJsonObject {}, 200))
        vault.server.reply(data(buildJsonObject { put("pruned", 3) }))
        deleteCredential(vault.context, credentialA)
        val pruned = pruneCredential(vault.context, credentialA, PURGE_KEEP_LAST)
        val (delete, prune) = vault.server.sent
        assertEquals("DELETE" to "/credentials/$credentialA", delete.method to delete.path)
        assertTrue(vault.verifies(delete.json, Action.CREDENTIAL_DELETE, listOf(credentialA)))
        assertEquals("POST" to "/credentials/$credentialA/prune", prune.method to prune.path)
        assertEquals(1, prune.json.getValue("keep_last").jsonPrimitive.int)
        assertTrue(vault.verifies(prune.json, Action.CREDENTIAL_PRUNE, listOf(credentialA, "1")))
        assertFalse(vault.verifies(prune.json, Action.CREDENTIAL_PRUNE, listOf(credentialA, "2")))
        assertEquals(3, pruned.pruned)
    }

    @Test
    fun recentlyDeletedIsEachCredentialWhoseNewestRevisionIsATombstone() {
        val other = newItemId(primitives)
        val purged = newItemId(primitives)
        val revisions = listOf(
            revision(credentialA, 1),
            revision(credentialA, 2),
            revision(credentialA, 3, deleted = true),
            revision(other, 4),
            revision(purged, 5, deleted = true),
        )
        val deleted = deletedCredentials(revisions).single()
        assertEquals(credentialA, deleted.credentialId)
        assertEquals(2, deleted.lastLive.seq)
        assertEquals(listOf(other), currentRevisions(revisions).map { it.credentialId })
        assertEquals(listOf(2L, 1L), credentialHistory(revisions, credentialA).map { it.seq })
    }

    @Test
    fun namesASiteByItsHost() {
        assertEquals("example.com", siteLabel("https://www.Example.com/login?x=1"))
        assertEquals("accounts.example.com", siteLabel("accounts.example.com/path"))
        assertEquals("example.com", siteLabel("user@example.com:8443"))
        assertEquals("my bank", siteLabel(" my bank "))
        assertEquals("", siteLabel("  "))
    }

    @Test
    fun thePasswordsViewSortsBySiteThenUsernameAndListsWhatWasDeleted() = runTest {
        val vault = TestVault()
        fun item(credentialId: String, seq: Long, payload: CredentialPayload?, deleted: Boolean = false): ReplicaItem {
            val dek = generateScopeKek(primitives)
            val revision = CredentialRevision(
                credentialId,
                newItemId(primitives),
                seq,
                sealText(payload?.let(::encodeCredentialPayload) ?: "{}", dek, primitives),
                sealSecretBlob(dek, vault.session.kek(Scope.PASSWORDS, 1), primitives),
                1,
                "v1",
                "2026-10-0${seq}T00:00:00Z",
                deleted,
            )
            return ReplicaItem(revision.revisionId, seq, wireJson.encodeToJsonElement(CredentialRevision.serializer(), revision) as kotlinx.serialization.json.JsonObject)
        }
        val b = newItemId(primitives)
        val c = newItemId(primitives)
        val view = passwordsView(
            vault.context,
            listOf(
                item(credentialA, 1, CredentialPayload("zeta.com", "ana", "old")),
                item(credentialA, 2, CredentialPayload("zeta.com", "ana", "new")),
                item(b, 3, CredentialPayload("Alpha.com", "bob", "p")),
                item(c, 4, CredentialPayload("alpha.com", "ana", "p")),
                item(c, 5, CredentialPayload("alpha.com", "ana", "p")),
                item(c, 6, null, deleted = true),
            ),
        )
        assertEquals(listOf("Alpha.com" to "bob", "zeta.com" to "ana"), view.rows.map { it.site to it.username })
        assertEquals("new", view.rows.last().password)
        val gone = view.deleted.single()
        assertEquals(c, gone.id)
        assertEquals("alpha.com", gone.site)
        assertEquals(5, gone.deleted.lastLive.seq)
        assertNull(view.rows.firstOrNull { it.id == c })
    }
}
