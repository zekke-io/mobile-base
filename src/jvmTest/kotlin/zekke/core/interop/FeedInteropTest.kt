package zekke.core.interop

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.account.removeOtherDevices
import zekke.core.api.Method
import zekke.core.auth.putEnvelope
import zekke.core.device.generateDeviceId
import zekke.core.feed.Feed
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Outbox
import zekke.core.feed.OutboxRewrap
import zekke.core.feed.OutboxState
import zekke.core.feed.Replica
import zekke.core.feed.outboxSchema
import zekke.core.feed.replicaSchema
import zekke.core.keyrings.generateScopeKek
import zekke.core.memory.SecretBytes
import zekke.core.scopes.Scope
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.openText
import zekke.core.sealed.sealSecretBlob
import zekke.core.sealed.sealText
import zekke.core.session.SessionKeystore
import zekke.core.signing.Action
import zekke.core.signing.signActionEnvelope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FeedInteropTest {
    private fun pin(digits: String) = digits.toCharArray()

    private class SealedNote(val body: JsonObject, val dek: SecretBytes)

    private fun sealNote(session: SessionKeystore, id: String, text: String, dek: SecretBytes = generateScopeKek()): SealedNote {
        val current = session.currentKek(Scope.NOTES)
        val body = buildJsonObject {
            put("id", id)
            put("ciphertext", sealText(text, dek))
            put("wrapped_dek", sealSecretBlob(dek, current.kek))
            put("key_generation", current.generation)
        }
        return SealedNote(body, dek)
    }

    private fun openNote(session: SessionKeystore, item: JsonObject): String {
        val kek = session.kek(Scope.NOTES, item.getValue("key_generation").jsonPrimitive.int)
        return openSecretBlob(item.getValue("wrapped_dek").jsonPrimitive.content, kek).use { dek ->
            openText(item.getValue("ciphertext").jsonPrimitive.content, dek)
        }
    }

    private fun replicaOf(phone: Phone) = Replica(JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { replicaSchema.create(it) }, phone.services.session.userAddress)

    private fun notesIn(replica: Replica) = replica.items(FeedScope.NOTES, ItemTypes.NOTE)

    @Test
    fun aWriteFromAnotherDeviceArrivesByCursorAndAResetResyncs() = runBlocking {
        val words = newPhrase()
        val phone = Phone()
        patiently { completeSignUp(phone.services, draftSignUp(phraseCopy(words)), pin("428193"), paranoid = false) }
        val feed = Feed(replicaOf(phone).also { replica = it }, phone.services.session, phone.api, CoroutineScope(Dispatchers.Default))
        try {
            val other = Phone()
            patiently { enrolThisDevice(other.services, phraseCopy(words), pin("739164")) }
            patiently { feed.sync(FeedScope.NOTES) }
            assertEquals(0, notesIn(replica).size)

            val id = generateDeviceId()
            val created = sealNote(other.services.session, id, "first draft")
            patiently { other.api.request(Method.POST, "/notes", body = created.body, token = other.api.tokens.require()) }
            assertTrue(patiently { feed.sync(FeedScope.NOTES) })
            val arrived = notesIn(replica).single()
            assertEquals(id, arrived.id)
            assertEquals("first draft", openNote(phone.services.session, arrived.item))

            val edited = sealNote(other.services.session, id, "second draft", created.dek)
            patiently { other.api.request(Method.PUT, "/notes/$id", body = JsonObject(edited.body - "id"), token = other.api.tokens.require()) }
            assertTrue(patiently { feed.sync(FeedScope.NOTES) })
            val updated = notesIn(replica).single()
            assertTrue(updated.seq > arrived.seq)
            assertEquals("second draft", openNote(phone.services.session, updated.item))

            val kept = generateDeviceId()
            patiently { other.api.request(Method.POST, "/notes", body = sealNote(other.services.session, kept, "kept").body, token = other.api.tokens.require()) }
            val envelope = signActionEnvelope(Action.NOTE_DELETE, listOf(id), other.services.session.signer())
            patiently { other.api.request(Method.DELETE, "/notes/$id", body = buildJsonObject { putEnvelope(envelope) }, token = other.api.tokens.require()) }
            assertTrue(patiently { feed.sync(FeedScope.NOTES) })
            assertEquals(listOf(kept), notesIn(replica).map { it.id })

            replica.forceCursor(FeedScope.NOTES, 1_000_000_000)
            assertTrue(patiently { feed.sync(FeedScope.NOTES) })
            assertEquals(listOf(kept), notesIn(replica).map { it.id })
            assertTrue(replica.cursor(FeedScope.NOTES) in 1 until 1_000_000_000)
        } finally {
            feed.close()
            deleteWithPhrase(phone, words)
        }
    }

    @Test
    fun aReplayThroughTheOutboxCreatesOneItemAndAStaleWriteWaitsForItsRewrap() = runBlocking {
        val words = newPhrase()
        val phone = Phone()
        patiently { completeSignUp(phone.services, draftSignUp(phraseCopy(words)), pin("428193"), paranoid = false) }
        val session = phone.services.session
        val outbox = Outbox(JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { outboxSchema.create(it) }, session.userAddress)
        val feed = Feed(replicaOf(phone).also { replica = it }, session, phone.api, CoroutineScope(Dispatchers.Default))
        try {
            val id = generateDeviceId()
            val note = sealNote(session, id, "written offline")
            outbox.enqueue(id, FeedScope.NOTES, Method.POST, "/notes", note.body, 1)
            assertEquals(1, patiently { outbox.flush(phone.api) }.sent)
            outbox.enqueue(id, FeedScope.NOTES, Method.POST, "/notes", note.body, 1)
            assertEquals(1, patiently { outbox.flush(phone.api) }.sent)
            patiently { feed.sync(FeedScope.NOTES) }
            assertEquals(listOf(id), notesIn(replica).map { it.id })

            val other = Phone()
            patiently { enrolThisDevice(other.services, phraseCopy(words), pin("739164")) }
            val late = generateDeviceId()
            val lateNote = sealNote(session, late, "sealed under generation 1")
            outbox.enqueue(late, FeedScope.NOTES, Method.POST, "/notes", lateNote.body, 1)
            patiently { removeOtherDevices(phone.services, phraseCopy(words), listOf(other.services.session.deviceId)) }
            assertEquals(2, session.currentGeneration(Scope.NOTES))

            val refused = patiently { outbox.flush(phone.api) }
            assertEquals(1, refused.waitingForRewrap)
            outbox.rewrapStale { entry ->
                val dek = openSecretBlob(entry.body.getValue("wrapped_dek").jsonPrimitive.content, session.kek(Scope.NOTES, entry.keyGeneration))
                val current = session.currentKek(Scope.NOTES)
                val body = JsonObject(entry.body + mapOf(
                    "wrapped_dek" to kotlinx.serialization.json.JsonPrimitive(sealSecretBlob(dek, current.kek)),
                    "key_generation" to kotlinx.serialization.json.JsonPrimitive(current.generation),
                ))
                dek.zero()
                OutboxRewrap(body, current.generation)
            }
            assertEquals(OutboxState.PENDING, outbox.entries().single().state)
            assertEquals(1, patiently { outbox.flush(phone.api) }.sent)

            patiently { feed.sync(FeedScope.NOTES) }
            val stored = notesIn(replica).associateBy { it.id }
            assertEquals(setOf(id, late), stored.keys)
            assertEquals(2, stored.getValue(late).item.getValue("key_generation").jsonPrimitive.int)
            assertEquals("sealed under generation 1", openNote(session, stored.getValue(late).item))
        } finally {
            feed.close()
            deleteWithPhrase(phone, words)
        }
    }

    private lateinit var replica: Replica
}
