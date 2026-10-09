package zekke.core.feed

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.Method
import zekke.core.api.TokenStore
import zekke.core.api.ZekkeApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class OutboxTest {
    private val driver = outboxDriver()
    private val outbox = Outbox(driver, ACCOUNT)
    private val sent = mutableListOf<String>()
    private val id1 = "11111111-1111-4111-8111-111111111111"
    private val id2 = "22222222-2222-4222-8222-222222222222"

    private fun api(respond: (Int) -> Pair<HttpStatusCode, String>): ZekkeApi {
        val tokens = TokenStore { 0 }.also { it.set("token") }
        return ZekkeApi(
            baseUrl = "http://api.test",
            tokens = tokens,
            httpClient = HttpClient(MockEngine { request ->
                sent += request.url.encodedPath
                if (request.url.encodedPath.contains("offline")) throw IOException("down")
                val (status, body) = respond(sent.size)
                respond(body, status, headersOf(HttpHeaders.ContentType, "application/json"))
            }),
        )
    }

    private fun note(id: String, generation: Int = 1) =
        outbox.enqueue(id, FeedScope.NOTES, Method.POST, "/notes", buildJsonObject { put("id", id); put("ciphertext", "c"); put("key_generation", generation) }, generation)

    @Test
    fun sendsInOrderAndForgetsWhatWasStored() = runTest {
        note(id1)
        note(id2)
        val flush = outbox.flush(api { HttpStatusCode.Created to "{\"data\":{}}" })
        assertEquals(2, flush.sent)
        assertEquals(OutboxStop.Drained, flush.stop)
        assertEquals(listOf("/notes", "/notes"), sent)
        assertEquals(0, outbox.entries().size)
    }

    @Test
    fun aStaleGenerationWaitsForTheNextUnlockToRewrapIt() = runTest {
        note(id1)
        val flush = outbox.flush(api { HttpStatusCode.Conflict to "{\"code\":\"STALE_KEY_GENERATION\"}" })
        assertEquals(1, flush.waitingForRewrap)
        assertEquals(OutboxState.NEEDS_REWRAP, outbox.entries().single().state)

        outbox.rewrapStale { entry -> OutboxRewrap(buildJsonObject { put("id", entry.itemId); put("key_generation", 2) }, 2) }
        val entry = outbox.entries().single()
        assertEquals(OutboxState.PENDING, entry.state)
        assertEquals(2, entry.keyGeneration)
        assertEquals(JsonPrimitive(2), entry.body["key_generation"])
    }

    @Test
    fun goingOfflineStopsAndKeepsEveryEntry() = runTest {
        outbox.enqueue(id1, FeedScope.NOTES, Method.POST, "/offline", buildJsonObject { put("id", id1) }, 1)
        note(id2)
        val flush = outbox.flush(api { HttpStatusCode.Created to "{}" })
        assertEquals(OutboxStop.Offline, flush.stop)
        assertEquals(2, outbox.entries().size)
        assertEquals(1L, outbox.entries().first().attempts)
    }

    @Test
    fun aRateLimitStopsAndARefusalIsSetAside() = runTest {
        note(id1)
        note(id2)
        val flush = outbox.flush(api { call -> if (call == 1) HttpStatusCode.BadRequest to "{\"code\":\"BAD_REQUEST\"}" else HttpStatusCode.TooManyRequests to "{}" })
        assertIs<OutboxStop.RateLimited>(flush.stop)
        assertEquals(listOf(OutboxState.REFUSED, OutboxState.PENDING), outbox.entries().map { it.state })
    }

    @Test
    fun aSignedActionNeverEntersTheOutbox() {
        assertFailsWith<SignedActionInOutboxException> {
            outbox.enqueue(id1, FeedScope.NOTES, Method.DELETE, "/notes/$id1", buildJsonObject { put("signature", "s") }, 1)
        }
        assertFailsWith<SignedActionInOutboxException> {
            outbox.enqueue(id1, FeedScope.NOTES, Method.PUT, "/users/username", buildJsonObject { put("challenge", "c") }, 1)
        }
    }

    @Test
    fun anotherAccountFindsTheOutboxEmpty() {
        note(id1)
        assertEquals(0, Outbox(driver, "b".repeat(64)).entries().size)
    }
}
