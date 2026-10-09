package zekke.core.api

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.io.IOException
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.encoding.bytesToBase64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ZekkeApiTest {
    private val requests = mutableListOf<HttpRequestData>()

    private fun api(
        identity: ClientIdentity? = null,
        handler: suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData,
    ) = ZekkeApi(
        baseUrl = "http://api.test/",
        clientIdentity = identity,
        httpClient = HttpClient(MockEngine { request -> requests += request; handler(request) }),
        nowEpochSeconds = { 1_790_000_000 },
    )

    private val json = headersOf(HttpHeaders.ContentType, "application/json")

    @Test
    fun sendsOnlyTheHeadersItNeedsAndTheClientIdentity() = runTest {
        val api = api(ClientIdentity(ClientPlatform.ANDROID, "1.2.3")) { respond("{\"data\":{}}", HttpStatusCode.OK, json) }
        api.request(Method.POST, "users/me", body = buildJsonObject { put("a", 1) }, token = "t")
        val sent = requests.single()
        assertEquals("http://api.test/users/me", sent.url.toString())
        assertEquals("Bearer t", sent.headers[HttpHeaders.Authorization])
        assertEquals("android/1.2.3", sent.headers[CLIENT_HEADER])
        assertEquals("{\"a\":1}", (sent.body as TextContent).text)
    }

    @Test
    fun noAuthorizationWithoutAToken() = runTest {
        api { respond("{}", HttpStatusCode.OK, json) }.request(Method.GET, "/users/lookup", query = mapOf("address" to "x", "skip" to null))
        assertNull(requests.single().headers[HttpHeaders.Authorization])
        assertEquals("address=x", requests.single().url.encodedQuery)
    }

    @Test
    fun aNoContentAnswerHasNoBody() = runTest {
        val response = api { respond("", HttpStatusCode.NoContent) }.request(Method.DELETE, "/oprf/devices/x")
        assertEquals(204, response.status)
        assertNull(response.data)
    }

    @Test
    fun readsTheEnvelopeAndThePage() = runTest {
        val response = api { respond("{\"data\":[1,2],\"page\":{\"next_cursor\":\"c\",\"has_more\":true}}", HttpStatusCode.OK, json) }
            .request(Method.GET, "/notes")
        assertEquals("c", response.page?.nextCursor)
        assertTrue(response.page?.hasMore == true)
    }

    @Test
    fun anErrorCarriesItsCodeAndNoMessage() = runTest {
        val error = assertFailsWith<ApiError> {
            api { respond("{\"code\":\"STALE_KEY_GENERATION\"}", HttpStatusCode.Conflict, json) }.request(Method.POST, "/notes")
        }
        assertEquals("STALE_KEY_GENERATION", error.code)
        assertTrue(error.isStaleKeyGeneration)
        assertEquals("POST /notes", error.endpoint)
    }

    @Test
    fun theRoutersPlainTextNotFoundIsAnApiError() = runTest {
        val error = assertFailsWith<ApiError> { api { respond("404 page not found", HttpStatusCode.NotFound) }.request(Method.GET, "/nope") }
        assertTrue(error.isAuthEndpointRejection)
    }

    @Test
    fun theTwoUnauthorizedAnswersAreDistinct() = runTest {
        val expired = assertFailsWith<ApiError> { api { respond("{\"code\":\"UNAUTHORIZED\"}", HttpStatusCode.Unauthorized, json) }.request(Method.GET, "/a") }
        val credentials = assertFailsWith<ApiError> { api { respond("{\"code\":\"INVALID_CREDENTIALS\"}", HttpStatusCode.Unauthorized, json) }.request(Method.GET, "/a") }
        assertTrue(expired.isSessionOver && !expired.isCredentialFailure)
        assertTrue(credentials.isCredentialFailure && !credentials.isSessionOver)
    }

    @Test
    fun aRateLimitCarriesRetryAfterAndAnUpgradeIsTyped() = runTest {
        val limited = assertFailsWith<ApiError> {
            api { respond("{\"code\":\"TOO_MANY_REQUESTS\"}", HttpStatusCode.TooManyRequests, headersOf(HttpHeaders.RetryAfter, "17")) }.request(Method.POST, "/sign-in")
        }
        assertTrue(limited.isRateLimited)
        assertEquals(17L, limited.retryAfterSeconds)
        val upgrade = assertFailsWith<ApiError> { api { respond("", HttpStatusCode.UpgradeRequired) }.request(Method.GET, "/a") }
        assertTrue(upgrade.isUpgradeRequired)
    }

    @Test
    fun aTransportFailureIsANetworkError() = runTest {
        assertFailsWith<NetworkError> { api { throw IOException("down") }.request(Method.GET, "/a") }
    }

    @Test
    fun aBodyOverTheCapIsRefusedBeforeSending() = runTest {
        val api = api { respond("{}", HttpStatusCode.OK, json) }
        val body = buildJsonObject { put("blob", bytesToBase64(ByteArray(MAX_BODY_BYTES))) }
        assertFailsWith<RequestTooLargeException> { api.request(Method.POST, "/secrets", body = body) }
        assertTrue(requests.isEmpty())
    }

    @Test
    fun recordsTheServerClockOffsetWithoutApplyingIt() = runTest {
        val api = api { respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.Date, "Sat, 12 Sep 2026 14:00:00 GMT")) }
        api.request(Method.GET, "/a")
        assertEquals(parseHttpDate("Sat, 12 Sep 2026 14:00:00 GMT")!! - 1_790_000_000, api.serverClockOffsetSeconds)
        assertTrue(api.isClockSkewed)
    }

    @Test
    fun parsesAnHttpDate() {
        assertEquals(1_759_968_000L, parseHttpDate("Thu, 09 Oct 2025 00:00:00 GMT"))
        assertNull(parseHttpDate("yesterday"))
    }

    @Test
    fun collectsPagesUntilHasMoreIsFalseEvenAfterAShortPage() = runTest {
        val pages = mapOf<String?, Pair<List<Int>, PageInfo?>>(
            null to (listOf(1) to PageInfo("a", true)),
            "a" to (emptyList<Int>() to PageInfo("b", true)),
            "b" to (listOf(2, 3) to PageInfo(null, false)),
        )
        assertEquals(listOf(1, 2, 3), collectPages { cursor -> pages.getValue(cursor) })
    }

    @Test
    fun canonicalisesEveryUuidSpellingAndRefusesOthers() {
        val canonical = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
        for (spelling in listOf(canonical.uppercase(), "{$canonical}", "urn:uuid:$canonical", canonical.replace("-", ""))) {
            assertEquals(canonical, canonicalizeUuid(spelling))
        }
        assertFailsWith<IllegalArgumentException> { canonicalizeUuid("not-a-uuid") }
    }

    @Test
    fun theTokenStoreForgetsAnExpiredToken() {
        val payload = bytesToBase64("{\"exp\":100,\"device_id\":\"d\"}".encodeToByteArray()).trimEnd('=').replace('+', '-').replace('/', '_')
        val token = "h.$payload.s"
        assertEquals("d", decodeJwtClaims(token)?.deviceId)
        var now = 99L
        val store = TokenStore { now }
        var seen: String? = "unset"
        store.onChange { seen = it }
        store.set(token)
        assertEquals(token, store.get())
        now = 100L
        assertNull(store.get())
        assertNull(seen)
        assertFalse(store.isAuthenticated)
        assertFailsWith<NoSessionTokenException> { store.require() }
    }

    @Test
    fun aClientVersionMustBeSemantic() {
        assertFailsWith<IllegalArgumentException> { ClientIdentity(ClientPlatform.IOS, "1.2") }
        assertEquals("ios/2.0.0-beta.1", ClientIdentity(ClientPlatform.IOS, "2.0.0-beta.1").header)
    }
}
