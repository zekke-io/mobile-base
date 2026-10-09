package zekke.core.items

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import zekke.core.api.ZekkeApi
import zekke.core.api.wireJson
import zekke.core.device.generateDeviceKeys
import zekke.core.encoding.spkiBase64ToUncompressedPoint
import zekke.core.keyrings.generateScopeKek
import zekke.core.primitives.primitives
import zekke.core.scopes.FULL_DEVICE_SCOPES
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import zekke.core.session.KeyringEntry
import zekke.core.session.SessionKeys
import zekke.core.session.SessionKeystore
import zekke.core.signing.Action
import zekke.core.signing.buildActionPayload
import zekke.core.signing.verifyPayload

internal class Reply(val status: Int, val body: String = "")

internal fun data(element: JsonElement, status: Int = 200) = Reply(status, wireJson.encodeToString(JsonObject.serializer(), buildJsonObject { put("data", element) }))

internal fun failure(status: Int, code: String) = Reply(status, "{\"code\":\"$code\"}")

internal class SentRequest(val method: String, val path: String, val query: String, val body: JsonObject?) {
    val json: JsonObject get() = body ?: error("the request carried no body")
}

internal class FakeServer {
    val sent = mutableListOf<SentRequest>()
    private val replies = ArrayDeque<(SentRequest) -> Reply>()

    fun reply(vararg next: Reply) {
        next.forEach { reply -> replies.addLast { reply } }
    }

    fun answer(next: (SentRequest) -> Reply) {
        replies.addLast(next)
    }

    val api: ZekkeApi = ZekkeApi(
        baseUrl = "http://api.test",
        httpClient = HttpClient(
            MockEngine { request: HttpRequestData ->
                val text = (request.body as? TextContent)?.text
                val received = SentRequest(request.method.value, request.url.encodedPath, request.url.encodedQuery, text?.let { wireJson.parseToJsonElement(it).jsonObject })
                sent += received
                val next = replies.removeFirstOrNull()?.invoke(received) ?: Reply(500)
                respond(next.body, HttpStatusCode.fromValue(next.status), headersOf(HttpHeaders.ContentType, "application/json"))
            },
        ),
    ).also { it.tokens.set("header.eyJleHAiOjQxMDI0NDQ4MDB9.signature") }
}

internal class TestVault(generations: Map<Scope, Int> = emptyMap(), scopes: List<Scope> = FULL_DEVICE_SCOPES) {
    val server = FakeServer()
    val device = generateDeviceKeys(primitives = primitives)
    val session = SessionKeystore(primitives = primitives)
    val context = ItemContext(server.api, session, primitives)

    init {
        val entries = KEYRING_SCOPES.filter { it in scopes }.flatMap { scope ->
            (1..(generations[scope] ?: 1)).map { KeyringEntry(scope, it, generateScopeKek(primitives)) }
        }
        val current = KEYRING_SCOPES.filter { it in scopes }.associateWith { generations[it] ?: 1 }
        session.open(SessionKeys("a".repeat(64), "root", device.deviceId, "registration", scopes, device, entries, current))
    }

    fun verifies(body: JsonObject, action: Action, args: List<String>): Boolean {
        val payload = buildActionPayload(
            body.getValue("challenge").jsonPrimitive.content,
            body.getValue("timestamp").jsonPrimitive.long,
            action,
            args,
        )
        return verifyPayload(payload, body.getValue("signature").jsonPrimitive.content, spkiBase64ToUncompressedPoint(device.signingPublicKey), primitives)
    }
}

internal fun storedRow(body: JsonObject, vararg extra: Pair<String, JsonElement>): JsonObject = JsonObject(
    body.filterKeys { it !in setOf("challenge", "timestamp", "signature", "expected_revision") } +
        mapOf(
            "created_at" to kotlinx.serialization.json.JsonPrimitive("2026-10-09T12:00:00.000000Z"),
            "updated_at" to kotlinx.serialization.json.JsonPrimitive("2026-10-09T12:00:00.000000Z"),
        ) + extra,
)
