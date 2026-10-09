package zekke.core.interop

import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import zekke.core.account.AccountServices
import zekke.core.account.UnlockOutcome
import zekke.core.api.ApiError
import zekke.core.api.ClientIdentity
import zekke.core.api.ClientPlatform
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.device.MemoryDeviceVault
import zekke.core.encoding.base64UrlToBytes
import zekke.core.keys.deriveRootKeysFromMnemonic
import zekke.core.keys.generateMnemonic
import zekke.core.keys.zeroRootKeys
import zekke.core.oprf.accountPinProof
import zekke.core.primitives.platformPrimitives
import zekke.core.session.SessionKeystore
import zekke.core.signing.rawKeySigner
import zekke.core.users.deleteAccount
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

internal val interopApi: String = System.getProperty("zekke.interop.api") ?: "http://localhost:8080"

internal class Phone {
    val api = ZekkeApi(baseUrl = interopApi, clientIdentity = ClientIdentity(ClientPlatform.ANDROID, "0.1.0"))
    val services = AccountServices(api, SessionKeystore(), MemoryDeviceVault())
}

internal fun newPhrase(): List<CharArray> = generateMnemonic(12)

internal fun phraseCopy(words: List<CharArray>): List<CharArray> = words.map { it.copyOf() }

internal suspend fun <T> patiently(step: suspend () -> T): T {
    repeat(4) {
        try {
            val result = step()
            if (result is UnlockOutcome.RateLimited) {
                delay(((result.retryAfterSeconds ?: 30) + 1).seconds)
                return@repeat
            }
            return result
        } catch (error: ApiError) {
            if (!error.isRateLimited) throw error
            delay(((error.retryAfterSeconds ?: 30) + 1).seconds)
        }
    }
    return step()
}

internal suspend fun deleteWithPhrase(phone: Phone, words: List<CharArray>, accountPin: CharArray? = null) {
    val primitives = platformPrimitives()
    val root = deriveRootKeysFromMnemonic(phraseCopy(words), primitives)
    try {
        val signer = rawKeySigner(root.signing.privateKey, primitives)
        val proof = accountPin?.let { patiently { accountPinProof(phone.api, signer, root.userAddress, it, primitives) } }
        patiently { deleteAccount(phone.api, root.userAddress, signer, proof?.sign, primitives) }
    } finally {
        zeroRootKeys(root)
    }
}

internal val billingToken: String = System.getenv("ZEKKE_INTEROP_BILLING_TOKEN") ?: "local-billing-token-0123456789abcdef"

internal suspend fun grantPremium(phone: Phone) {
    val ticket = phone.api.request(Method.POST, "/billing/ticket", token = phone.api.tokens.require())
        .data!!.jsonObject.getValue("ticket").jsonPrimitive.content
    val subject = Json.parseToJsonElement(base64UrlToBytes(ticket.split('.')[1]).decodeToString()).jsonObject.getValue("sub").jsonPrimitive.content
    val body = """{"plan":"premium_1","paid_until":"${java.time.Instant.now().plusSeconds(365L * 24 * 3600)}","renews":true,"version":1}"""
    val response = HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI("$interopApi/internal/entitlements/$subject"))
            .header("Authorization", "Bearer $billingToken")
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(body))
            .build(),
        HttpResponse.BodyHandlers.ofString(),
    )
    check(response.statusCode() == 204) { "granting premium_1 answered ${response.statusCode()} ${response.body()}" }
}
