package zekke.core.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import zekke.core.encoding.base64UrlToBytes
import zekke.core.encoding.bytesToUtf8
import zekke.core.memory.newPlatformLock
import zekke.core.memory.withLock
import zekke.core.signing.currentTimestamp

@Serializable
class SessionGrant(
    @SerialName("access_token") val accessToken: String,
    @SerialName("device_id") val deviceId: String,
)

class JwtClaims(val exp: Long?, val iat: Long?, val userAddress: String?, val deviceId: String?)

fun decodeJwtClaims(token: String): JwtClaims? {
    val segments = token.split('.')
    if (segments.size != 3) return null
    val claims: JsonObject = try {
        Json.parseToJsonElement(bytesToUtf8(base64UrlToBytes(segments[1]))).jsonObject
    } catch (_: IllegalArgumentException) {
        return null
    } catch (_: SerializationException) {
        return null
    } catch (_: CharacterCodingException) {
        return null
    }
    fun long(name: String) = (claims[name] as? JsonPrimitive)?.longOrNull
    fun text(name: String) = (claims[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
    return JwtClaims(long("exp"), long("iat"), text("user_address"), text("device_id"))
}

fun jwtExpiresAtEpochSeconds(token: String): Long? = decodeJwtClaims(token)?.exp

fun isJwtExpired(token: String, nowEpochSeconds: Long): Boolean {
    val expiresAt = jwtExpiresAtEpochSeconds(token) ?: return false
    return expiresAt <= nowEpochSeconds
}

class NoSessionTokenException : IllegalStateException("no valid session token: sign in again")

class TokenStore(private val nowEpochSeconds: () -> Long = ::currentTimestamp) {
    private val guard = newPlatformLock()
    private var token: String? = null
    private val listeners = LinkedHashSet<(String?) -> Unit>()

    fun set(value: String) {
        guard.withLock { token = value }
        notifyListeners(value)
    }

    fun get(): String? {
        val current = guard.withLock { token } ?: return null
        if (isJwtExpired(current, nowEpochSeconds())) {
            clear()
            return null
        }
        return current
    }

    fun require(): String = get() ?: throw NoSessionTokenException()

    val expiresAtEpochSeconds: Long? get() = guard.withLock { token }?.let(::jwtExpiresAtEpochSeconds)

    val isAuthenticated: Boolean get() = get() != null

    fun clear() {
        val had = guard.withLock { token.also { token = null } } != null
        if (had) notifyListeners(null)
    }

    fun onChange(listener: (String?) -> Unit): () -> Unit {
        guard.withLock { listeners.add(listener) }
        return { guard.withLock { listeners.remove(listener) } }
    }

    private fun notifyListeners(value: String?) {
        guard.withLock { listeners.toList() }.forEach { it(value) }
    }
}
