package zekke.core.clients

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import zekke.core.api.ClientPlatform
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.api.isSemanticVersion
import kotlin.math.sign

@Serializable
class ClientPolicy(
    val platform: String,
    @SerialName("min_supported") val minSupported: String,
    val latest: String,
    @SerialName("deprecated_below") val deprecatedBelow: String? = null,
    @SerialName("deprecation_ends") val deprecationEnds: String? = null,
)

sealed interface VersionNotice {
    data object Current : VersionNotice

    data class Available(val latest: String) : VersionNotice

    data class Deprecated(val latest: String, val deprecationEnds: String) : VersionNotice

    data class Required(val latest: String) : VersionNotice
}

private class ParsedVersion(val core: List<Long>, val prerelease: List<String>)

private fun parse(version: String): ParsedVersion? {
    if (!isSemanticVersion(version)) return null
    val dash = version.indexOf('-')
    val core = (if (dash < 0) version else version.substring(0, dash)).split('.').map { it.toLong() }
    val prerelease = if (dash < 0) emptyList() else version.substring(dash + 1).split('.')
    return ParsedVersion(core, prerelease)
}

private fun comparePrerelease(a: List<String>, b: List<String>): Int {
    if (a.isEmpty() || b.isEmpty()) return if (a.size == b.size) 0 else if (a.isEmpty()) 1 else -1
    for (index in 0 until minOf(a.size, b.size)) {
        if (a[index] == b[index]) continue
        val left = a[index].takeIf { part -> part.all { it in '0'..'9' } }?.toLongOrNull()
        val right = b[index].takeIf { part -> part.all { it in '0'..'9' } }?.toLongOrNull()
        return when {
            left != null && right != null -> (left - right).sign
            left != null -> -1
            right != null -> 1
            else -> if (a[index] < b[index]) -1 else 1
        }
    }
    return (a.size - b.size).sign
}

fun compareVersions(a: String, b: String): Int? {
    val left = parse(a) ?: return null
    val right = parse(b) ?: return null
    for (index in 0 until 3) {
        if (left.core[index] != right.core[index]) return (left.core[index] - right.core[index]).sign
    }
    return comparePrerelease(left.prerelease, right.prerelease)
}

private fun below(version: String, floor: String?): Boolean {
    if (floor == null) return false
    val order = compareVersions(version, floor)
    return order != null && order < 0
}

fun versionNotice(policy: ClientPolicy, version: String): VersionNotice = when {
    below(version, policy.minSupported) -> VersionNotice.Required(policy.latest)
    policy.deprecationEnds != null && below(version, policy.deprecatedBelow) -> VersionNotice.Deprecated(policy.latest, policy.deprecationEnds)
    below(version, policy.latest) -> VersionNotice.Available(policy.latest)
    else -> VersionNotice.Current
}

suspend fun getClientPolicy(api: ZekkeApi, platform: ClientPlatform): ClientPolicy? = try {
    api.request(Method.GET, "/clients/${platform.wire}/policy").decode(ClientPolicy.serializer())
} catch (error: CancellationException) {
    throw error
} catch (_: Exception) {
    null
}
