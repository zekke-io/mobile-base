package zekke.core.api

private val CANONICAL_UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
private val COMPACT_UUID = Regex("^[0-9a-f]{32}$")
private val SEMANTIC_VERSION = Regex("^(0|[1-9]\\d{0,8})\\.(0|[1-9]\\d{0,8})\\.(0|[1-9]\\d{0,8})(-[0-9A-Za-z]+(\\.[0-9A-Za-z]+)*)?$")

fun isCanonicalUuid(value: String): Boolean = CANONICAL_UUID.matches(value)

fun assertCanonicalUuid(value: String, label: String = "id"): String {
    require(isCanonicalUuid(value)) { "$label must be a canonical lowercase hyphenated UUID, got \"$value\"" }
    return value
}

fun canonicalizeUuid(value: String, label: String = "id"): String {
    val trimmed = value.trim()
    val unwrapped = when {
        trimmed.startsWith("urn:uuid:") -> trimmed.removePrefix("urn:uuid:")
        trimmed.startsWith("{") && trimmed.endsWith("}") -> trimmed.substring(1, trimmed.length - 1)
        else -> trimmed
    }.lowercase()
    val hyphenated = if (COMPACT_UUID.matches(unwrapped)) {
        "${unwrapped.substring(0, 8)}-${unwrapped.substring(8, 12)}-${unwrapped.substring(12, 16)}-${unwrapped.substring(16, 20)}-${unwrapped.substring(20)}"
    } else {
        unwrapped
    }
    return assertCanonicalUuid(hyphenated, label)
}

fun isSemanticVersion(value: String): Boolean = SEMANTIC_VERSION.matches(value)

enum class ClientPlatform(val wire: String) {
    ANDROID("android"),
    IOS("ios"),
    EXTENSION("extension"),
}

const val CLIENT_HEADER = "Zekke-Client"

class ClientIdentity(val platform: ClientPlatform, val version: String) {
    init {
        require(isSemanticVersion(version)) { "client version must be semantic (1.2.3), got \"$version\"" }
    }

    val header: String get() = "${platform.wire}/$version"
}
