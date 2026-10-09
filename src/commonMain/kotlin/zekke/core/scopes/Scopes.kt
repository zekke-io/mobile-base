package zekke.core.scopes

enum class Scope(val wire: String, val isKeyring: Boolean) {
    ADMIN("admin", isKeyring = false),
    PASSWORDS("passwords", isKeyring = true),
    SECRETS("secrets", isKeyring = true),
    NOTES("notes", isKeyring = true),
    DOCUMENTS("documents", isKeyring = true),
    FILES("files", isKeyring = true),
    SHARING("sharing", isKeyring = true),
    ;

    companion object {
        fun fromWire(name: String): Scope? = entries.firstOrNull { it.wire == name }
    }
}

val SCOPES: List<Scope> = Scope.entries

val KEYRING_SCOPES: List<Scope> = Scope.entries.filter { it.isKeyring }

val ITEM_SCOPES: List<Scope> = listOf(Scope.SECRETS, Scope.NOTES, Scope.DOCUMENTS, Scope.FILES)

val DEK_SCOPES: List<Scope> = ITEM_SCOPES + Scope.PASSWORDS

val FULL_DEVICE_SCOPES: List<Scope> = SCOPES

val CANONICAL_SCOPE_LIST: String = SCOPES.joinToString(",") { it.wire }

enum class ScopedItemType(val wire: String, val scope: Scope) {
    SECRET("secret", Scope.SECRETS),
    NOTE("note", Scope.NOTES),
    DOCUMENT("document", Scope.DOCUMENTS),
    FILE("file", Scope.FILES),
}

class InvalidScopeListException(list: String) : IllegalArgumentException("\"$list\" is not a non-empty canonical scope list")

fun scopeForItemType(itemType: ScopedItemType): Scope = itemType.scope

fun parseScopeList(list: String): List<Scope> {
    if (list.isEmpty()) throw InvalidScopeListException(list)
    var previous = -1
    return list.split(',').map { name ->
        val scope = Scope.fromWire(name) ?: throw InvalidScopeListException(list)
        if (scope.ordinal <= previous) throw InvalidScopeListException(list)
        previous = scope.ordinal
        scope
    }
}

fun formatScopeList(scopes: Iterable<Scope>): String {
    val held = scopes.toSet()
    if (held.isEmpty()) throw InvalidScopeListException("")
    return SCOPES.filter { it in held }.joinToString(",") { it.wire }
}

fun keyringScopesOf(scopes: Iterable<Scope>): List<Scope> {
    val held = scopes.toSet()
    return KEYRING_SCOPES.filter { it in held }
}

fun isFullDevice(scopes: Iterable<Scope>): Boolean = Scope.ADMIN in scopes
