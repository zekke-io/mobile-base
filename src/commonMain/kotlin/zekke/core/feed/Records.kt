package zekke.core.feed

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import zekke.core.scopes.Scope

enum class FeedScope(val wire: String, val scope: Scope) {
    PASSWORDS("passwords", Scope.PASSWORDS),
    SECRETS("secrets", Scope.SECRETS),
    NOTES("notes", Scope.NOTES),
    DOCUMENTS("documents", Scope.DOCUMENTS),
    FILES("files", Scope.FILES),
    ;

    companion object {
        fun of(scope: Scope): FeedScope? = entries.firstOrNull { it.scope == scope }
    }
}

object ItemTypes {
    const val CREDENTIAL = "credential"
    const val SECRET = "secret"
    const val NOTE = "note"
    const val FOLDER_MANIFEST = "folder_manifest"
    const val DOCUMENT = "document"
    const val DOCUMENT_FOLDER = "document_folder"
    const val FILE = "file"
    const val FILE_FOLDER = "file_folder"
}

@Serializable
class Change(val seq: Long, val type: String, val id: String, val tombstone: Boolean = false, val item: JsonObject? = null)

@Serializable
class ChangesPage(val changes: List<Change> = emptyList(), val cursor: Long = 0, val more: Boolean = false)

const val FEED_PAGE_LIMIT = 500

class ReplicaItem(val id: String, val seq: Long, val item: JsonObject)
