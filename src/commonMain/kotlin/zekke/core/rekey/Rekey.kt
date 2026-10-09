package zekke.core.rekey

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import zekke.core.account.AccountServices
import zekke.core.account.removeOtherDevices
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.collectPages
import zekke.core.credentials.listCredentialsMeta
import zekke.core.files.R2States
import zekke.core.files.listFiles
import zekke.core.folders.FolderStore
import zekke.core.folders.ManifestScope
import zekke.core.folders.TreeScope
import zekke.core.folders.listTreeFolderRecords
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.signedBody
import zekke.core.keyrings.refreshKeyrings
import zekke.core.notes.listNotesMeta
import zekke.core.scopes.DEK_SCOPES
import zekke.core.scopes.Scope
import zekke.core.secrets.listDeletedSecrets
import zekke.core.secrets.listSecretsMeta
import zekke.core.signing.Action
import zekke.core.signing.normalizeActionArgs
import zekke.core.trash.getTrashKeys

const val REKEY_BATCH_SIZE = 100

class WrappedItem(val id: String, val wrappedDek: String, val keyGeneration: Int)

class RekeyOutcome(val scope: Scope, val requested: Int, val rekeyed: Int, val folders: Int? = null, val preferences: Int? = null)

@Serializable
private class RekeyResponse(val requested: Int, val rekeyed: Int)

@Serializable
private class DocumentWrap(
    val id: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
)

private class RekeyRoute(val path: String, val action: Action, val idField: String)

private val ROUTES = mapOf(
    Scope.SECRETS to RekeyRoute("/secrets/keys", Action.SECRET_REKEY, "id"),
    Scope.NOTES to RekeyRoute("/notes/keys", Action.NOTE_REKEY, "id"),
    Scope.DOCUMENTS to RekeyRoute("/documents/keys", Action.DOCUMENT_REKEY, "id"),
    Scope.FILES to RekeyRoute("/files/keys", Action.FILE_REKEY, "id"),
    Scope.PASSWORDS to RekeyRoute("/credentials/keys", Action.CREDENTIAL_REKEY, "revision_id"),
)

private val FOLDER_ROUTES = mapOf(
    TreeScope.DOCUMENTS to RekeyRoute("/documents/folders/keys", Action.DOCUMENT_FOLDER_REKEY, "id"),
    TreeScope.FILES to RekeyRoute("/files/folders/keys", Action.FILE_FOLDER_REKEY, "id"),
)

fun staleItems(items: List<WrappedItem>, generation: Int): List<WrappedItem> =
    items.filter { it.keyGeneration < generation }.distinctBy { it.id }.sortedBy { it.id }

suspend fun listDocumentWraps(context: ItemContext): List<WrappedItem> = collectPages { cursor ->
    val response = context.api.request(Method.GET, "/documents", token = context.api.tokens.require(), query = mapOf("cursor" to cursor))
    val page = if (response.data == null) emptyList() else response.decode(ListSerializer(DocumentWrap.serializer()))
    page.map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) } to response.page
}

suspend fun listWraps(context: ItemContext, scope: Scope): List<WrappedItem> = when (scope) {
    Scope.SECRETS -> (listSecretsMeta(context).map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) } +
        listDeletedSecrets(context).map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) })
    Scope.NOTES -> listNotesMeta(context).map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) }
    Scope.DOCUMENTS -> listDocumentWraps(context) + getTrashKeys(context, TreeScope.DOCUMENTS).items.map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) }
    Scope.FILES -> listFiles(context).filter { it.r2State == R2States.OK }.map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) } +
        getTrashKeys(context, TreeScope.FILES).items.map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) }
    Scope.PASSWORDS -> listCredentialsMeta(context).map { WrappedItem(it.revisionId, it.wrappedDek, it.keyGeneration) }
    else -> emptyList()
}

private suspend fun rewrapBatch(context: ItemContext, scope: Scope, batch: List<WrappedItem>, route: RekeyRoute): Int {
    val deks = ScopeDeks(context, scope)
    var generation = 0
    val wraps = batch.map { item ->
        deks.unwrap(item.wrappedDek, item.keyGeneration).use { dek ->
            val wrapped = deks.wrap(dek)
            generation = wrapped.keyGeneration
            item.id to wrapped.wrappedDek
        }
    }
    val ids = normalizeActionArgs(route.action, batch.map { it.id })
    val body = signedBody(context, route.action, ids) {
        put("key_generation", generation)
        putJsonArray("items") { wraps.forEach { (id, wrapped) -> addJsonObject { put(route.idField, id); put("wrapped_dek", wrapped) } } }
    }
    return context.api.request(Method.PUT, route.path, body = body, token = context.api.tokens.require())
        .decode(RekeyResponse.serializer()).rekeyed
}

private suspend fun rewrapAll(context: ItemContext, scope: Scope, items: List<WrappedItem>, route: RekeyRoute): Pair<Int, Int> {
    val stale = staleItems(items, context.session.currentGeneration(scope))
    var rekeyed = 0
    for (batch in stale.chunked(REKEY_BATCH_SIZE)) {
        rekeyed += try {
            rewrapBatch(context, scope, batch, route)
        } catch (error: ApiError) {
            if (!error.isStaleKeyGeneration) throw error
            refreshKeyrings(context.api, context.session, context.primitives)
            rewrapBatch(context, scope, batch, route)
        }
    }
    return stale.size to rekeyed
}

suspend fun rewrapScope(context: ItemContext, scope: Scope): RekeyOutcome {
    val route = ROUTES[scope] ?: throw IllegalArgumentException("${scope.wire} holds no item keys")
    val (requested, rekeyed) = rewrapAll(context, scope, listWraps(context, scope), route)
    return RekeyOutcome(scope, requested, rekeyed)
}

suspend fun rewrapFolderNames(context: ItemContext, scope: TreeScope): Pair<Int, Int> {
    val folders = listTreeFolderRecords(context, scope).map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) } +
        getTrashKeys(context, scope).folders.map { WrappedItem(it.id, it.wrappedDek, it.keyGeneration) }
    return rewrapAll(context, scope.scope, folders, FOLDER_ROUTES.getValue(scope))
}

private suspend fun rewrapFolders(context: ItemContext, scope: Scope, store: FolderStore): Int? {
    TreeScope.entries.firstOrNull { it.scope == scope }?.let { return rewrapFolderNames(context, it).second }
    ManifestScope.entries.firstOrNull { it.scope == scope }?.let { return if (store.reseal(it)) 1 else 0 }
    return null
}

suspend fun rewrapAfterRotation(context: ItemContext, scopes: Collection<Scope>): List<RekeyOutcome> {
    val wanted = DEK_SCOPES.filter { it in scopes && context.session.holds(it) }
    return FolderStore(context).use { store ->
        wanted.map { scope ->
            val outcome = rewrapScope(context, scope)
            val folders = rewrapFolders(context, scope, store)
            val preferences = if (scope == PREFERENCES_SCOPE) (if (resealPreferences(context)) 1 else 0) else null
            RekeyOutcome(scope, outcome.requested, outcome.rekeyed, folders, preferences)
        }
    }
}

suspend fun rewrapStale(context: ItemContext): List<RekeyOutcome> = rewrapAfterRotation(context, DEK_SCOPES)

suspend fun removeOtherDevicesAndRewrap(services: AccountServices, words: List<CharArray>, deviceIds: List<String>): List<RekeyOutcome> {
    val rotated = removeOtherDevices(services, words, deviceIds)
    return rewrapAfterRotation(ItemContext(services.api, services.session, services.primitives), rotated)
}
