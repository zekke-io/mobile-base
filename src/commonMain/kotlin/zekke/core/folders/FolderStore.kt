package zekke.core.folders

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.wireJson
import zekke.core.encoding.bytesToUtf8
import zekke.core.encoding.zeroBytes
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Replica
import zekke.core.feed.ReplicaItem
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.generateDek
import zekke.core.items.hashReceivedCiphertext
import zekke.core.items.signedBody
import zekke.core.keyrings.refreshKeyrings
import zekke.core.memory.newPlatformLock
import zekke.core.memory.withLock
import zekke.core.scopes.Scope
import zekke.core.sealed.openBlob
import zekke.core.sealed.sealBlob
import zekke.core.signing.Action

const val MAX_FOLDER_MANIFEST_ATTEMPTS = 4

enum class ManifestScope(val wire: String, val scope: Scope, val feedScope: FeedScope) {
    SECRETS("secrets", Scope.SECRETS, FeedScope.SECRETS),
    NOTES("notes", Scope.NOTES, FeedScope.NOTES),
    ;

    val rules: FolderRules get() = FolderRules(maxDepth = 1, home = true)
}

@Serializable
class FolderManifestRecord(
    val scope: String,
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val revision: Long,
    @SerialName("updated_at") val updatedAt: String,
)

class FoldersKeptChangingException : IllegalStateException("the folders kept changing on another device; try again")

class LoadedManifest(val manifest: FolderManifest, val revision: Long)

suspend fun getFolderManifest(context: ItemContext, scope: ManifestScope): FolderManifestRecord? = try {
    context.api.request(Method.GET, "/${scope.wire}/folders", token = context.api.tokens.require())
        .decode(FolderManifestRecord.serializer())
} catch (error: ApiError) {
    if (error.status == 404) null else throw error
}

private suspend fun putFolderManifest(
    context: ItemContext,
    scope: ManifestScope,
    sealed: SealedManifest,
    expectedRevision: Long,
): FolderManifestRecord {
    val digest = hashReceivedCiphertext(sealed.ciphertext, context.primitives)
    val body = signedBody(context, Action.FOLDERS_UPDATE, listOf(scope.wire, expectedRevision.toString(), digest)) {
        put("ciphertext", sealed.ciphertext)
        put("wrapped_dek", sealed.wrappedDek)
        put("key_generation", sealed.keyGeneration)
        put("expected_revision", expectedRevision)
    }
    return context.api.request(Method.PUT, "/${scope.wire}/folders", body = body, token = context.api.tokens.require())
        .decode(FolderManifestRecord.serializer())
}

private class SealedManifest(val ciphertext: String, val wrappedDek: String, val keyGeneration: Int)

private fun sealManifest(context: ItemContext, scope: ManifestScope, manifest: FolderManifest): SealedManifest {
    val plaintext = formatFolderManifest(manifest).encodeToByteArray()
    try {
        return generateDek(context.primitives).use { dek ->
            val wrapped = ScopeDeks(context, scope.scope).wrap(dek)
            SealedManifest(sealBlob(plaintext, dek, context.primitives), wrapped.wrappedDek, wrapped.keyGeneration)
        }
    } finally {
        zeroBytes(plaintext)
    }
}

suspend fun openFolderManifest(context: ItemContext, scope: ManifestScope, record: FolderManifestRecord): FolderManifest {
    val opened = ScopeDeks(context, scope.scope).unwrap(record.wrappedDek, record.keyGeneration).use { dek ->
        openBlob(record.ciphertext, dek, context.primitives)
    }
    try {
        return validateFolderManifest(parseFolderManifest(bytesToUtf8(opened)), scope.rules)
    } finally {
        zeroBytes(opened)
    }
}

fun folderManifestRecord(items: List<ReplicaItem>): FolderManifestRecord? =
    items.firstOrNull()?.let { wireJson.decodeFromJsonElement(FolderManifestRecord.serializer(), it.item) }

class FolderStore(private val context: ItemContext) : AutoCloseable {
    private val guard = newPlatformLock()
    private val cache = HashMap<ManifestScope, LoadedManifest>()
    private val writes = Mutex()
    private val stopListening = context.session.onLock { guard.withLock { cache.clear() } }

    fun cached(scope: ManifestScope): FolderManifest? = guard.withLock { cache[scope]?.manifest }

    suspend fun load(scope: ManifestScope, fresh: Boolean = false): FolderManifest {
        if (!fresh) cached(scope)?.let { return it }
        return loadRecord(scope, getFolderManifest(context, scope)).manifest
    }

    suspend fun loadFromReplica(scope: ManifestScope, replica: Replica): FolderManifest {
        val record = folderManifestRecord(replica.items(scope.feedScope, ItemTypes.FOLDER_MANIFEST)) ?: return load(scope)
        val held = guard.withLock { cache[scope] }
        if (held != null && held.revision >= record.revision) return held.manifest
        return loadRecord(scope, record).manifest
    }

    private suspend fun loadRecord(scope: ManifestScope, record: FolderManifestRecord?): LoadedManifest {
        val loaded = if (record == null) {
            LoadedManifest(emptyFolderManifest(scope.rules), 0)
        } else {
            LoadedManifest(openFolderManifest(context, scope, record), record.revision)
        }
        guard.withLock { cache[scope] = loaded }
        return loaded
    }

    suspend fun edit(scope: ManifestScope, edit: FolderEdit): FolderManifest = writes.withLock { editLocked(scope, edit) }

    suspend fun reset(scope: ManifestScope): FolderManifest = writes.withLock { resetLocked(scope) }

    suspend fun reseal(scope: ManifestScope): Boolean = writes.withLock { resealLocked(scope) }

    private suspend fun editLocked(scope: ManifestScope, edit: FolderEdit): FolderManifest {
        var fresh = guard.withLock { cache[scope] } == null
        repeat(MAX_FOLDER_MANIFEST_ATTEMPTS) {
            val held = if (fresh) null else guard.withLock { cache[scope] }
            val loaded = held ?: loadRecord(scope, getFolderManifest(context, scope))
            val edited = edit.apply(loaded.manifest, scope.rules)
            if (edited === loaded.manifest) return loaded.manifest
            val next = mergeFolderManifests(loaded.manifest, edited, scope.rules)
            try {
                val stored = putFolderManifest(context, scope, sealManifest(context, scope, next), loaded.revision)
                guard.withLock { cache[scope] = LoadedManifest(next, stored.revision) }
                return next
            } catch (error: ApiError) {
                when {
                    error.isStaleKeyGeneration -> {
                        refreshKeyrings(context.api, context.session, context.primitives)
                        fresh = false
                    }
                    error.status == 409 -> fresh = true
                    else -> throw error
                }
            }
        }
        throw FoldersKeptChangingException()
    }

    private suspend fun resetLocked(scope: ManifestScope): FolderManifest {
        val manifest = emptyFolderManifest(scope.rules)
        repeat(MAX_FOLDER_MANIFEST_ATTEMPTS) {
            val record = getFolderManifest(context, scope)
            try {
                val stored = putFolderManifest(context, scope, sealManifest(context, scope, manifest), record?.revision ?: 0)
                guard.withLock { cache[scope] = LoadedManifest(manifest, stored.revision) }
                return manifest
            } catch (error: ApiError) {
                when {
                    error.isStaleKeyGeneration -> refreshKeyrings(context.api, context.session, context.primitives)
                    error.status == 409 -> Unit
                    else -> throw error
                }
            }
        }
        throw FoldersKeptChangingException()
    }

    private suspend fun resealLocked(scope: ManifestScope): Boolean {
        repeat(MAX_FOLDER_MANIFEST_ATTEMPTS) {
            val record = getFolderManifest(context, scope)
            if (record == null || record.keyGeneration >= context.session.currentGeneration(scope.scope)) return false
            val manifest = openFolderManifest(context, scope, record)
            try {
                val stored = putFolderManifest(context, scope, sealManifest(context, scope, manifest), record.revision)
                guard.withLock { cache[scope] = LoadedManifest(manifest, stored.revision) }
                return true
            } catch (error: ApiError) {
                when {
                    error.isStaleKeyGeneration -> refreshKeyrings(context.api, context.session, context.primitives)
                    error.status == 409 -> Unit
                    else -> throw error
                }
            }
        }
        throw FoldersKeptChangingException()
    }

    override fun close() {
        stopListening()
        guard.withLock { cache.clear() }
    }
}
