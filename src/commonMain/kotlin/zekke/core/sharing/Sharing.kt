package zekke.core.sharing

import kotlinx.coroutines.CancellationException
import zekke.core.api.ApiError
import zekke.core.chain.InvalidChainException
import zekke.core.chain.PublishedSharingKeys
import zekke.core.chain.verifyProofPath
import zekke.core.files.ByteArrayUpload
import zekke.core.files.DEFAULT_DOWNLOAD_BUFFER_BYTES
import zekke.core.files.DownloadBufferExceededException
import zekke.core.files.FileManifest
import zekke.core.files.ObjectStore
import zekke.core.files.PlaintextSink
import zekke.core.files.decryptObject
import zekke.core.files.getFileDownload
import zekke.core.files.openManifest
import zekke.core.files.uploadFile
import zekke.core.folders.FolderEdit
import zekke.core.folders.FolderEditException
import zekke.core.folders.FolderManifest
import zekke.core.folders.FolderRules
import zekke.core.folders.MAX_TREE_DEPTH
import zekke.core.folders.emptyFolderManifest
import zekke.core.folders.formatFolderManifest
import zekke.core.folders.mergeFolderManifests
import zekke.core.folders.parseFolderManifest
import zekke.core.folders.validateFolderManifest
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.generateDek
import zekke.core.keyrings.deriveShareSubkey
import zekke.core.keyrings.refreshKeyrings
import zekke.core.memory.SecretBytes
import zekke.core.memory.SecretZeroedException
import zekke.core.memory.newPlatformLock
import zekke.core.memory.withLock
import zekke.core.notes.createNote
import zekke.core.notes.getNote
import zekke.core.notes.noteTitle
import zekke.core.pqxdh.RecipientSecrets
import zekke.core.pqxdh.rawX25519Agreement
import zekke.core.scopes.ITEM_SCOPES
import zekke.core.scopes.Scope
import zekke.core.scopes.ScopedItemType
import zekke.core.sealed.openBlob
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.openText
import zekke.core.sealed.sealBlob
import zekke.core.sealed.sealSecretBlob
import zekke.core.secrets.MalformedSecretPayloadException
import zekke.core.secrets.createSecret
import zekke.core.secrets.decodeSecretPayload
import zekke.core.secrets.getSecret
import zekke.core.session.SessionLockedException
import zekke.core.users.getPublicKeys
import zekke.core.users.normalizeUsername
import zekke.core.users.resolveUsername

val SHARED_FOLDER_RULES = FolderRules(maxDepth = MAX_TREE_DEPTH, home = false)
const val MAX_SHARED_FOLDERS_ATTEMPTS = 4

class PublishedCounterparty(
    val uuid: String,
    val userAddress: String,
    val rootPublicKey: String,
    val fingerprint: String,
    val sharingKeys: PublishedSharingKeys,
    val proofVerified: Boolean,
)

sealed interface ConnectionTrust {
    data class Trusted(val fingerprint: String) : ConnectionTrust
    data class Unpinned(val fingerprint: String) : ConnectionTrust
    data class RootChanged(val fingerprint: String, val pinned: String) : ConnectionTrust
    data class ProofInvalid(val fingerprint: String) : ConnectionTrust
    data object AccountChanged : ConnectionTrust
    data object Unresolvable : ConnectionTrust
}

class ConnectionNotTrustedException(val trust: ConnectionTrust) : IllegalStateException("refusing to send through this connection: $trust")

class UnknownRecipientException(username: String) : IllegalArgumentException("no account currently uses the username \"$username\"")

class AlreadyConnectedException(username: String) : IllegalStateException("this account is already connected to \"$username\"")

class ConnectionNotOpenableException : IllegalStateException("this connection cannot be opened with this device's keys")

class ScopeNotSharedException(scope: Scope) : IllegalStateException("this connection holds no sub-key for ${scope.wire} on this side")

class ShareNotRewrappableException(shareId: String) : IllegalStateException("share $shareId does not open under any sub-key of this connection")

class ConnectionGoneException : IllegalStateException("this connection no longer exists")

class DocumentsNotInCoreException : UnsupportedOperationException("documents are not opened by the core")

class SharedFoldersKeptChangingException : IllegalStateException("the shared folders kept changing on the other side; try again")

class InvitationDraft(val connection: ConnectionRecord, val fingerprint: String)

class ReestablishOutcome(val reestablished: Boolean, val shares: Int)

class ReceivedItem(
    val shareId: String,
    val connectionId: String,
    val itemType: String,
    val itemId: String,
    val direction: String,
    val counterparty: String,
    val createdAt: String,
    val name: String?,
    val readable: Boolean,
    val problem: String? = null,
    val sizeBytes: Long? = null,
    val mime: String? = null,
    val text: String? = null,
)

class SharedFile(val manifest: FileManifest, val bytes: ByteArray)

fun connectionIsStale(connection: ConnectionRecord, publishedGeneration: Int): Boolean =
    connection.recipientKeyGeneration < publishedGeneration

fun connectionWith(connections: List<ConnectionRecord>, username: String): ConnectionRecord? {
    val wanted = normalizeUsername(username)
    return connections.firstOrNull { it.username == wanted }
}

class SharingService(private val context: ItemContext) : AutoCloseable {
    private class LoadedFolders(val manifest: FolderManifest, val revision: Long, val recipientKeyGeneration: Int)

    private val guard = newPlatformLock()
    private val counterparties = HashMap<String, PublishedCounterparty>()
    private val connections = HashMap<String, ConnectionRecord>()
    private val folders = HashMap<String, LoadedFolders>()
    private val addressBook = AddressBookStore(context)
    private val stopListening = context.session.onLock { forget() }

    private val session get() = context.session
    private val primitives get() = context.primitives

    private fun forget() {
        guard.withLock {
            counterparties.clear()
            connections.clear()
            folders.clear()
            addressBook.forget()
        }
    }

    override fun close() {
        stopListening()
        forget()
    }

    fun current(connection: ConnectionRecord): ConnectionRecord = guard.withLock { connections[connection.id] } ?: connection

    private fun remember(connection: ConnectionRecord): ConnectionRecord = connection.also { guard.withLock { connections[it.id] = it } }

    suspend fun connections(): List<ConnectionRecord> = listConnections(context).map(::remember)

    fun sharableScopes(): List<Scope> = ITEM_SCOPES.filter { session.holds(it) }

    fun sharableItemTypes(): List<ScopedItemType> = ScopedItemType.entries.filter { session.holds(it.scope) && it != ScopedItemType.DOCUMENT }

    suspend fun loadAddressBook(fresh: Boolean = false): AddressBook = addressBook.load(fresh)

    suspend fun editAddressBook(edit: AddressBookEdit): AddressBook = addressBook.edit(edit)

    fun ownRootFingerprint(): String = rootFingerprint(session.rootPublicKey, primitives)

    suspend fun fetchPublishedCounterparty(username: String): PublishedCounterparty? {
        val resolved = resolveUsername(context.api, username) ?: return null
        val published = getPublicKeys(context.api, resolved.uuid)
        val sharingKeys = PublishedSharingKeys(published.sharingKeys.generation, published.sharingKeys.x25519PublicKey, published.sharingKeys.mlkemPublicKey)
        val verified = try {
            verifyProofPath(published.userAddress, published.rootPublicKey, sharingKeys, published.proof.map { it.toStored() }, primitives)
            true
        } catch (_: InvalidChainException) {
            false
        }
        return PublishedCounterparty(resolved.uuid, published.userAddress, published.rootPublicKey, rootFingerprint(published.rootPublicKey, primitives), sharingKeys, verified)
    }

    suspend fun publishedCounterparty(connection: ConnectionRecord): PublishedCounterparty? {
        val key = "${connection.id}|${connection.username}"
        guard.withLock { counterparties[key] }?.let { return it }
        val fetched = fetchPublishedCounterparty(connection.username) ?: return null
        guard.withLock { counterparties[key] = fetched }
        return fetched
    }

    suspend fun judgeCounterparty(published: PublishedCounterparty, mayPin: Boolean): ConnectionTrust {
        if (!published.proofVerified) return ConnectionTrust.ProofInvalid(published.fingerprint)
        var pinned = addressBook.load().pins[published.userAddress]
        if (pinned == null) {
            if (!mayPin) return ConnectionTrust.Unpinned(published.fingerprint)
            pinned = addressBook.edit(pinRoot(published.userAddress, published.rootPublicKey)).pins.getValue(published.userAddress)
        }
        if (pinned.rootPublicKey != published.rootPublicKey) {
            return ConnectionTrust.RootChanged(published.fingerprint, rootFingerprint(pinned.rootPublicKey, primitives))
        }
        return ConnectionTrust.Trusted(published.fingerprint)
    }

    suspend fun verifyConnection(connection: ConnectionRecord): ConnectionTrust {
        val published = publishedCounterparty(connection) ?: return ConnectionTrust.Unresolvable
        if (published.userAddress != connection.userAddress) return ConnectionTrust.AccountChanged
        val awaitingMe = !connection.isAccepted && !connection.isOutbound
        return judgeCounterparty(published, mayPin = !awaitingMe)
    }

    suspend fun assertConnectionTrusted(connection: ConnectionRecord) {
        val trust = verifyConnection(connection)
        if (trust !is ConnectionTrust.Trusted) throw ConnectionNotTrustedException(trust)
    }

    private fun sealSubkeys(connectionKey: SecretBytes): List<ConnectionKeyRecord> = sharableScopes().map { scope ->
        deriveShareSubkey(connectionKey, scope, primitives).use { subkey ->
            val current = session.currentKek(scope)
            ConnectionKeyRecord(scope.wire, current.generation, sealSecretBlob(subkey, current.kek, primitives))
        }
    }

    suspend fun storeSubkeys(connection: ConnectionRecord, connectionKey: SecretBytes): List<ConnectionKeyRecord> {
        var retried = false
        while (true) {
            val keys = sealSubkeys(connectionKey)
            try {
                putConnectionKeys(context, connection.id, keys)
                remember(current(connection).with(keys = keys))
                return keys
            } catch (error: ApiError) {
                if (retried || !error.isStaleKeyGeneration) throw error
                retried = true
                refreshKeyrings(context.api, session, primitives)
            }
        }
    }

    private suspend fun ensureKek(scope: Scope, generation: Int): SecretBytes {
        if (!session.hasKek(scope, generation)) refreshKeyrings(context.api, session, primitives)
        return session.kek(scope, generation)
    }

    suspend fun connectionKeyFor(connection: ConnectionRecord): SecretBytes {
        session.requireScope(Scope.SHARING)
        val held = current(connection)
        if (held.isOutbound) {
            val wrapped = held.senderWrappedKey ?: throw ConnectionNotOpenableException()
            return openSecretBlob(wrapped, ensureKek(Scope.SHARING, held.senderKeyGeneration), primitives)
        }
        val blob = held.pqxdhBlob ?: throw ConnectionNotOpenableException()
        ensureKek(Scope.SHARING, held.recipientKeyGeneration)
        val sharing = session.sharingKeys(held.recipientKeyGeneration)
        return openConnectionKey(
            blob,
            RecipientSecrets(rawX25519Agreement(sharing.x25519PrivateKey, primitives), sharing.mlkemSecretKey),
            held.userAddress,
            session.userAddress,
            primitives,
        )
    }

    private suspend fun encapsulateTo(published: PublishedCounterparty, username: String): Pair<ConnectionRecord, SecretBytes> {
        val connectionKey = createConnectionKey(primitives)
        try {
            val blob = sealConnectionKey(
                connectionKey,
                publishedRecipientKeys(published.sharingKeys.x25519PublicKey, published.sharingKeys.mlkemPublicKey),
                session.userAddress,
                published.userAddress,
                primitives,
            )
            val sharing = session.currentKek(Scope.SHARING)
            val connection = createConnection(
                context,
                username,
                blob,
                sealSecretBlob(connectionKey, sharing.kek, primitives),
                sharing.generation,
                published.sharingKeys.generation,
            )
            return remember(connection) to connectionKey
        } catch (error: Throwable) {
            connectionKey.zero()
            throw error
        }
    }

    suspend fun inviteByUsername(username: String, existing: List<ConnectionRecord> = emptyList()): InvitationDraft {
        session.requireScope(Scope.SHARING)
        if (connectionWith(existing, username) != null) throw AlreadyConnectedException(username)
        val resolved = resolveUsername(context.api, username) ?: throw UnknownRecipientException(username)
        if (connectionWith(existing, resolved.username) != null) throw AlreadyConnectedException(resolved.username)
        var published = fetchPublishedCounterparty(resolved.username) ?: throw UnknownRecipientException(username)
        judgeCounterparty(published, mayPin = true).let { if (it !is ConnectionTrust.Trusted) throw ConnectionNotTrustedException(it) }
        val made = try {
            encapsulateTo(published, resolved.username)
        } catch (error: ApiError) {
            if (error.status == 409 && error.code == "CONFLICT") throw AlreadyConnectedException(resolved.username)
            if (!error.isStaleKeyGeneration) throw error
            refreshKeyrings(context.api, session, primitives)
            published = fetchPublishedCounterparty(resolved.username) ?: throw UnknownRecipientException(username)
            judgeCounterparty(published, mayPin = true).let { if (it !is ConnectionTrust.Trusted) throw ConnectionNotTrustedException(it) }
            encapsulateTo(published, resolved.username)
        }
        return made.second.use { key ->
            storeSubkeys(made.first, key)
            InvitationDraft(current(made.first), published.fingerprint)
        }
    }

    suspend fun acceptInvitation(connection: ConnectionRecord) {
        connectionKeyFor(connection).use { storeSubkeys(connection, it) }
        acceptConnection(context, connection.id)
        remember(current(connection).with(status = ConnectionStatus.ACCEPTED))
        val published = publishedCounterparty(connection)
        if (published != null && published.userAddress == connection.userAddress) judgeCounterparty(published, mayPin = true)
    }

    suspend fun shareSubkey(connection: ConnectionRecord, scope: Scope): SecretBytes {
        session.requireScope(scope)
        val stored = current(connection).subkeys.firstOrNull { it.scope == scope.wire }
        if (stored != null) return openSecretBlob(stored.wrappedKey, ensureKek(scope, stored.keyGeneration), primitives)
        if (!session.holds(Scope.SHARING)) throw ScopeNotSharedException(scope)
        return connectionKeyFor(connection).use { key ->
            storeSubkeys(connection, key)
            deriveShareSubkey(key, scope, primitives)
        }
    }

    private suspend fun itemDek(itemType: ScopedItemType, itemId: String): SecretBytes {
        val (wrapped, generation) = when (itemType) {
            ScopedItemType.SECRET -> getSecret(context, itemId).let { it.wrappedDek to it.keyGeneration }
            ScopedItemType.NOTE -> getNote(context, itemId).let { it.wrappedDek to it.keyGeneration }
            ScopedItemType.FILE -> getFileDownload(context, itemId).let { it.wrappedDek to it.keyGeneration }
            ScopedItemType.DOCUMENT -> throw DocumentsNotInCoreException()
        }
        return ScopeDeks(context, itemType.scope).unwrap(wrapped, generation)
    }

    private suspend fun sendUnderConnection(connection: ConnectionRecord, itemType: ScopedItemType, itemId: String, dek: SecretBytes): ShareRecord =
        shareSubkey(connection, itemType.scope).use { subkey ->
            createShare(context, connection.id, itemType, itemId, wrapUnderConnection(subkey, dek, primitives))
        }

    suspend fun shareItem(connection: ConnectionRecord, itemType: ScopedItemType, itemId: String, dek: SecretBytes): ShareRecord {
        assertConnectionTrusted(connection)
        return sendUnderConnection(connection, itemType, itemId, dek)
    }

    suspend fun shareItemById(connection: ConnectionRecord, itemType: ScopedItemType, itemId: String): ShareRecord {
        assertConnectionTrusted(connection)
        return itemDek(itemType, itemId).use { sendUnderConnection(connection, itemType, itemId, it) }
    }

    suspend fun sharedItemDek(connection: ConnectionRecord, itemType: ScopedItemType, wrappedDek: String?): SecretBytes {
        val wrapped = wrappedDek ?: throw ConnectionNotOpenableException()
        return shareSubkey(connection, itemType.scope).use { unwrapUnderConnection(it, wrapped, primitives) }
    }

    suspend fun openSharedText(connection: ConnectionRecord, shareId: String): String {
        val shared = getSharedItem(context, shareId)
        return sharedItemDek(connection, itemTypeOf(shared.itemType), shared.wrappedDek).use { openText(shared.ciphertext, it, primitives) }
    }

    suspend fun openSharedFile(connection: ConnectionRecord, shareId: String, store: ObjectStore, sink: PlaintextSink): FileManifest {
        val shared = getSharedItem(context, shareId)
        val download = getSharedDownload(context, shareId)
        return sharedItemDek(connection, ScopedItemType.FILE, download.wrappedDek).use { dek ->
            val manifest = openManifest(shared.ciphertext, dek, primitives)
            store.read(download.url) { decryptObject(it, manifest, dek, sink, primitives = primitives) }
            manifest
        }
    }

    suspend fun openSharedFileBytes(connection: ConnectionRecord, shareId: String, store: ObjectStore, maxBytes: Long = DEFAULT_DOWNLOAD_BUFFER_BYTES): SharedFile {
        var out = ByteArray(0)
        var at = 0
        val manifest = openSharedFile(connection, shareId, store) { bytes, offset, length ->
            val needed = at + length
            if (needed > maxBytes) throw DownloadBufferExceededException(needed.toLong(), maxBytes)
            if (needed > out.size) out = out.copyOf(maxOf(needed, out.size * 2))
            bytes.copyInto(out, at, offset, offset + length)
            at += length
        }
        return SharedFile(manifest, out.copyOf(at))
    }

    suspend fun copySharedItem(connection: ConnectionRecord, share: ShareRecord, store: ObjectStore): Pair<ScopedItemType, String> {
        val itemType = itemTypeOf(share.itemType)
        session.requireScope(itemType.scope)
        return when (itemType) {
            ScopedItemType.SECRET -> itemType to createSecret(context, openSharedText(connection, share.id)).secret.id
            ScopedItemType.NOTE -> itemType to createNote(context, openSharedText(connection, share.id)).note.id
            ScopedItemType.FILE -> {
                val file = openSharedFileBytes(connection, share.id, store)
                try {
                    itemType to uploadFile(context, ByteArrayUpload(file.manifest.name, file.manifest.mime, file.bytes), store).id
                } finally {
                    file.bytes.fill(0)
                }
            }
            ScopedItemType.DOCUMENT -> throw DocumentsNotInCoreException()
        }
    }

    private fun describeOpened(base: ReceivedItem, itemType: ScopedItemType, dek: SecretBytes, ciphertext: String): ReceivedItem = when (itemType) {
        ScopedItemType.FILE -> openManifest(ciphertext, dek, primitives).let { base.copy(name = it.name, readable = true, sizeBytes = it.size, mime = it.mime) }
        ScopedItemType.DOCUMENT -> base.copy(readable = true)
        ScopedItemType.SECRET -> {
            val plaintext = openText(ciphertext, dek, primitives)
            try {
                val payload = decodeSecretPayload(plaintext)
                base.copy(name = payload.name, readable = true, text = payload.value)
            } catch (_: MalformedSecretPayloadException) {
                base.copy(readable = true, text = plaintext)
            }
        }
        ScopedItemType.NOTE -> openText(ciphertext, dek, primitives).let { base.copy(name = noteTitle(it), readable = true, text = it) }
    }

    private suspend fun describe(base: ReceivedItem, wrappedDek: String?, connection: ConnectionRecord, fetch: suspend () -> String): ReceivedItem {
        val itemType = try {
            itemTypeOf(base.itemType)
        } catch (_: IllegalArgumentException) {
            return base.copy(problem = "unknown item type")
        }
        var step = "unwrapping the item key"
        return try {
            sharedItemDek(connection, itemType, wrappedDek).use { dek ->
                step = "fetching the item"
                val ciphertext = fetch()
                step = "opening the payload"
                describeOpened(base, itemType, dek, ciphertext)
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: SessionLockedException) {
            throw error
        } catch (error: SecretZeroedException) {
            throw error
        } catch (error: Exception) {
            base.copy(problem = "$step: ${error.message ?: "the payload did not open"}")
        }
    }

    suspend fun describeReceived(share: ShareRecord, connection: ConnectionRecord?): ReceivedItem {
        val base = ReceivedItem(share.id, share.connectionId, share.itemType, share.itemId, ConnectionDirection.INBOUND, share.senderUsername ?: connection?.username ?: "", share.createdAt, null, false)
        if (connection == null) return base.copy(problem = "the connection it came through is gone")
        return describe(base, share.wrappedDek, connection) { getSharedItem(context, share.id).ciphertext }
    }

    suspend fun describeSent(share: ConnectionShareRecord, connection: ConnectionRecord): ReceivedItem {
        val base = ReceivedItem(share.id, connection.id, share.itemType, share.itemId, ConnectionDirection.OUTBOUND, connection.username, share.createdAt, null, false)
        return describe(base, share.wrappedDek, connection) {
            when (itemTypeOf(share.itemType)) {
                ScopedItemType.SECRET -> getSecret(context, share.itemId).ciphertext
                ScopedItemType.NOTE -> getNote(context, share.itemId).ciphertext
                ScopedItemType.FILE -> getFileDownload(context, share.itemId).ciphertext
                ScopedItemType.DOCUMENT -> ""
            }
        }
    }

    suspend fun describeConnection(connection: ConnectionRecord): List<ReceivedItem> = listConnectionShares(context, connection.id).map { share ->
        if (share.direction == ConnectionDirection.OUTBOUND) {
            describeSent(share, connection)
        } else {
            describeReceived(ShareRecord(share.id, connection.id, share.itemType, share.itemId, share.wrappedDek, share.createdAt, connection.username), connection)
        }
    }

    private fun rewrapShare(share: ConnectionShareRecord, oldKey: SecretBytes, newKey: SecretBytes): ShareWrap {
        for (scope in ITEM_SCOPES) {
            val dek = deriveShareSubkey(oldKey, scope, primitives).use { subkey ->
                try {
                    unwrapUnderConnection(subkey, share.wrappedDek, primitives)
                } catch (_: ConnectionKeyException) {
                    null
                }
            } ?: continue
            return dek.use { opened -> deriveShareSubkey(newKey, scope, primitives).use { ShareWrap(share.id, wrapUnderConnection(it, opened, primitives)) } }
        }
        throw ShareNotRewrappableException(share.id)
    }

    suspend fun reestablishConnection(connection: ConnectionRecord): ReestablishOutcome {
        val held = current(connection)
        if (!held.isOutbound || !held.isAccepted) return ReestablishOutcome(false, 0)
        if (sharableScopes().size != ITEM_SCOPES.size) return ReestablishOutcome(false, 0)
        val published = fetchPublishedCounterparty(held.username) ?: return ReestablishOutcome(false, 0)
        if (published.userAddress != held.userAddress) return ReestablishOutcome(false, 0)
        if (!connectionIsStale(held, published.sharingKeys.generation)) return ReestablishOutcome(false, 0)
        judgeCounterparty(published, mayPin = false).let { if (it !is ConnectionTrust.Trusted) throw ConnectionNotTrustedException(it) }

        return connectionKeyFor(held).use { oldKey ->
            createConnectionKey(primitives).use { newKey ->
                val shares = listConnectionShares(context, held.id).map { rewrapShare(it, oldKey, newKey) }
                val folderWrap = getConnectionFolders(context, held.id)?.let { record ->
                    deriveShareSubkey(oldKey, Scope.SHARING, primitives).use { oldSubkey ->
                        deriveShareSubkey(newKey, Scope.SHARING, primitives).use { newSubkey ->
                            unwrapUnderConnection(oldSubkey, record.wrappedDek, primitives).use { dek ->
                                wrapUnderConnection(newSubkey, dek, primitives) to record.revision
                            }
                        }
                    }
                }
                val blob = sealConnectionKey(
                    newKey,
                    publishedRecipientKeys(published.sharingKeys.x25519PublicKey, published.sharingKeys.mlkemPublicKey),
                    session.userAddress,
                    published.userAddress,
                    primitives,
                )
                val sharing = session.currentKek(Scope.SHARING)
                val keys = sealSubkeys(newKey)
                val senderWrapped = sealSecretBlob(newKey, sharing.kek, primitives)
                val result = putConnectionExchange(
                    context,
                    held.id,
                    blob,
                    senderWrapped,
                    sharing.generation,
                    published.sharingKeys.generation,
                    keys,
                    shares,
                    folderWrap,
                )
                remember(
                    held.with(
                        keys = keys,
                        pqxdhBlob = blob,
                        senderWrappedKey = senderWrapped,
                        senderKeyGeneration = sharing.generation,
                        recipientKeyGeneration = published.sharingKeys.generation,
                    ),
                )
                ReestablishOutcome(true, result.shares)
            }
        }
    }

    private suspend fun foldersSubkey(connection: ConnectionRecord): SecretBytes =
        connectionKeyFor(connection).use { deriveShareSubkey(it, Scope.SHARING, primitives) }

    private suspend fun refreshConnection(connection: ConnectionRecord): ConnectionRecord =
        connections().firstOrNull { it.id == connection.id } ?: throw ConnectionGoneException()

    private fun cachedFolders(connection: ConnectionRecord): LoadedFolders? {
        val held = current(connection)
        return guard.withLock { folders[held.id] }?.takeIf { it.recipientKeyGeneration == held.recipientKeyGeneration }
    }

    private suspend fun openFolders(connection: ConnectionRecord, record: ConnectionFoldersRecord): FolderManifest {
        val held = if (record.recipientKeyGeneration != current(connection).recipientKeyGeneration) refreshConnection(connection) else current(connection)
        val opened = foldersSubkey(held).use { subkey ->
            unwrapUnderConnection(subkey, record.wrappedDek, primitives).use { dek -> openBlob(record.ciphertext, dek, primitives) }
        }
        try {
            return validateFolderManifest(parseFolderManifest(opened.decodeToString()), SHARED_FOLDER_RULES)
        } finally {
            opened.fill(0)
        }
    }

    suspend fun loadSharedFolders(connection: ConnectionRecord, fresh: Boolean = false): FolderManifest {
        session.requireScope(Scope.SHARING)
        if (!fresh) cachedFolders(connection)?.let { return it.manifest }
        val record = getConnectionFolders(context, connection.id)
        val manifest = if (record == null) emptyFolderManifest(SHARED_FOLDER_RULES) else openFolders(connection, record)
        guard.withLock { folders[connection.id] = LoadedFolders(manifest, record?.revision ?: 0, current(connection).recipientKeyGeneration) }
        return manifest
    }

    private suspend fun putFolders(connection: ConnectionRecord, manifest: FolderManifest, expectedRevision: Long): ConnectionFoldersRecord {
        val held = current(connection)
        val plaintext = formatFolderManifest(manifest).encodeToByteArray()
        try {
            val (ciphertext, wrapped) = generateDek(primitives).use { dek ->
                val sealed = sealBlob(plaintext, dek, primitives)
                sealed to foldersSubkey(held).use { wrapUnderConnection(it, dek, primitives) }
            }
            val stored = putConnectionFolders(context, held.id, ciphertext, wrapped, held.recipientKeyGeneration, expectedRevision)
            guard.withLock { folders[held.id] = LoadedFolders(manifest, stored.revision, stored.recipientKeyGeneration) }
            return stored
        } finally {
            plaintext.fill(0)
        }
    }

    suspend fun editSharedFolders(connection: ConnectionRecord, edit: FolderEdit): FolderManifest {
        var fresh = cachedFolders(connection) == null
        repeat(MAX_SHARED_FOLDERS_ATTEMPTS) {
            val reread = fresh || cachedFolders(connection) == null
            if (reread) loadSharedFolders(connection, fresh = true)
            val loaded = cachedFolders(connection) ?: guard.withLock { folders.getValue(connection.id) }
            val edited = try {
                edit.apply(loaded.manifest, SHARED_FOLDER_RULES)
            } catch (error: FolderEditException) {
                if (!reread) {
                    fresh = true
                    return@repeat
                }
                throw error
            }
            if (edited === loaded.manifest) return loaded.manifest
            val next = mergeFolderManifests(loaded.manifest, edited, SHARED_FOLDER_RULES)
            try {
                putFolders(connection, next, loaded.revision)
                return next
            } catch (error: ApiError) {
                when {
                    error.isStaleKeyGeneration -> {
                        remember(refreshConnection(connection))
                        fresh = true
                    }
                    error.status == 409 -> fresh = true
                    else -> throw error
                }
            }
        }
        throw SharedFoldersKeptChangingException()
    }

    suspend fun resetSharedFolders(connection: ConnectionRecord): FolderManifest {
        session.requireScope(Scope.SHARING)
        val manifest = emptyFolderManifest(SHARED_FOLDER_RULES)
        repeat(MAX_SHARED_FOLDERS_ATTEMPTS) {
            val record = getConnectionFolders(context, connection.id)
            try {
                putFolders(connection, manifest, record?.revision ?: 0)
                return manifest
            } catch (error: ApiError) {
                when {
                    error.isStaleKeyGeneration -> remember(refreshConnection(connection))
                    error.status == 409 -> Unit
                    else -> throw error
                }
            }
        }
        throw SharedFoldersKeptChangingException()
    }
}

private fun ReceivedItem.copy(
    name: String? = this.name,
    readable: Boolean = this.readable,
    problem: String? = this.problem,
    sizeBytes: Long? = this.sizeBytes,
    mime: String? = this.mime,
    text: String? = this.text,
) = ReceivedItem(shareId, connectionId, itemType, itemId, direction, counterparty, createdAt, name, readable, problem, sizeBytes, mime, text)
