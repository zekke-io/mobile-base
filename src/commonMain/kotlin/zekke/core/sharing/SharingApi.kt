package zekke.core.sharing

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.assertCanonicalUuid
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.items.ItemContext
import zekke.core.items.itemIdOrNew
import zekke.core.items.signedBody
import zekke.core.scopes.Scope
import zekke.core.scopes.ScopedItemType
import zekke.core.signing.Action
import zekke.core.users.MalformedUsernameException
import zekke.core.users.isUsername
import zekke.core.users.normalizeUsername

object ConnectionStatus {
    const val PENDING = "pending"
    const val ACCEPTED = "accepted"
}

object ConnectionDirection {
    const val INBOUND = "inbound"
    const val OUTBOUND = "outbound"
}

@Serializable
class ConnectionKeyRecord(
    val scope: String,
    @SerialName("key_generation") val keyGeneration: Int,
    @SerialName("wrapped_key") val wrappedKey: String,
)

@Serializable
class ConnectionRecord(
    val id: String,
    val direction: String,
    val username: String,
    @SerialName("user_address") val userAddress: String,
    val status: String,
    @SerialName("pqxdh_blob") val pqxdhBlob: String? = null,
    @SerialName("sender_wrapped_key") val senderWrappedKey: String? = null,
    @SerialName("sender_key_generation") val senderKeyGeneration: Int = 0,
    @SerialName("recipient_key_generation") val recipientKeyGeneration: Int = 0,
    val keys: List<ConnectionKeyRecord>? = null,
    @SerialName("created_at") val createdAt: String = "",
) {
    val isOutbound: Boolean get() = direction == ConnectionDirection.OUTBOUND
    val isAccepted: Boolean get() = status == ConnectionStatus.ACCEPTED
    val subkeys: List<ConnectionKeyRecord> get() = keys.orEmpty()

    fun with(
        keys: List<ConnectionKeyRecord>? = this.keys,
        pqxdhBlob: String? = this.pqxdhBlob,
        senderWrappedKey: String? = this.senderWrappedKey,
        senderKeyGeneration: Int = this.senderKeyGeneration,
        recipientKeyGeneration: Int = this.recipientKeyGeneration,
        status: String = this.status,
    ) = ConnectionRecord(id, direction, username, userAddress, status, pqxdhBlob, senderWrappedKey, senderKeyGeneration, recipientKeyGeneration, keys, createdAt)
}

@Serializable
class ShareRecord(
    val id: String,
    @SerialName("connection_id") val connectionId: String,
    @SerialName("item_type") val itemType: String,
    @SerialName("item_id") val itemId: String,
    @SerialName("wrapped_dek") val wrappedDek: String? = null,
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("sender_username") val senderUsername: String? = null,
)

@Serializable
class ConnectionShareRecord(
    val id: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("item_type") val itemType: String,
    @SerialName("item_id") val itemId: String,
    val direction: String,
    @SerialName("created_at") val createdAt: String = "",
)

@Serializable
class SharedItemRecord(
    val id: String,
    @SerialName("connection_id") val connectionId: String,
    @SerialName("item_type") val itemType: String,
    @SerialName("item_id") val itemId: String,
    @SerialName("wrapped_dek") val wrappedDek: String? = null,
    val ciphertext: String,
    @SerialName("sender_username") val senderUsername: String? = null,
    @SerialName("created_at") val createdAt: String = "",
)

@Serializable
class SharedDownloadRecord(
    @SerialName("share_id") val shareId: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    val url: String,
    @SerialName("expires_at") val expiresAt: String = "",
)

@Serializable
class ItemRecipientRecord(
    val id: String,
    @SerialName("item_type") val itemType: String,
    @SerialName("item_id") val itemId: String,
    val username: String,
    @SerialName("created_at") val createdAt: String = "",
)

@Serializable
class ConnectionFoldersRecord(
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    val revision: Long,
    @SerialName("recipient_key_generation") val recipientKeyGeneration: Int,
    @SerialName("updated_at") val updatedAt: String = "",
)

@Serializable
class AddressBookRecord(
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val revision: Long,
    @SerialName("updated_at") val updatedAt: String = "",
)

@Serializable
class ExchangeResult(val shares: Int)

class ShareWrap(val id: String, val wrappedDek: String)

fun itemTypeOf(wire: String): ScopedItemType =
    ScopedItemType.entries.firstOrNull { it.wire == wire } ?: throw IllegalArgumentException("unknown item type $wire")

private suspend fun ItemContext.send(method: Method, path: String, body: JsonObject? = null) =
    api.request(method, path, body = body, token = api.tokens.require())

suspend fun createConnection(
    context: ItemContext,
    recipientUsername: String,
    pqxdhBlob: String,
    senderWrappedKey: String,
    senderKeyGeneration: Int,
    recipientKeyGeneration: Int,
    id: String? = null,
): ConnectionRecord {
    val username = normalizeUsername(recipientUsername)
    if (!isUsername(username)) throw MalformedUsernameException(recipientUsername)
    val connectionId = itemIdOrNew(id, context.primitives)
    val body = signedBody(
        context,
        Action.CONNECTION_INVITE,
        listOf(username, pqxdhBlob, senderKeyGeneration.toString(), recipientKeyGeneration.toString()),
    ) {
        put("id", connectionId)
        put("recipient_username", username)
        put("pqxdh_blob", pqxdhBlob)
        put("sender_wrapped_key", senderWrappedKey)
        put("sender_key_generation", senderKeyGeneration)
        put("recipient_key_generation", recipientKeyGeneration)
    }
    return context.send(Method.POST, "/connections", body).decode(ConnectionRecord.serializer())
}

suspend fun listConnections(context: ItemContext): List<ConnectionRecord> {
    val response = context.send(Method.GET, "/connections")
    return if (response.data == null) emptyList() else response.decode(ListSerializer(ConnectionRecord.serializer()))
}

suspend fun acceptConnection(context: ItemContext, id: String) {
    val canonical = assertCanonicalUuid(id)
    context.send(Method.POST, "/connections/$canonical/accept", signedBody(context, Action.CONNECTION_ACCEPT, listOf(canonical)))
}

suspend fun deleteConnection(context: ItemContext, id: String) {
    val canonical = assertCanonicalUuid(id)
    context.send(Method.DELETE, "/connections/$canonical", signedBody(context, Action.CONNECTION_DELETE, listOf(canonical)))
}

fun connectionKeysDigest(keys: List<ConnectionKeyRecord>, context: ItemContext): String =
    bytesToHex(context.primitives.sha2.sha256(utf8ToBytes(keys.joinToString("\n") { "${it.scope}:${it.keyGeneration}:${it.wrappedKey}" })))

suspend fun putConnectionKeys(context: ItemContext, id: String, keys: List<ConnectionKeyRecord>) {
    val canonical = assertCanonicalUuid(id)
    val body = signedBody(context, Action.CONNECTION_KEYS, listOf(canonical, connectionKeysDigest(keys, context))) {
        putJsonArray("keys") { keys.forEach { key -> addJsonObject { put("scope", key.scope); put("key_generation", key.keyGeneration); put("wrapped_key", key.wrappedKey) } } }
    }
    context.send(Method.PUT, "/connections/$canonical/keys", body)
}

suspend fun listConnectionShares(context: ItemContext, id: String): List<ConnectionShareRecord> {
    val response = context.send(Method.GET, "/connections/${assertCanonicalUuid(id)}/shares")
    return if (response.data == null) emptyList() else response.decode(ListSerializer(ConnectionShareRecord.serializer()))
}

suspend fun getConnectionFolders(context: ItemContext, id: String): ConnectionFoldersRecord? = try {
    context.send(Method.GET, "/connections/${assertCanonicalUuid(id)}/folders").decode(ConnectionFoldersRecord.serializer())
} catch (error: ApiError) {
    if (error.status == 404) null else throw error
}

suspend fun putConnectionFolders(
    context: ItemContext,
    id: String,
    ciphertext: String,
    wrappedDek: String,
    recipientKeyGeneration: Int,
    expectedRevision: Long,
): ConnectionFoldersRecord {
    val connectionId = assertCanonicalUuid(id)
    val digest = bytesToHex(context.primitives.sha2.sha256(utf8ToBytes(ciphertext)))
    val body = signedBody(
        context,
        Action.CONNECTION_FOLDERS_UPDATE,
        listOf(connectionId, expectedRevision.toString(), recipientKeyGeneration.toString(), digest),
    ) {
        put("ciphertext", ciphertext)
        put("wrapped_dek", wrappedDek)
        put("recipient_key_generation", recipientKeyGeneration)
        put("expected_revision", expectedRevision)
    }
    return context.send(Method.PUT, "/connections/$connectionId/folders", body).decode(ConnectionFoldersRecord.serializer())
}

suspend fun putConnectionExchange(
    context: ItemContext,
    id: String,
    pqxdhBlob: String,
    senderWrappedKey: String,
    senderKeyGeneration: Int,
    recipientKeyGeneration: Int,
    keys: List<ConnectionKeyRecord>,
    shares: List<ShareWrap>,
    folders: Pair<String, Long>?,
): ExchangeResult {
    val connectionId = assertCanonicalUuid(id)
    val body = signedBody(
        context,
        Action.CONNECTION_REESTABLISH,
        listOf(connectionId, pqxdhBlob, senderKeyGeneration.toString(), recipientKeyGeneration.toString()),
    ) {
        put("pqxdh_blob", pqxdhBlob)
        put("sender_wrapped_key", senderWrappedKey)
        put("sender_key_generation", senderKeyGeneration)
        put("recipient_key_generation", recipientKeyGeneration)
        putJsonArray("keys") { keys.forEach { key -> addJsonObject { put("scope", key.scope); put("key_generation", key.keyGeneration); put("wrapped_key", key.wrappedKey) } } }
        putJsonArray("shares") { shares.forEach { share -> addJsonObject { put("id", share.id); put("wrapped_dek", share.wrappedDek) } } }
        if (folders != null) putJsonObject("folders") { put("wrapped_dek", folders.first); put("expected_revision", folders.second) }
    }
    return context.send(Method.PUT, "/connections/$connectionId/exchange", body).decode(ExchangeResult.serializer())
}

suspend fun createShare(context: ItemContext, connectionId: String, itemType: ScopedItemType, itemId: String, wrappedDek: String, id: String? = null): ShareRecord {
    val shareId = itemIdOrNew(id, context.primitives)
    val connection = assertCanonicalUuid(connectionId)
    val item = assertCanonicalUuid(itemId)
    val body = signedBody(context, Action.SHARE_CREATE, listOf(connection, itemType.wire, item)) {
        put("id", shareId)
        put("connection_id", connection)
        put("item_type", itemType.wire)
        put("item_id", item)
        put("wrapped_dek", wrappedDek)
    }
    return context.send(Method.POST, "/shares", body).decode(ShareRecord.serializer())
}

suspend fun deleteShare(context: ItemContext, id: String) {
    val canonical = assertCanonicalUuid(id)
    context.send(Method.DELETE, "/shares/$canonical", signedBody(context, Action.SHARE_DELETE, listOf(canonical)))
}

suspend fun listInbox(context: ItemContext): List<ShareRecord> {
    val response = context.send(Method.GET, "/shares")
    return if (response.data == null) emptyList() else response.decode(ListSerializer(ShareRecord.serializer()))
}

suspend fun getSharedItem(context: ItemContext, shareId: String): SharedItemRecord =
    context.send(Method.GET, "/shares/${assertCanonicalUuid(shareId)}").decode(SharedItemRecord.serializer())

suspend fun getSharedDownload(context: ItemContext, shareId: String): SharedDownloadRecord =
    context.send(Method.GET, "/shares/${assertCanonicalUuid(shareId)}/download").decode(SharedDownloadRecord.serializer())

suspend fun listItemRecipients(context: ItemContext, itemType: ScopedItemType, itemId: String): List<ItemRecipientRecord> {
    val response = context.send(Method.GET, "/items/${itemType.wire}/${assertCanonicalUuid(itemId)}/shares")
    return if (response.data == null) emptyList() else response.decode(ListSerializer(ItemRecipientRecord.serializer()))
}

suspend fun getAddressBook(context: ItemContext): AddressBookRecord? = try {
    context.send(Method.GET, "/sharing/address-book").decode(AddressBookRecord.serializer())
} catch (error: ApiError) {
    if (error.status == 404) null else throw error
}

suspend fun putAddressBook(context: ItemContext, ciphertext: String, wrappedDek: String, keyGeneration: Int, expectedRevision: Long): AddressBookRecord {
    val digest = bytesToHex(context.primitives.sha2.sha256(utf8ToBytes(ciphertext)))
    val body = signedBody(context, Action.ADDRESS_BOOK_UPDATE, listOf(expectedRevision.toString(), digest)) {
        put("ciphertext", ciphertext)
        put("wrapped_dek", wrappedDek)
        put("key_generation", keyGeneration)
        put("expected_revision", expectedRevision)
    }
    return context.send(Method.PUT, "/sharing/address-book", body).decode(AddressBookRecord.serializer())
}

fun scopeOf(itemType: ScopedItemType): Scope = itemType.scope
