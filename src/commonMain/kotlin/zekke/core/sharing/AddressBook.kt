package zekke.core.sharing

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import zekke.core.api.ApiError
import zekke.core.api.wireJson
import zekke.core.encoding.bytesToUtf8
import zekke.core.encoding.zeroBytes
import zekke.core.folders.nowTimestamp
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.generateDek
import zekke.core.keyrings.refreshKeyrings
import zekke.core.scopes.Scope
import zekke.core.sealed.openBlob
import zekke.core.sealed.sealBlob

const val ADDRESS_BOOK_VERSION = 1
const val MAX_ADDRESS_BOOK_ATTEMPTS = 4

@Serializable
data class RootPin(@SerialName("root_public_key") val rootPublicKey: String, @SerialName("pinned_at") val pinnedAt: String)

@Serializable
data class NamedEntry(val name: String, @SerialName("updated_at") val updatedAt: String)

@Serializable
class AddressBook(
    val v: Int = ADDRESS_BOOK_VERSION,
    val pins: Map<String, RootPin> = emptyMap(),
    val nicknames: Map<String, NamedEntry> = emptyMap(),
    val devices: Map<String, NamedEntry> = emptyMap(),
)

class AddressBookFormatException : IllegalStateException("the address book did not decode as a known version")

class AddressBookKeptChangingException : IllegalStateException("the address book kept changing on another device; try again")

fun interface AddressBookEdit {
    fun apply(book: AddressBook): AddressBook
}

fun emptyAddressBook(): AddressBook = AddressBook()

fun parseAddressBook(text: String): AddressBook {
    val book = try {
        wireJson.decodeFromString(AddressBook.serializer(), text)
    } catch (_: SerializationException) {
        throw AddressBookFormatException()
    } catch (_: IllegalArgumentException) {
        throw AddressBookFormatException()
    }
    if (book.v != ADDRESS_BOOK_VERSION) throw AddressBookFormatException()
    return book
}

fun formatAddressBook(book: AddressBook): String = wireJson.encodeToString(AddressBook.serializer(), book)

private fun mergeNamed(stored: Map<String, NamedEntry>, local: Map<String, NamedEntry>): Map<String, NamedEntry> {
    val merged = LinkedHashMap(stored)
    for ((id, entry) in local) {
        val held = merged[id]
        if (held == null || entry.updatedAt > held.updatedAt) merged[id] = entry
    }
    return merged
}

fun mergeAddressBooks(stored: AddressBook, local: AddressBook): AddressBook = AddressBook(
    pins = LinkedHashMap(local.pins).apply { putAll(stored.pins) },
    nicknames = mergeNamed(stored.nicknames, local.nicknames),
    devices = mergeNamed(stored.devices, local.devices),
)

fun setNickname(connectionId: String, name: String, at: String = nowTimestamp()) = AddressBookEdit { book ->
    AddressBook(book.v, book.pins, book.nicknames + (connectionId to NamedEntry(name.trim(), at)), book.devices)
}

fun setDeviceName(deviceId: String, name: String, at: String = nowTimestamp()) = AddressBookEdit { book ->
    AddressBook(book.v, book.pins, book.nicknames, book.devices + (deviceId to NamedEntry(name.trim(), at)))
}

fun pinRoot(userAddress: String, rootPublicKey: String, at: String = nowTimestamp()) = AddressBookEdit { book ->
    if (userAddress in book.pins) book else AddressBook(book.v, book.pins + (userAddress to RootPin(rootPublicKey, at)), book.nicknames, book.devices)
}

fun displayName(entry: NamedEntry?): String? = entry?.name?.trim()?.takeIf { it.isNotEmpty() }

internal class AddressBookStore(private val context: ItemContext) {
    private class Loaded(val book: AddressBook, val revision: Long)

    private var loaded: Loaded? = null

    fun forget() {
        loaded = null
    }

    private suspend fun open(record: AddressBookRecord): AddressBook {
        val opened = ScopeDeks(context, Scope.SHARING).unwrap(record.wrappedDek, record.keyGeneration).use { dek ->
            openBlob(record.ciphertext, dek, context.primitives)
        }
        try {
            return parseAddressBook(bytesToUtf8(opened))
        } finally {
            zeroBytes(opened)
        }
    }

    private fun seal(book: AddressBook): Triple<String, String, Int> {
        val plaintext = formatAddressBook(book).encodeToByteArray()
        try {
            return generateDek(context.primitives).use { dek ->
                val wrapped = ScopeDeks(context, Scope.SHARING).wrap(dek)
                Triple(sealBlob(plaintext, dek, context.primitives), wrapped.wrappedDek, wrapped.keyGeneration)
            }
        } finally {
            zeroBytes(plaintext)
        }
    }

    suspend fun load(fresh: Boolean = false): AddressBook {
        if (!fresh) loaded?.let { return it.book }
        val record = getAddressBook(context)
        val next = if (record == null) Loaded(emptyAddressBook(), 0) else Loaded(open(record), record.revision)
        loaded = next
        return next.book
    }

    suspend fun edit(edit: AddressBookEdit): AddressBook {
        var fresh = loaded == null
        repeat(MAX_ADDRESS_BOOK_ATTEMPTS) {
            if (fresh || loaded == null) load(fresh = true)
            val held = loaded!!
            val next = edit.apply(held.book)
            if (next === held.book) return held.book
            try {
                val (ciphertext, wrappedDek, generation) = seal(next)
                val stored = putAddressBook(context, ciphertext, wrappedDek, generation, held.revision)
                loaded = Loaded(next, stored.revision)
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
        throw AddressBookKeptChangingException()
    }
}
