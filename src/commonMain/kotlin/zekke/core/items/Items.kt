package zekke.core.items

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import zekke.core.api.ApiError
import zekke.core.api.NetworkError
import zekke.core.api.ZekkeApi
import zekke.core.api.assertCanonicalUuid
import zekke.core.auth.putEnvelope
import zekke.core.device.generateDeviceId
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.feed.Outbox
import zekke.core.feed.OutboxEntry
import zekke.core.feed.OutboxRewrap
import zekke.core.keyrings.refreshKeyrings
import zekke.core.memory.SecretBytes
import zekke.core.memory.SecretZeroedException
import zekke.core.memory.adoptAsSecret
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope
import zekke.core.sealed.MalformedSealedBlobException
import zekke.core.sealed.SealedBlobAuthenticationException
import zekke.core.sealed.UnsupportedSealedVersionException
import zekke.core.sealed.openSecretBlob
import zekke.core.sealed.openText
import zekke.core.sealed.sealSecretBlob
import zekke.core.session.MissingGenerationException
import zekke.core.session.SessionKeystore
import zekke.core.signing.Action
import zekke.core.signing.normalizeActionArgs
import zekke.core.signing.signActionEnvelope

const val DEK_BYTES = 32

class ItemContext(
    val api: ZekkeApi,
    val session: SessionKeystore,
    val primitives: Primitives = platformPrimitives(),
)

class WrappedDek(val wrappedDek: String, val keyGeneration: Int)

class ItemTooLargeException(val bytes: Int, val limit: Int, unit: String = "bytes") :
    IllegalArgumentException("the item is $bytes $unit, over the $limit-$unit limit")

class EmptySelectionException : IllegalArgumentException("nothing was selected")

fun generateDek(primitives: Primitives = platformPrimitives()): SecretBytes =
    primitives.secureRandom.nextBytes(DEK_BYTES).adoptAsSecret()

fun newItemId(primitives: Primitives = platformPrimitives()): String = generateDeviceId(primitives)

fun itemIdOrNew(id: String?, primitives: Primitives = platformPrimitives()): String =
    if (id == null) newItemId(primitives) else assertCanonicalUuid(id)

fun hashReceivedCiphertext(ciphertext: String, primitives: Primitives = platformPrimitives()): String =
    bytesToHex(primitives.sha2.sha256(utf8ToBytes(ciphertext)))

fun utf8Length(text: String): Int = text.encodeToByteArray().size

fun codePointCount(text: String): Int {
    var count = 0
    var index = 0
    while (index < text.length) {
        val high = text[index]
        index += if (high.isHighSurrogate() && index + 1 < text.length && text[index + 1].isLowSurrogate()) 2 else 1
        count++
    }
    return count
}

fun takeCodePoints(text: String, limit: Int): String {
    var count = 0
    var index = 0
    while (index < text.length && count < limit) {
        val high = text[index]
        index += if (high.isHighSurrogate() && index + 1 < text.length && text[index + 1].isLowSurrogate()) 2 else 1
        count++
    }
    return text.substring(0, index)
}

class ScopeDeks(private val context: ItemContext, val scope: Scope) {
    fun wrap(dek: SecretBytes): WrappedDek {
        val current = context.session.currentKek(scope)
        return WrappedDek(sealSecretBlob(dek, current.kek, context.primitives), current.generation)
    }

    suspend fun unwrap(wrappedDek: String, keyGeneration: Int): SecretBytes {
        if (!context.session.hasKek(scope, keyGeneration)) refreshKeyrings(context.api, context.session, context.primitives)
        return unwrapHeld(wrappedDek, keyGeneration)
    }

    fun unwrapHeld(wrappedDek: String, keyGeneration: Int): SecretBytes =
        openSecretBlob(wrappedDek, context.session.kek(scope, keyGeneration), context.primitives)

    suspend fun openText(ciphertext: String, wrappedDek: String, keyGeneration: Int): String =
        unwrap(wrappedDek, keyGeneration).use { dek -> openText(ciphertext, dek, context.primitives) }

    fun openHeldTextOrNull(ciphertext: String, wrappedDek: String, keyGeneration: Int): String? = try {
        if (!context.session.hasKek(scope, keyGeneration)) {
            null
        } else {
            unwrapHeld(wrappedDek, keyGeneration).use { dek -> openText(ciphertext, dek, context.primitives) }
        }
    } catch (error: SecretZeroedException) {
        throw error
    } catch (_: SealedBlobAuthenticationException) {
        null
    } catch (_: MalformedSealedBlobException) {
        null
    } catch (_: UnsupportedSealedVersionException) {
        null
    } catch (_: MissingGenerationException) {
        null
    } catch (_: CharacterCodingException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    suspend fun refreshForGenerations(generations: Collection<Int>) {
        if (generations.all { context.session.hasKek(scope, it) }) return
        try {
            refreshKeyrings(context.api, context.session, context.primitives)
        } catch (error: CancellationException) {
            throw error
        } catch (_: NetworkError) {
        } catch (_: ApiError) {
        }
    }
}

internal fun signedBody(
    context: ItemContext,
    action: Action,
    args: List<String>,
    fields: JsonObjectBuilder.() -> Unit = {},
): JsonObject {
    val envelope = signActionEnvelope(action, args, context.session.signer(), context.primitives)
    return buildJsonObject {
        fields()
        putEnvelope(envelope)
    }
}

internal fun canonicalSelection(action: Action, ids: List<String>): List<String> {
    if (ids.isEmpty()) throw EmptySelectionException()
    return normalizeActionArgs(action, ids.map { assertCanonicalUuid(it) })
}

fun rewrapQueuedBody(context: ItemContext, entry: OutboxEntry): OutboxRewrap {
    val deks = ScopeDeks(context, entry.scope.scope)
    val wrapped = entry.body.getValue("wrapped_dek").jsonPrimitive.content
    val generation = entry.body.getValue("key_generation").jsonPrimitive.int
    return deks.unwrapHeld(wrapped, generation).use { dek ->
        val next = deks.wrap(dek)
        val body = JsonObject(
            entry.body + mapOf("wrapped_dek" to JsonPrimitive(next.wrappedDek), "key_generation" to JsonPrimitive(next.keyGeneration)),
        )
        OutboxRewrap(body, next.keyGeneration)
    }
}

suspend fun rewrapStaleEntries(context: ItemContext, outbox: Outbox) {
    refreshKeyrings(context.api, context.session, context.primitives)
    outbox.rewrapStale { entry -> rewrapQueuedBody(context, entry) }
}
