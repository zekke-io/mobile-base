package zekke.core.rekey

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.items.ItemContext
import zekke.core.items.ScopeDeks
import zekke.core.items.generateDek
import zekke.core.items.hashReceivedCiphertext
import zekke.core.items.signedBody
import zekke.core.keyrings.refreshKeyrings
import zekke.core.scopes.Scope
import zekke.core.sealed.openBlob
import zekke.core.sealed.sealBlob
import zekke.core.signing.Action

val PREFERENCES_SCOPE: Scope = Scope.DOCUMENTS
const val MAX_PREFERENCES_ATTEMPTS = 4

@Serializable
class PreferencesRecord(
    val ciphertext: String,
    @SerialName("wrapped_dek") val wrappedDek: String,
    @SerialName("key_generation") val keyGeneration: Int,
    val revision: Long,
    @SerialName("updated_at") val updatedAt: String = "",
)

class PreferencesKeptChangingException : IllegalStateException("the preferences kept changing on another device; try again")

suspend fun getPreferencesRecord(context: ItemContext): PreferencesRecord? = try {
    context.api.request(Method.GET, "/preferences", token = context.api.tokens.require()).decode(PreferencesRecord.serializer())
} catch (error: ApiError) {
    if (error.status == 404) null else throw error
}

suspend fun resealPreferences(context: ItemContext): Boolean {
    if (!context.session.holds(PREFERENCES_SCOPE)) return false
    val deks = ScopeDeks(context, PREFERENCES_SCOPE)
    repeat(MAX_PREFERENCES_ATTEMPTS) {
        val record = getPreferencesRecord(context) ?: return false
        if (record.keyGeneration >= context.session.currentGeneration(PREFERENCES_SCOPE)) return false
        val plaintext = deks.unwrap(record.wrappedDek, record.keyGeneration).use { openBlob(record.ciphertext, it, context.primitives) }
        try {
            val (ciphertext, wrapped) = generateDek(context.primitives).use { dek -> sealBlob(plaintext, dek, context.primitives) to deks.wrap(dek) }
            val digest = hashReceivedCiphertext(ciphertext, context.primitives)
            val body = signedBody(context, Action.PREFERENCES_UPDATE, listOf(record.revision.toString(), digest)) {
                put("ciphertext", ciphertext)
                put("wrapped_dek", wrapped.wrappedDek)
                put("key_generation", wrapped.keyGeneration)
                put("expected_revision", record.revision)
            }
            context.api.request(Method.PUT, "/preferences", body = body, token = context.api.tokens.require())
            return true
        } catch (error: ApiError) {
            if (error.status != 409) throw error
            if (error.isStaleKeyGeneration) refreshKeyrings(context.api, context.session, context.primitives)
        } finally {
            plaintext.fill(0)
        }
    }
    throw PreferencesKeptChangingException()
}
