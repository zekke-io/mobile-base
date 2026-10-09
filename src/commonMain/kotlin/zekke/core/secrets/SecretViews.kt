package zekke.core.secrets

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.wireJson
import zekke.core.feed.FeedScope
import zekke.core.feed.ItemTypes
import zekke.core.feed.Replica
import zekke.core.feed.ReplicaItem
import zekke.core.items.ItemContext
import zekke.core.items.utf8Length

class SecretPayload(val name: String, val value: String)

class MalformedSecretPayloadException : IllegalArgumentException("this item was not written as a name and a value")

fun encodeSecretPayload(payload: SecretPayload): String = wireJson.encodeToString(
    JsonObject.serializer(),
    buildJsonObject {
        put("name", payload.name)
        put("value", payload.value)
    },
)

fun decodeSecretPayload(plaintext: String): SecretPayload {
    val parsed = try {
        wireJson.parseToJsonElement(plaintext) as? JsonObject
    } catch (_: SerializationException) {
        null
    } ?: throw MalformedSecretPayloadException()
    val name = (parsed["name"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    val value = (parsed["value"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (name == null || value == null) throw MalformedSecretPayloadException()
    return SecretPayload(name, value)
}

class VaultRow(
    val id: String,
    val name: String,
    val value: String,
    val bytes: Int,
    val version: String,
    val updatedAt: String,
    val readable: Boolean,
)

class DeletedVaultRow(val id: String, val name: String, val readable: Boolean, val deletedAt: String)

class VaultView(val rows: List<VaultRow>, val deleted: List<DeletedVaultRow>)

class OpenedSecret(val record: SecretRecord, val plaintext: String?)

fun buildVaultRows(opened: List<OpenedSecret>): List<VaultRow> =
    opened.map(::toVaultRow).sortedByDescending { it.updatedAt }

fun buildDeletedVaultRows(opened: List<OpenedSecret>): List<DeletedVaultRow> =
    opened.mapNotNull { entry ->
        val deletedAt = entry.record.deletedAt ?: return@mapNotNull null
        val row = toVaultRow(entry)
        DeletedVaultRow(entry.record.id, row.name, row.readable, deletedAt)
    }.sortedByDescending { it.deletedAt }

private fun toVaultRow(entry: OpenedSecret): VaultRow {
    val record = entry.record
    val payload = entry.plaintext?.let {
        try {
            decodeSecretPayload(it)
        } catch (_: MalformedSecretPayloadException) {
            null
        }
    }
    return VaultRow(
        id = record.id,
        name = payload?.name ?: "",
        value = payload?.value ?: "",
        bytes = utf8Length(record.ciphertext),
        version = record.version,
        updatedAt = record.updatedAt,
        readable = payload != null,
    )
}

fun secretRecords(items: List<ReplicaItem>): List<SecretRecord> =
    items.map { wireJson.decodeFromJsonElement(SecretRecord.serializer(), it.item) }

suspend fun openSecretRecords(context: ItemContext, records: List<SecretRecord>): List<OpenedSecret> {
    val deks = secretDeks(context)
    deks.refreshForGenerations(records.map { it.keyGeneration }.toSet())
    return records.map { OpenedSecret(it, deks.openHeldTextOrNull(it.ciphertext, it.wrappedDek, it.keyGeneration)) }
}

suspend fun vaultView(context: ItemContext, items: List<ReplicaItem>): VaultView {
    val opened = openSecretRecords(context, secretRecords(items))
    val (deleted, live) = opened.partition { it.record.deletedAt != null }
    return VaultView(buildVaultRows(live), buildDeletedVaultRows(deleted))
}

suspend fun vaultView(context: ItemContext, replica: Replica): VaultView =
    vaultView(context, replica.items(FeedScope.SECRETS, ItemTypes.SECRET))
