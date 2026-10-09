package zekke.core.feed

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import zekke.core.device.generateDeviceKeys
import zekke.core.keyrings.generateScopeKek
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import zekke.core.session.KeyringEntry
import zekke.core.session.SessionKeys
import zekke.core.session.SessionKeystore

internal const val ACCOUNT = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

internal fun replicaDriver(): JdbcSqliteDriver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { replicaSchema.create(it) }

internal fun outboxDriver(): JdbcSqliteDriver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY).also { outboxSchema.create(it) }

internal fun item(id: String, text: String): JsonObject = JsonObject(mapOf("id" to JsonPrimitive(id), "ciphertext" to JsonPrimitive(text)))

internal fun change(seq: Long, id: String, text: String = "c$seq", type: String = ItemTypes.NOTE) = Change(seq, type, id, item = item(id, text))

internal fun tombstone(seq: Long, id: String, type: String = ItemTypes.NOTE) = Change(seq, type, id, tombstone = true)

internal fun unlockedSession(scopes: List<Scope> = listOf(Scope.ADMIN) + KEYRING_SCOPES): SessionKeystore {
    val device = generateDeviceKeys()
    val keyrings = KEYRING_SCOPES.filter { it in scopes }.map { KeyringEntry(it, 1, generateScopeKek()) }
    return SessionKeystore().also {
        it.open(SessionKeys(ACCOUNT, "root", device.deviceId, "registration", scopes, device, keyrings, keyrings.associate { entry -> entry.scope to 1 }))
    }
}
