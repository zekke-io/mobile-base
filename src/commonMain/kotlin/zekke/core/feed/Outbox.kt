package zekke.core.feed

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.NetworkError
import zekke.core.api.ZekkeApi
import zekke.core.api.assertCanonicalUuid
import zekke.core.api.wireJson
import zekke.core.feed.outboxdb.OutboxDatabase
import zekke.core.signing.currentTimestamp

val outboxSchema: SqlSchema<QueryResult.Value<Unit>> = OutboxDatabase.Schema

const val OUTBOX_ACCOUNT_KEY = "user_address"

enum class OutboxState { PENDING, NEEDS_REWRAP, REFUSED }

class OutboxEntry(
    val position: Long,
    val itemId: String,
    val scope: FeedScope,
    val method: Method,
    val path: String,
    val body: JsonObject,
    val keyGeneration: Int,
    val state: OutboxState,
    val attempts: Long,
    val createdAtEpochSeconds: Long,
)

sealed interface OutboxStop {
    data object Drained : OutboxStop

    data object Offline : OutboxStop

    data class RateLimited(val retryAfterSeconds: Long?) : OutboxStop

    data object SessionOver : OutboxStop

    data class ServerUnavailable(val status: Int) : OutboxStop
}

class OutboxFlush(val sent: Int, val waitingForRewrap: Int, val refused: Int, val stop: OutboxStop)

class SignedActionInOutboxException : IllegalArgumentException("a signed action is signed and sent while the user waits, never queued")

class OutboxRewrap(val body: JsonObject, val keyGeneration: Int)

class Outbox(driver: SqlDriver, userAddress: String, private val nowEpochSeconds: () -> Long = ::currentTimestamp) {
    private val queries = OutboxDatabase(driver).outboxQueries

    init {
        val owner = queries.metaValue(OUTBOX_ACCOUNT_KEY).executeAsOneOrNull()
        if (owner != userAddress) {
            queries.clearAll()
            queries.setMeta(OUTBOX_ACCOUNT_KEY, userAddress)
        }
    }

    fun enqueue(itemId: String, scope: FeedScope, method: Method, path: String, body: JsonObject, keyGeneration: Int): Long {
        if (method != Method.POST && method != Method.PUT) throw SignedActionInOutboxException()
        if (listOf("signature", "challenge", "pin_proof").any { it in body }) throw SignedActionInOutboxException()
        assertCanonicalUuid(itemId)
        val serialized = wireJson.encodeToString(JsonObject.serializer(), body)
        return queries.transactionWithResult {
            queries.insertEntry(itemId, scope.wire, method.name, path, serialized, keyGeneration.toLong(), OutboxState.PENDING.name, nowEpochSeconds())
            queries.lastPosition().executeAsOne()
        }
    }

    fun entries(): List<OutboxEntry> = queries.entries().executeAsList().map {
        OutboxEntry(
            position = it.position,
            itemId = it.item_id,
            scope = FeedScope.entries.first { scope -> scope.wire == it.scope },
            method = Method.valueOf(it.method),
            path = it.path,
            body = wireJson.parseToJsonElement(it.body).jsonObject,
            keyGeneration = it.key_generation.toInt(),
            state = OutboxState.valueOf(it.state),
            attempts = it.attempts,
            createdAtEpochSeconds = it.created_at,
        )
    }

    fun pendingCount(): Int = entries().count { it.state == OutboxState.PENDING }

    fun discard(position: Long) = queries.deleteEntry(position)

    fun rewrapStale(rewrap: (OutboxEntry) -> OutboxRewrap) {
        for (entry in entries().filter { it.state == OutboxState.NEEDS_REWRAP }) {
            val next = rewrap(entry)
            queries.replaceBody(wireJson.encodeToString(JsonObject.serializer(), next.body), next.keyGeneration.toLong(), OutboxState.PENDING.name, entry.position)
        }
    }

    suspend fun flush(api: ZekkeApi): OutboxFlush {
        var sent = 0
        for (entry in entries()) {
            if (entry.state != OutboxState.PENDING) continue
            queries.countAttempt(entry.position)
            val token = api.tokens.get() ?: return summary(sent, OutboxStop.SessionOver)
            try {
                api.request(entry.method, entry.path, body = entry.body, token = token)
                queries.deleteEntry(entry.position)
                sent++
            } catch (error: NetworkError) {
                return summary(sent, OutboxStop.Offline)
            } catch (error: ApiError) {
                when {
                    error.isStaleKeyGeneration -> queries.markState(OutboxState.NEEDS_REWRAP.name, entry.position)
                    error.isRateLimited -> return summary(sent, OutboxStop.RateLimited(error.retryAfterSeconds))
                    error.isSessionOver -> return summary(sent, OutboxStop.SessionOver)
                    error.status >= 500 -> return summary(sent, OutboxStop.ServerUnavailable(error.status))
                    else -> queries.markState(OutboxState.REFUSED.name, entry.position)
                }
            }
        }
        return summary(sent, OutboxStop.Drained)
    }

    private fun summary(sent: Int, stop: OutboxStop): OutboxFlush {
        val all = entries()
        return OutboxFlush(sent, all.count { it.state == OutboxState.NEEDS_REWRAP }, all.count { it.state == OutboxState.REFUSED }, stop)
    }
}
