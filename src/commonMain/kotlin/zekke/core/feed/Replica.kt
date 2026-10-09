package zekke.core.feed

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import zekke.core.api.wireJson
import zekke.core.feed.db.ReplicaDatabase

const val REPLICA_ACCOUNT_KEY = "user_address"

val replicaSchema: SqlSchema<QueryResult.Value<Unit>> = WipingSchema(ReplicaDatabase.Schema)

internal class WipingSchema(private val base: SqlSchema<QueryResult.Value<Unit>>) : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long get() = base.version

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> = base.create(driver)

    override fun migrate(driver: SqlDriver, oldVersion: Long, newVersion: Long, vararg callbacks: app.cash.sqldelight.db.AfterVersion): QueryResult.Value<Unit> {
        dropEverything(driver)
        return base.create(driver)
    }
}

internal fun dropEverything(driver: SqlDriver) {
    val names = driver.executeQuery(
        identifier = null,
        sql = "SELECT type, name FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'",
        mapper = { cursor ->
            val found = mutableListOf<Pair<String, String>>()
            while (cursor.next().value) found += cursor.getString(0)!! to cursor.getString(1)!!
            QueryResult.Value(found)
        },
        parameters = 0,
    ).value
    for ((type, name) in names.sortedBy { if (it.first == "index") 0 else 1 }) {
        driver.execute(null, "DROP ${type.uppercase()} IF EXISTS \"$name\"", 0)
    }
}

class Replica(driver: SqlDriver, userAddress: String) {
    private val database = ReplicaDatabase(driver)
    private val queries = database.replicaQueries

    init {
        val owner = queries.metaValue(REPLICA_ACCOUNT_KEY).executeAsOneOrNull()
        if (owner != userAddress) {
            wipe()
            queries.setMeta(REPLICA_ACCOUNT_KEY, userAddress)
        }
    }

    fun cursor(scope: FeedScope): Long = queries.cursorOf(scope.wire).executeAsOneOrNull()?.cursor ?: 0

    fun isSynced(scope: FeedScope): Boolean = queries.cursorOf(scope.wire).executeAsOneOrNull()?.synced == 1L

    fun apply(scope: FeedScope, changes: List<Change>, cursor: Long, synced: Boolean): Boolean = database.transactionWithResult {
        var changed = false
        for (change in changes) changed = applyOne(scope, change) || changed
        val current = cursor(scope)
        queries.setCursor(scope.wire, maxOf(current, cursor), if (synced || isSynced(scope)) 1 else 0)
        changed
    }

    private fun applyOne(scope: FeedScope, change: Change): Boolean {
        val held = queries.rowSeq(change.type, change.id).executeAsOneOrNull()
        val removedAt = queries.tombstoneSeq(change.type, change.id).executeAsOneOrNull() ?: 0
        if (change.tombstone) {
            if (held != null && held >= change.seq) return false
            queries.putTombstone(change.type, change.id, scope.wire, maxOf(removedAt, change.seq))
            if (held == null) return false
            queries.deleteRow(change.type, change.id)
            return true
        }
        val item = change.item ?: return false
        if (removedAt >= change.seq) return false
        if (held != null && held >= change.seq) return false
        val clean = JsonObject(item.filterValues { it != JsonNull })
        queries.putRow(change.type, change.id, scope.wire, change.seq, wireJson.encodeToString(JsonObject.serializer(), clean))
        return true
    }

    fun items(scope: FeedScope, type: String): List<ReplicaItem> =
        queries.itemsOf(scope.wire, type).executeAsList().map { ReplicaItem(it.item_id, it.seq, wireJson.parseToJsonElement(it.item).jsonObject) }

    fun size(scope: FeedScope): Long = queries.countInScope(scope.wire).executeAsOne()

    fun reset(scope: FeedScope) {
        database.transaction {
            queries.clearRows(scope.wire)
            queries.clearTombstones(scope.wire)
            queries.clearCursor(scope.wire)
        }
    }

    fun wipe() {
        database.transaction {
            queries.clearAllRows()
            queries.clearAllTombstones()
            queries.clearAllCursors()
        }
    }

    internal fun forceCursor(scope: FeedScope, cursor: Long) {
        queries.setCursor(scope.wire, cursor, if (isSynced(scope)) 1 else 0)
    }
}
