package zekke.core.feed

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReplicaTest {
    private val driver = replicaDriver()
    private val replica = Replica(driver, ACCOUNT)

    private fun texts() = replica.items(FeedScope.NOTES, ItemTypes.NOTE).associate { it.id to it.item.getValue("ciphertext").jsonPrimitive.content }

    @Test
    fun theNewestCopyWinsAndALateOlderOneChangesNothing() {
        assertTrue(replica.apply(FeedScope.NOTES, listOf(change(5, "n1", "new")), 5, synced = true))
        assertFalse(replica.apply(FeedScope.NOTES, listOf(change(3, "n1", "old")), 5, synced = true))
        assertEquals(mapOf("n1" to "new"), texts())
    }

    @Test
    fun aTombstoneRemovesTheRowAndKeepsAnOlderCopyFromComingBack() {
        replica.apply(FeedScope.NOTES, listOf(change(1, "n1"), change(2, "n2")), 2, synced = true)
        assertTrue(replica.apply(FeedScope.NOTES, listOf(tombstone(3, "n1")), 3, synced = true))
        assertFalse(replica.apply(FeedScope.NOTES, listOf(change(2, "n1")), 3, synced = true))
        assertEquals(setOf("n2"), texts().keys)
    }

    @Test
    fun theCursorOnlyMovesForwardAndIsAppliedWithItsPage() {
        replica.apply(FeedScope.NOTES, listOf(change(9, "n1")), 9, synced = false)
        replica.apply(FeedScope.NOTES, emptyList(), 4, synced = true)
        assertEquals(9, replica.cursor(FeedScope.NOTES))
        assertTrue(replica.isSynced(FeedScope.NOTES))
        assertEquals(0, replica.cursor(FeedScope.SECRETS))
    }

    @Test
    fun nullFieldsAreStoredAbsent() {
        val withNull = JsonObject(mapOf("id" to JsonPrimitive("n1"), "folder_id" to JsonNull))
        replica.apply(FeedScope.NOTES, listOf(Change(1, ItemTypes.NOTE, "n1", item = withNull)), 1, synced = true)
        assertFalse("folder_id" in replica.items(FeedScope.NOTES, ItemTypes.NOTE).single().item)
    }

    @Test
    fun resettingAScopeEmptiesOnlyThatScope() {
        replica.apply(FeedScope.NOTES, listOf(change(1, "n1")), 1, synced = true)
        replica.apply(FeedScope.SECRETS, listOf(change(1, "s1", type = ItemTypes.SECRET)), 1, synced = true)
        replica.reset(FeedScope.NOTES)
        assertEquals(0, replica.size(FeedScope.NOTES))
        assertEquals(0, replica.cursor(FeedScope.NOTES))
        assertEquals(1, replica.size(FeedScope.SECRETS))
    }

    @Test
    fun anotherAccountOpeningTheSameDatabaseFindsItEmpty() {
        replica.apply(FeedScope.NOTES, listOf(change(1, "n1")), 1, synced = true)
        val other = Replica(driver, "b".repeat(64))
        assertEquals(0, other.size(FeedScope.NOTES))
        assertEquals(0, other.cursor(FeedScope.NOTES))
    }

    @Test
    fun aLocalSchemaChangeWipesTheReplicaInsteadOfMigratingIt() {
        replica.apply(FeedScope.NOTES, listOf(change(1, "n1")), 1, synced = true)
        replicaSchema.migrate(driver, replicaSchema.version, replicaSchema.version + 1)
        val reopened = Replica(driver, ACCOUNT)
        assertEquals(0, reopened.size(FeedScope.NOTES))
        assertEquals(0, reopened.cursor(FeedScope.NOTES))
    }
}
