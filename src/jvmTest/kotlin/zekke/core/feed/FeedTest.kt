package zekke.core.feed

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import zekke.core.api.ApiError
import zekke.core.scopes.Scope
import zekke.core.session.ScopeNotHeldException
import zekke.core.session.SessionLockedException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalCoroutinesApi::class)
class FeedTest {
    private val replica = Replica(replicaDriver(), ACCOUNT)
    private val calls = mutableListOf<Long>()

    @Test
    fun pullsFromZeroThenFromTheCursorFollowingEveryPage() = runTest {
        val pages = mutableListOf(
            ChangesPage(listOf(change(1, "a"), change(2, "b")), cursor = 2, more = true),
            ChangesPage(listOf(change(3, "c")), cursor = 3, more = false),
            ChangesPage(emptyList(), cursor = 3, more = false),
        )
        val feed = Feed(replica, unlockedSession(), { _, since, _ -> calls += since; pages.removeAt(0) }, backgroundScope)
        assertTrue(feed.sync(FeedScope.NOTES))
        assertEquals(listOf(0L, 2L), calls)
        assertEquals(3, replica.size(FeedScope.NOTES))
        assertEquals(false, feed.sync(FeedScope.NOTES))
        assertEquals(3L, calls.last())
    }

    @Test
    fun aResetEmptiesTheScopeAndPullsFromZeroOnce() = runTest {
        replica.apply(FeedScope.NOTES, listOf(change(7, "stale")), 7, synced = true)
        val feed = Feed(replica, unlockedSession(), { _, since, _ ->
            calls += since
            if (since > 0) throw ApiError("RESET", 410, "GET /changes")
            ChangesPage(listOf(change(2, "fresh")), cursor = 2, more = false)
        }, backgroundScope)
        assertTrue(feed.sync(FeedScope.NOTES))
        assertEquals(listOf(7L, 0L), calls)
        assertEquals(listOf("fresh"), replica.items(FeedScope.NOTES, ItemTypes.NOTE).map { it.id })
    }

    @Test
    fun aCallerArrivingDuringAPullWaitsForItAndSharesOneMore() = runTest {
        val gate = CompletableDeferred<Unit>()
        var answered = 0L
        val feed = Feed(replica, unlockedSession(), { _, since, _ ->
            calls += since
            if (calls.size == 1) gate.await()
            answered += 1
            ChangesPage(listOf(change(answered, "n$answered")), cursor = answered, more = false)
        }, backgroundScope)
        val first = async { feed.sync(FeedScope.NOTES) }
        runCurrent()
        val second = async { feed.sync(FeedScope.NOTES) }
        val third = async { feed.sync(FeedScope.NOTES) }
        runCurrent()
        gate.complete(Unit)
        first.await(); second.await(); third.await()
        assertEquals(2, calls.size)
    }

    @Test
    fun aChangeIsAnnouncedUnlessTheReadIsQuiet() = runTest {
        var next = 0L
        val feed = Feed(replica, unlockedSession(), { _, _, _ -> next++; ChangesPage(listOf(change(next, "n$next")), cursor = next, more = false) }, backgroundScope)
        val seen = mutableListOf<FeedScope>()
        backgroundScope.launch { feed.changes.collect { seen += it } }
        runCurrent()
        feed.sync(FeedScope.NOTES, notify = false)
        feed.sync(FeedScope.NOTES)
        runCurrent()
        assertEquals(listOf(FeedScope.NOTES), seen)
    }

    @Test
    fun syncRunsOnlyWhileUnlockedAndOnlyForAHeldScope() = runTest {
        val session = unlockedSession(listOf(Scope.PASSWORDS))
        val feed = Feed(replica, session, { _, _, _ -> ChangesPage() }, backgroundScope)
        assertFailsWith<ScopeNotHeldException> { feed.sync(FeedScope.NOTES) }
        session.lock()
        assertFailsWith<SessionLockedException> { feed.sync(FeedScope.PASSWORDS) }
    }

    @Test
    fun pollingBacksOffWhileNothingChangesAndStopsOnLock() = runTest {
        val session = unlockedSession()
        val feed = Feed(replica, session, { _, _, _ -> ChangesPage(cursor = 0) }, backgroundScope, pollInterval = 30.seconds, maxPollInterval = 120.seconds)
        feed.sync(FeedScope.NOTES)
        feed.startPolling(listOf(FeedScope.NOTES))
        advanceTimeBy(31.seconds); runCurrent()
        assertEquals(60.seconds, feed.currentPollDelay)
        advanceTimeBy(61.seconds); runCurrent()
        assertEquals(120.seconds, feed.currentPollDelay)
        advanceTimeBy(121.seconds); runCurrent()
        assertEquals(120.seconds, feed.currentPollDelay)
        session.lock()
        advanceTimeBy(600.seconds); runCurrent()
    }
}
