package zekke.core.feed

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.ZekkeApi
import zekke.core.session.SessionKeystore
import zekke.core.session.SessionLockedException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

val DEFAULT_FEED_POLL: Duration = 30.seconds
val DEFAULT_FEED_MAX_POLL: Duration = 120.seconds
const val MAX_FEED_PAGES = 10_000

class FeedTooLongException(scope: FeedScope) : IllegalStateException("the ${scope.wire} feed exceeded $MAX_FEED_PAGES pages")

suspend fun fetchChanges(api: ZekkeApi, scope: FeedScope, since: Long, limit: Int): ChangesPage {
    val response = api.request(
        Method.GET,
        "/changes",
        token = api.tokens.require(),
        query = mapOf("scope" to scope.wire, "since" to since.toString(), "limit" to limit.toString()),
    )
    return if (response.data == null) ChangesPage(cursor = since) else response.decode(ChangesPage.serializer())
}

fun interface ChangesFetcher {
    suspend fun fetch(scope: FeedScope, since: Long, limit: Int): ChangesPage
}

class Feed(
    private val replica: Replica,
    private val session: SessionKeystore,
    private val fetcher: ChangesFetcher,
    private val scope: CoroutineScope,
    private val limit: Int = FEED_PAGE_LIMIT,
    private val pollInterval: Duration = DEFAULT_FEED_POLL,
    private val maxPollInterval: Duration = DEFAULT_FEED_MAX_POLL,
) {
    constructor(replica: Replica, session: SessionKeystore, api: ZekkeApi, scope: CoroutineScope) :
        this(replica, session, ChangesFetcher { feedScope, since, limit -> fetchChanges(api, feedScope, since, limit) }, scope)

    private val work = CoroutineScope(scope.coroutineContext + SupervisorJob(scope.coroutineContext[Job]))
    private val guard = Mutex()
    private val running = HashMap<FeedScope, Deferred<Boolean>>()
    private val queued = HashMap<FeedScope, Deferred<Boolean>>()
    private val changedScopes = MutableSharedFlow<FeedScope>(extraBufferCapacity = 64)
    private var pollJob: Job? = null

    var currentPollDelay: Duration = pollInterval
        private set

    val changes: SharedFlow<FeedScope> = changedScopes.asSharedFlow()

    init {
        session.onLock { stopPolling() }
    }

    suspend fun sync(feedScope: FeedScope, notify: Boolean = true): Boolean {
        val pass = guard.withLock {
            val current = running[feedScope]
            if (current == null) {
                start(feedScope, notify).also { running[feedScope] = it }
            } else {
                queued.getOrPut(feedScope) {
                    work.async {
                        runCatching { current.await() }
                        guard.withLock { queued.remove(feedScope) }
                        sync(feedScope, notify)
                    }
                }
            }
        }
        return pass.await()
    }

    suspend fun syncAll(scopes: List<FeedScope>): Boolean {
        var changed = false
        for (feedScope in scopes) {
            changed = runCatching { sync(feedScope) }.getOrDefault(false) || changed
        }
        return changed
    }

    fun startPolling(scopes: List<FeedScope>) {
        stopPolling()
        currentPollDelay = pollInterval
        pollJob = work.launch {
            while (true) {
                delay(currentPollDelay)
                if (!session.isUnlocked) break
                val changed = syncAll(scopes)
                currentPollDelay = if (changed) pollInterval else minOf(maxPollInterval, currentPollDelay * 2)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    fun close() {
        stopPolling()
        work.cancel()
    }

    private fun start(feedScope: FeedScope, notify: Boolean): Deferred<Boolean> = work.async {
        try {
            pull(feedScope).also { if (it && notify) changedScopes.tryEmit(feedScope) }
        } finally {
            guard.withLock { running.remove(feedScope) }
        }
    }

    private suspend fun pull(feedScope: FeedScope): Boolean {
        if (!session.isUnlocked) throw SessionLockedException()
        session.requireScope(feedScope.scope)
        var changed = false
        var resetDone = false
        repeat(MAX_FEED_PAGES) {
            val page = try {
                fetcher.fetch(feedScope, replica.cursor(feedScope), limit)
            } catch (error: ApiError) {
                if (error.isReset && !resetDone && replica.cursor(feedScope) > 0) {
                    replica.reset(feedScope)
                    resetDone = true
                    changed = true
                    return@repeat
                }
                throw error
            }
            val wasSynced = replica.isSynced(feedScope)
            changed = replica.apply(feedScope, page.changes, page.cursor, synced = !page.more) || changed
            if (!page.more) return changed || !wasSynced
        }
        throw FeedTooLongException(feedScope)
    }
}
