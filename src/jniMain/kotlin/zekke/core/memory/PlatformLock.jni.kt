package zekke.core.memory

import java.util.concurrent.locks.ReentrantLock

internal actual fun newPlatformLock(): PlatformLock = object : PlatformLock {
    private val lock = ReentrantLock()

    override fun lock() = lock.lock()

    override fun unlock() = lock.unlock()
}
