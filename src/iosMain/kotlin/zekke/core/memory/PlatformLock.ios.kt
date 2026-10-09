package zekke.core.memory

import platform.Foundation.NSRecursiveLock

internal actual fun newPlatformLock(): PlatformLock = object : PlatformLock {
    private val lock = NSRecursiveLock()

    override fun lock() = lock.lock()

    override fun unlock() = lock.unlock()
}
