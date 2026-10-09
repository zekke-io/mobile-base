package zekke.core.memory

internal interface PlatformLock {
    fun lock()
    fun unlock()
}

internal expect fun newPlatformLock(): PlatformLock

internal inline fun <T> PlatformLock.withLock(block: () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}
