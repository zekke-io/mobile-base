package zekke.core.memory

object SecretRegistry {
    private val lock = newPlatformLock()
    private val live = LinkedHashSet<SecretBytes>()

    internal fun remember(secret: SecretBytes) {
        lock.withLock { live.add(secret) }
    }

    internal fun forget(secret: SecretBytes) {
        lock.withLock { live.remove(secret) }
    }

    val liveCount: Int get() = lock.withLock { live.size }

    fun zeroAll(): Int {
        var zeroedCount = 0
        while (true) {
            val snapshot = lock.withLock { live.toList() }
            if (snapshot.isEmpty()) return zeroedCount
            for (secret in snapshot) {
                secret.zero()
                zeroedCount++
            }
        }
    }
}
