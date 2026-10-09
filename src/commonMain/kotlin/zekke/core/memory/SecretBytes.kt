package zekke.core.memory

import kotlin.concurrent.Volatile

class SecretZeroedException : IllegalStateException("this secret was zeroed: the session was locked or the secret was consumed")

class SecretBytes private constructor(private val bytes: ByteArray) : AutoCloseable {
    private val accessLock = newPlatformLock()

    @Volatile
    private var zeroed = false

    val size: Int get() = bytes.size

    val isZeroed: Boolean get() = zeroed

    inline fun <T> withBytes(block: (ByteArray) -> T): T {
        val opened = openForUse()
        try {
            return block(opened)
        } finally {
            closeAfterUse()
        }
    }

    @PublishedApi
    internal fun openForUse(): ByteArray {
        accessLock.lock()
        if (zeroed) {
            accessLock.unlock()
            throw SecretZeroedException()
        }
        return bytes
    }

    @PublishedApi
    internal fun closeAfterUse() {
        accessLock.unlock()
    }

    fun copy(): SecretBytes = withBytes { adopt(it.copyOf()) }

    fun copyOfRange(fromIndex: Int, toIndex: Int): SecretBytes = withBytes { adopt(it.copyOfRange(fromIndex, toIndex)) }

    fun zero() {
        accessLock.withLock {
            bytes.fill(0)
            zeroed = true
        }
        SecretRegistry.forget(this)
    }

    override fun close() = zero()

    override fun toString(): String = "SecretBytes(${bytes.size} bytes${if (zeroed) ", zeroed" else ""})"

    companion object {
        fun adopt(bytes: ByteArray): SecretBytes = SecretBytes(bytes).also(SecretRegistry::remember)
    }
}

fun ByteArray.adoptAsSecret(): SecretBytes = SecretBytes.adopt(this)

fun zeroSecrets(vararg secrets: SecretBytes?) {
    for (secret in secrets) secret?.zero()
}
