package zekke.core.memory

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class SecretBytesConcurrencyTest {
    @Test
    fun zeroingWaitsForAUseInProgressAndThenRefusesTheNext() {
        val secret = byteArrayOf(1, 2, 3, 4).adoptAsSecret()
        val inUse = CountDownLatch(1)
        val release = CountDownLatch(1)
        var seenDuringUse = ByteArray(0)

        val user = thread {
            secret.withBytes { bytes ->
                inUse.countDown()
                release.await(5, TimeUnit.SECONDS)
                seenDuringUse = bytes.copyOf()
            }
        }
        inUse.await(5, TimeUnit.SECONDS)

        val zeroer = thread { SecretRegistry.zeroAll() }
        Thread.sleep(200)
        assertTrue(zeroer.isAlive, "the lock must wait while the key is in use")

        release.countDown()
        user.join(5_000)
        zeroer.join(5_000)

        assertContentEquals(byteArrayOf(1, 2, 3, 4), seenDuringUse, "a use in progress finishes with the real key")
        assertTrue(secret.isZeroed)
    }
}
