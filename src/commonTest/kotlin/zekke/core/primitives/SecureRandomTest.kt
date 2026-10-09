package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class SecureRandomTest {
    @Test
    fun returnsTheRequestedSize() {
        assertEquals(0, primitives.secureRandom.nextBytes(0).size)
        assertEquals(12, primitives.secureRandom.nextBytes(12).size)
    }

    @Test
    fun twoDrawsDiffer() {
        assertFalse(primitives.secureRandom.nextBytes(32).contentEquals(primitives.secureRandom.nextBytes(32)))
    }
}
