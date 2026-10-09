package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class P256ScalarTest {
    private val order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    private val orderMinusOne = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
    private val zero = "00".repeat(32)
    private val one = "00".repeat(31) + "01"

    @Test
    fun aPrivateKeyIsAScalarBetweenOneAndTheOrder() {
        assertFalse(P256Scalar.isValidPrivateKey(zero.hexToBytes()))
        assertTrue(P256Scalar.isValidPrivateKey(one.hexToBytes()))
        assertTrue(P256Scalar.isValidPrivateKey(orderMinusOne.hexToBytes()))
        assertFalse(P256Scalar.isValidPrivateKey(order.hexToBytes()))
        assertFalse(P256Scalar.isValidPrivateKey("ff".repeat(32).hexToBytes()))
    }

    @Test
    fun addsModuloTheOrder() {
        val cases = listOf(
            Triple(
                "d7686ba4e960e3f01d2625977772d60cc5b46c5d8cc592f3f6ebd29950c11859",
                "d5945882445d3162073886e4db61686bbf589e93fd6d3ecde46d97f9b2955479",
                "acfcc4282dbe1551245eac7c52d43e78c8261043e31b333ce79f9fd006f34781",
            ),
            Triple(
                "74dea8b0558015b7e93745fc09946964a2e8cc9c0c146475f7a82f1a09a15d85",
                "39c902f5de6576d8f44b4601dc43b1b921d476e6b9f6602ca9309ca0a4f6ab3a",
                "aea7aba633e58c90dd828bfde5d81b1dc4bd4382c60ac4a2a0d8cbbaae9808bf",
            ),
            Triple(
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254c",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254a",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632545",
            ),
            Triple(orderMinusOne, one, zero),
            Triple(one, one, "00".repeat(31) + "02"),
        )
        for ((left, right, sum) in cases) {
            assertEquals(sum, P256Scalar.addModOrder(left.hexToBytes(), right.hexToBytes()).toHex())
        }
    }

    @Test
    fun refusesAScalarAtOrAboveTheOrder() {
        assertFailsWith<IllegalArgumentException> { P256Scalar.addModOrder(order.hexToBytes(), one.hexToBytes()) }
    }
}
