package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals

class Argon2idTest {
    private val pinParameters = Argon2idParameters(iterations = 3, memoryKib = 65536, parallelism = 1, outputLength = 32)

    @Test
    fun reproducesTheDevicePinWithAThirtyTwoByteSalt() {
        val pin = TestVectors.string("pin_oprf", "pin").utf8()
        val salt = TestVectors.hex("pin_oprf", "argon2id", "device_salt_hex")
        assertEquals(
            TestVectors.string("pin_oprf", "argon2id", "device_output_hex"),
            primitives.argon2id.hash(pin, salt, pinParameters).toHex(),
        )
    }

    @Test
    fun reproducesTheAccountPinSaltedWithTheUserAddressText() {
        val pin = TestVectors.string("pin_oprf", "pin").utf8()
        val salt = TestVectors.string("seed_and_user_address", "user_address").utf8()
        assertEquals(
            TestVectors.string("pin_oprf", "argon2id", "account_output_hex"),
            primitives.argon2id.hash(pin, salt, pinParameters).toHex(),
        )
    }
}
