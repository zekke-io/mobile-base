package zekke.core.pin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PinRulesTest {
    @Test
    fun acceptsSixDigitsThatAreNeitherARunNorARepeat() {
        for (pin in listOf("428193", "123457", "112233", "098765")) {
            assertEquals(PinValidation.Valid, validatePin(pin.toCharArray()), pin)
        }
    }

    @Test
    fun refusesEachRuleWithItsReason() {
        val cases = mapOf(
            "12345" to PinRejection.WRONG_LENGTH,
            "1234567" to PinRejection.WRONG_LENGTH,
            "12a456" to PinRejection.NON_DIGIT,
            "١٢٣٤٥٧" to PinRejection.NON_DIGIT,
            "111111" to PinRejection.REPEATING_DIGIT,
            "123456" to PinRejection.ASCENDING_SEQUENCE,
            "456789" to PinRejection.ASCENDING_SEQUENCE,
            "654321" to PinRejection.DESCENDING_SEQUENCE,
        )
        for ((pin, reason) in cases) {
            assertEquals(PinValidation.Invalid(reason), validatePin(pin.toCharArray()), pin)
        }
        assertEquals(PinRejection.REPEATING_DIGIT, assertFailsWith<InvalidPinException> { assertValidPin("000000".toCharArray()) }.reason)
    }
}
