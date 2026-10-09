package zekke.core.pin

const val PIN_LENGTH = 6

enum class PinRejection(val code: String) {
    WRONG_LENGTH("wrong-length"),
    NON_DIGIT("non-digit"),
    REPEATING_DIGIT("repeating-digit"),
    ASCENDING_SEQUENCE("ascending-sequence"),
    DESCENDING_SEQUENCE("descending-sequence"),
}

sealed interface PinValidation {
    data object Valid : PinValidation

    data class Invalid(val reason: PinRejection) : PinValidation
}

class InvalidPinException(val reason: PinRejection) : IllegalArgumentException("invalid PIN: ${reason.code}")

private fun isStrictRun(pin: CharArray, step: Int): Boolean {
    for (index in 1 until pin.size) {
        if (pin[index] - pin[index - 1] != step) return false
    }
    return true
}

fun validatePin(pin: CharArray): PinValidation = when {
    pin.size != PIN_LENGTH -> PinValidation.Invalid(PinRejection.WRONG_LENGTH)
    pin.any { it !in '0'..'9' } -> PinValidation.Invalid(PinRejection.NON_DIGIT)
    isStrictRun(pin, 0) -> PinValidation.Invalid(PinRejection.REPEATING_DIGIT)
    isStrictRun(pin, 1) -> PinValidation.Invalid(PinRejection.ASCENDING_SEQUENCE)
    isStrictRun(pin, -1) -> PinValidation.Invalid(PinRejection.DESCENDING_SEQUENCE)
    else -> PinValidation.Valid
}

fun assertValidPin(pin: CharArray) {
    val result = validatePin(pin)
    if (result is PinValidation.Invalid) throw InvalidPinException(result.reason)
}
