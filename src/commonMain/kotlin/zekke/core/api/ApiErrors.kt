package zekke.core.api

object ErrorCodes {
    const val INVALID_BODY = "INVALID_BODY"
    const val INVALID_PARAM = "INVALID_PARAM"
    const val UNAUTHORIZED = "UNAUTHORIZED"
    const val INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    const val NOT_FOUND = "NOT_FOUND"
    const val METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    const val CONFLICT = "CONFLICT"
    const val INVALID_BATCH = "INVALID_BATCH"
    const val STALE_KEY_GENERATION = "STALE_KEY_GENERATION"
    const val TOO_MANY_DEVICES = "TOO_MANY_DEVICES"
    const val TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"
    const val INTERNAL_ERROR = "INTERNAL_ERROR"
    const val NOT_READY = "NOT_READY"
    const val QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    const val USERNAME_UNAVAILABLE = "USERNAME_UNAVAILABLE"
    const val PLAN_REQUIRED = "PLAN_REQUIRED"
    const val UPGRADE_REQUIRED = "UPGRADE_REQUIRED"
    const val RESET = "RESET"
}

class ApiError(
    val code: String,
    val status: Int,
    val endpoint: String,
    val allow: String? = null,
    val retryAfterSeconds: Long? = null,
) : Exception("$code ($status) from $endpoint") {
    val isSessionOver: Boolean get() = status == 401 && code == ErrorCodes.UNAUTHORIZED
    val isCredentialFailure: Boolean get() = status == 401 && code == ErrorCodes.INVALID_CREDENTIALS
    val isAuthEndpointRejection: Boolean get() = status == 404 && code == ErrorCodes.NOT_FOUND
    val isUpgradeRequired: Boolean get() = status == 426
    val isPlanRequired: Boolean get() = status == 403 && code == ErrorCodes.PLAN_REQUIRED
    val isRateLimited: Boolean get() = status == 429
    val isStaleKeyGeneration: Boolean get() = status == 409 && code == ErrorCodes.STALE_KEY_GENERATION
    val isTooManyDevices: Boolean get() = status == 409 && code == ErrorCodes.TOO_MANY_DEVICES
    val isInvalidBatch: Boolean get() = status == 400 && code == ErrorCodes.INVALID_BATCH
    val isQuotaExceeded: Boolean get() = status == 507
    val isObjectTooLarge: Boolean get() = status == 413
    val isUsernameUnavailable: Boolean get() = status == 422 && code == ErrorCodes.USERNAME_UNAVAILABLE
    val isReset: Boolean get() = status == 410
}

class NetworkError(val endpoint: String, cause: Throwable? = null) : Exception("network failure calling $endpoint", cause)

class RequestTooLargeException(val bytes: Int, val limit: Int) : IllegalArgumentException("request body is $bytes bytes, over the $limit byte cap")

internal fun fallbackCode(status: Int): String = when (status) {
    400 -> ErrorCodes.INVALID_BODY
    401 -> ErrorCodes.UNAUTHORIZED
    404 -> ErrorCodes.NOT_FOUND
    405 -> ErrorCodes.METHOD_NOT_ALLOWED
    409 -> ErrorCodes.CONFLICT
    410 -> ErrorCodes.RESET
    426 -> ErrorCodes.UPGRADE_REQUIRED
    429 -> ErrorCodes.TOO_MANY_REQUESTS
    503 -> ErrorCodes.NOT_READY
    else -> ErrorCodes.INTERNAL_ERROR
}

fun parseRetryAfter(value: String?): Long? {
    val trimmed = value?.trim() ?: return null
    return if (trimmed.isNotEmpty() && trimmed.all { it in '0'..'9' }) trimmed.toLongOrNull() else null
}
