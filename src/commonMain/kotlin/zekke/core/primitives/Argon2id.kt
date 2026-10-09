package zekke.core.primitives

interface Argon2id {
    fun hash(password: ByteArray, salt: ByteArray, parameters: Argon2idParameters): ByteArray
}

data class Argon2idParameters(
    val iterations: Int,
    val memoryKib: Int,
    val parallelism: Int,
    val outputLength: Int,
)
