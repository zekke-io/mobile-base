package zekke.core.primitives

interface Pbkdf2HmacSha512 {
    fun derive(password: ByteArray, salt: ByteArray, iterations: Int, outputLength: Int): ByteArray
}
