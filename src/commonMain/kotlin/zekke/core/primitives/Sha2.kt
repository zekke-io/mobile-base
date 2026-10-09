package zekke.core.primitives

interface Sha2 {
    fun sha256(data: ByteArray): ByteArray
    fun sha512(data: ByteArray): ByteArray
    fun sha256Stream(): StreamingHash
}

interface StreamingHash : AutoCloseable {
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset)
    fun finish(): ByteArray
}
