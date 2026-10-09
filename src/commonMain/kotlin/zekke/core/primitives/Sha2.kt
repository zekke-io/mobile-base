package zekke.core.primitives

interface Sha2 {
    fun sha256(data: ByteArray): ByteArray
    fun sha512(data: ByteArray): ByteArray
}
