package zekke.core.primitives

interface HmacSha512 {
    fun mac(key: ByteArray, data: ByteArray): ByteArray
}
