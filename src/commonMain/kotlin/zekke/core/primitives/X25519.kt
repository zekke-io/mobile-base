package zekke.core.primitives

interface X25519 {
    fun publicKey(privateKey: ByteArray): ByteArray
    fun sharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray

    companion object {
        const val KEY_BYTES = 32
    }
}
