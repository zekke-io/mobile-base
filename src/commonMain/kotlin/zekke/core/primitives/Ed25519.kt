package zekke.core.primitives

interface Ed25519 {
    fun publicKey(seed: ByteArray): ByteArray
    fun sign(seed: ByteArray, message: ByteArray): ByteArray
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    companion object {
        const val SEED_BYTES = 32
        const val PUBLIC_KEY_BYTES = 32
        const val SIGNATURE_BYTES = 64
    }
}
