package zekke.core.primitives

interface EcdsaP256 {
    fun publicKey(privateKey: ByteArray): ByteArray
    fun sign(privateKey: ByteArray, message: ByteArray): ByteArray
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    companion object {
        const val PRIVATE_KEY_BYTES = 32
        const val UNCOMPRESSED_PUBLIC_KEY_BYTES = 65
        const val SIGNATURE_BYTES = 64
    }
}
