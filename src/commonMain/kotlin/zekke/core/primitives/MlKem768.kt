package zekke.core.primitives

interface MlKem768 {
    fun keyPairFromSeed(seed: ByteArray): MlKem768KeyPair
    fun encapsulate(publicKey: ByteArray): MlKem768Encapsulation
    fun decapsulate(secretKey: ByteArray, ciphertext: ByteArray): ByteArray

    companion object {
        const val SEED_BYTES = 64
        const val PUBLIC_KEY_BYTES = 1184
        const val SECRET_KEY_BYTES = 2400
        const val CIPHERTEXT_BYTES = 1088
        const val SHARED_SECRET_BYTES = 32
    }
}

class MlKem768KeyPair(val publicKey: ByteArray, val secretKey: ByteArray)

class MlKem768Encapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)
