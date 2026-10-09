package zekke.core.primitives

interface AesGcm {
    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray
    fun decrypt(key: ByteArray, iv: ByteArray, ciphertextWithTag: ByteArray): ByteArray?

    companion object {
        const val KEY_BYTES = 32
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
    }
}
