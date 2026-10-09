package zekke.core.primitives

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal actual fun platformAesGcm(providers: CryptographyProviders): AesGcm = JcaAesGcm

private object JcaAesGcm : AesGcm {
    override fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray =
        freshCipher(Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext)

    override fun decrypt(key: ByteArray, iv: ByteArray, ciphertextWithTag: ByteArray): ByteArray? {
        require(ciphertextWithTag.size >= AesGcm.TAG_BYTES) { "an AES-GCM ciphertext carries a ${AesGcm.TAG_BYTES}-byte tag" }
        return try {
            freshCipher(Cipher.DECRYPT_MODE, key, iv).doFinal(ciphertextWithTag)
        } catch (_: AEADBadTagException) {
            null
        }
    }

    private fun freshCipher(mode: Int, key: ByteArray, iv: ByteArray): Cipher {
        require(key.size == AesGcm.KEY_BYTES) { "an AES-256-GCM key is ${AesGcm.KEY_BYTES} bytes" }
        require(iv.size == AesGcm.IV_BYTES) { "an AES-GCM IV is ${AesGcm.IV_BYTES} bytes" }
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(AesGcm.TAG_BYTES * 8, iv))
        }
    }
}
