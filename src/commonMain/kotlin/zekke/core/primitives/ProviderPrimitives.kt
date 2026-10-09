package zekke.core.primitives

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyAlgorithm
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.PBKDF2
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA512

internal expect fun platformCryptographyProviders(): List<CryptographyProvider>

internal class CryptographyProviders(private val providers: List<CryptographyProvider>) {
    fun <A : CryptographyAlgorithm> algorithm(id: CryptographyAlgorithmId<A>): A =
        providers.firstNotNullOfOrNull { it.getOrNull(id) } ?: throw PrimitiveFailureException("${id.name} lookup")
}

internal class ProviderSha2(private val providers: CryptographyProviders) : Sha2 {
    override fun sha256(data: ByteArray): ByteArray = providers.algorithm(SHA256).hasher().hashBlocking(data)

    override fun sha512(data: ByteArray): ByteArray = providers.algorithm(SHA512).hasher().hashBlocking(data)
}

internal class ProviderHmacSha512(private val providers: CryptographyProviders) : HmacSha512 {
    override fun mac(key: ByteArray, data: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "an HMAC key is never empty here" }
        return providers.algorithm(HMAC)
            .keyDecoder(SHA512)
            .decodeFromByteArrayBlocking(HMAC.Key.Format.RAW, key)
            .signatureGenerator()
            .generateSignatureBlocking(data)
    }
}

internal class ProviderPbkdf2HmacSha512(private val providers: CryptographyProviders) : Pbkdf2HmacSha512 {
    override fun derive(password: ByteArray, salt: ByteArray, iterations: Int, outputLength: Int): ByteArray {
        require(iterations > 0 && outputLength > 0) { "PBKDF2 needs a positive iteration count and output length" }
        return providers.algorithm(PBKDF2)
            .secretDerivation(SHA512, iterations, outputLength.bytes, salt)
            .deriveSecretToByteArrayBlocking(password)
    }
}

internal class ProviderHkdf(private val providers: CryptographyProviders) : Hkdf {
    override fun sha512(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): ByteArray =
        derive(SHA512, inputKeyMaterial, salt, info, outputLength)

    override fun sha256(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): ByteArray =
        derive(SHA256, inputKeyMaterial, salt, info, outputLength)

    private fun derive(
        digest: CryptographyAlgorithmId<Digest>,
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray {
        require(outputLength > 0) { "HKDF needs a positive output length" }
        return providers.algorithm(HKDF)
            .secretDerivation(digest, outputLength.bytes, salt.takeIf { it.isNotEmpty() }, info)
            .deriveSecretToByteArrayBlocking(inputKeyMaterial)
    }
}

internal class ProviderAesGcm(private val providers: CryptographyProviders) : AesGcm {
    override fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        requireKeyAndIv(key, iv)
        return cipher(key).encryptWithIvBlocking(iv, plaintext)
    }

    override fun decrypt(key: ByteArray, iv: ByteArray, ciphertextWithTag: ByteArray): ByteArray? {
        requireKeyAndIv(key, iv)
        require(ciphertextWithTag.size >= AesGcm.TAG_BYTES) { "an AES-GCM ciphertext carries a ${AesGcm.TAG_BYTES}-byte tag" }
        val cipher = cipher(key)
        return try {
            cipher.decryptWithIvBlocking(iv, ciphertextWithTag)
        } catch (_: Exception) {
            null
        }
    }

    private fun cipher(key: ByteArray) = providers.algorithm(AES.GCM)
        .keyDecoder()
        .decodeFromByteArrayBlocking(AES.Key.Format.RAW, key)
        .cipher()

    private fun requireKeyAndIv(key: ByteArray, iv: ByteArray) {
        require(key.size == AesGcm.KEY_BYTES) { "an AES-256-GCM key is ${AesGcm.KEY_BYTES} bytes" }
        require(iv.size == AesGcm.IV_BYTES) { "an AES-GCM IV is ${AesGcm.IV_BYTES} bytes" }
    }
}

internal class ProviderEcdsaP256(private val providers: CryptographyProviders) : EcdsaP256 {
    override fun publicKey(privateKey: ByteArray): ByteArray =
        decodePrivateKey(privateKey).getPublicKeyBlocking().encodeToByteArrayBlocking(EC.PublicKey.Format.RAW)

    override fun sign(privateKey: ByteArray, message: ByteArray): ByteArray =
        decodePrivateKey(privateKey)
            .signatureGenerator(SHA256, ECDSA.SignatureFormat.RAW)
            .generateSignatureBlocking(message)

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != EcdsaP256.UNCOMPRESSED_PUBLIC_KEY_BYTES || signature.size != EcdsaP256.SIGNATURE_BYTES) {
            return false
        }
        val verifier = try {
            providers.algorithm(ECDSA)
                .publicKeyDecoder(EC.Curve.P256)
                .decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW, publicKey)
                .signatureVerifier(SHA256, ECDSA.SignatureFormat.RAW)
        } catch (_: Exception) {
            return false
        }
        return verifier.tryVerifySignatureBlocking(message, signature)
    }

    private fun decodePrivateKey(privateKey: ByteArray): ECDSA.PrivateKey {
        require(P256Scalar.isValidPrivateKey(privateKey)) { "a P-256 private key is a scalar in [1, n)" }
        return providers.algorithm(ECDSA)
            .privateKeyDecoder(EC.Curve.P256)
            .decodeFromByteArrayBlocking(EC.PrivateKey.Format.RAW, privateKey)
    }
}
