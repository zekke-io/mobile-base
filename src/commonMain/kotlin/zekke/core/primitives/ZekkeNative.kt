package zekke.core.primitives

internal expect fun zekkeNative(): ZekkeNative

internal interface ZekkeNative {
    fun randomBytes(out: ByteArray)
    fun x25519PublicKey(publicKey: ByteArray, privateKey: ByteArray): Int
    fun x25519SharedSecret(sharedSecret: ByteArray, privateKey: ByteArray, publicKey: ByteArray): Int
    fun ed25519PublicKey(publicKey: ByteArray, seed: ByteArray): Int
    fun ed25519Sign(signature: ByteArray, message: ByteArray, seed: ByteArray): Int
    fun ed25519Verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Int
    fun ristretto255IsValidPoint(point: ByteArray): Int
    fun ristretto255FromUniformBytes(point: ByteArray, uniformBytes: ByteArray): Int
    fun ristretto255ScalarMult(result: ByteArray, scalar: ByteArray, point: ByteArray): Int
    fun ristretto255ScalarMultBase(result: ByteArray, scalar: ByteArray): Int
    fun ristretto255ScalarInvert(inverse: ByteArray, scalar: ByteArray): Int
    fun ristretto255ScalarReduce(scalar: ByteArray, wideScalar: ByteArray): Int
    fun ristretto255ScalarRandom(scalar: ByteArray): Int
    fun argon2id(out: ByteArray, password: ByteArray, salt: ByteArray, iterations: Int, memoryKib: Int, parallelism: Int): Int
    fun mlKem768KeyPairFromSeed(publicKey: ByteArray, secretKey: ByteArray, seed: ByteArray): Int
    fun mlKem768Encapsulate(ciphertext: ByteArray, sharedSecret: ByteArray, publicKey: ByteArray): Int
    fun mlKem768Decapsulate(sharedSecret: ByteArray, ciphertext: ByteArray, secretKey: ByteArray): Int
}

internal const val ZEKKE_NATIVE_OK = 0
