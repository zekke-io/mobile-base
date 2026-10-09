package zekke.core.primitives

internal object ZekkeNativeJni : ZekkeNative {
    private const val LIBRARY_NAME = "zekke_native"
    private const val LIBRARY_PATH_PROPERTY = "zekke.native.library"

    init {
        val libraryPath = System.getProperty(LIBRARY_PATH_PROPERTY)
        if (libraryPath != null) System.load(libraryPath) else System.loadLibrary(LIBRARY_NAME)
    }

    external override fun randomBytes(out: ByteArray)
    external override fun x25519PublicKey(publicKey: ByteArray, privateKey: ByteArray): Int
    external override fun x25519SharedSecret(sharedSecret: ByteArray, privateKey: ByteArray, publicKey: ByteArray): Int
    external override fun ed25519PublicKey(publicKey: ByteArray, seed: ByteArray): Int
    external override fun ed25519Sign(signature: ByteArray, message: ByteArray, seed: ByteArray): Int
    external override fun ed25519Verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Int
    external override fun ristretto255IsValidPoint(point: ByteArray): Int
    external override fun ristretto255FromUniformBytes(point: ByteArray, uniformBytes: ByteArray): Int
    external override fun ristretto255ScalarMult(result: ByteArray, scalar: ByteArray, point: ByteArray): Int
    external override fun ristretto255ScalarMultBase(result: ByteArray, scalar: ByteArray): Int
    external override fun ristretto255ScalarInvert(inverse: ByteArray, scalar: ByteArray): Int
    external override fun ristretto255ScalarReduce(scalar: ByteArray, wideScalar: ByteArray): Int
    external override fun ristretto255ScalarRandom(scalar: ByteArray): Int
    external override fun argon2id(out: ByteArray, password: ByteArray, salt: ByteArray, iterations: Int, memoryKib: Int, parallelism: Int): Int
    external override fun mlKem768KeyPairFromSeed(publicKey: ByteArray, secretKey: ByteArray, seed: ByteArray): Int
    external override fun mlKem768Encapsulate(ciphertext: ByteArray, sharedSecret: ByteArray, publicKey: ByteArray): Int
    external override fun mlKem768Decapsulate(sharedSecret: ByteArray, ciphertext: ByteArray, secretKey: ByteArray): Int
}
