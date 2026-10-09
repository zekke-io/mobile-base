package zekke.core.primitives

private fun Int.orFail(operation: String) {
    if (this != ZEKKE_NATIVE_OK) throw PrimitiveFailureException(operation)
}

private fun requireSize(name: String, bytes: ByteArray, expected: Int) {
    require(bytes.size == expected) { "$name is $expected bytes, not ${bytes.size}" }
}

internal class NativeX25519(private val native: ZekkeNative) : X25519 {
    override fun publicKey(privateKey: ByteArray): ByteArray {
        requireSize("an X25519 private key", privateKey, X25519.KEY_BYTES)
        val publicKey = ByteArray(X25519.KEY_BYTES)
        native.x25519PublicKey(publicKey, privateKey).orFail("X25519 public key")
        return publicKey
    }

    override fun sharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        requireSize("an X25519 private key", privateKey, X25519.KEY_BYTES)
        requireSize("an X25519 public key", publicKey, X25519.KEY_BYTES)
        val sharedSecret = ByteArray(X25519.KEY_BYTES)
        native.x25519SharedSecret(sharedSecret, privateKey, publicKey).orFail("X25519 shared secret")
        return sharedSecret
    }
}

internal class NativeMlKem768(private val native: ZekkeNative) : MlKem768 {
    override fun keyPairFromSeed(seed: ByteArray): MlKem768KeyPair {
        requireSize("an ML-KEM-768 seed", seed, MlKem768.SEED_BYTES)
        val publicKey = ByteArray(MlKem768.PUBLIC_KEY_BYTES)
        val secretKey = ByteArray(MlKem768.SECRET_KEY_BYTES)
        native.mlKem768KeyPairFromSeed(publicKey, secretKey, seed).orFail("ML-KEM-768 key generation")
        return MlKem768KeyPair(publicKey, secretKey)
    }

    override fun encapsulate(publicKey: ByteArray): MlKem768Encapsulation {
        requireSize("an ML-KEM-768 public key", publicKey, MlKem768.PUBLIC_KEY_BYTES)
        val ciphertext = ByteArray(MlKem768.CIPHERTEXT_BYTES)
        val sharedSecret = ByteArray(MlKem768.SHARED_SECRET_BYTES)
        native.mlKem768Encapsulate(ciphertext, sharedSecret, publicKey).orFail("ML-KEM-768 encapsulation")
        return MlKem768Encapsulation(ciphertext, sharedSecret)
    }

    override fun decapsulate(secretKey: ByteArray, ciphertext: ByteArray): ByteArray {
        requireSize("an ML-KEM-768 secret key", secretKey, MlKem768.SECRET_KEY_BYTES)
        requireSize("an ML-KEM-768 ciphertext", ciphertext, MlKem768.CIPHERTEXT_BYTES)
        val sharedSecret = ByteArray(MlKem768.SHARED_SECRET_BYTES)
        native.mlKem768Decapsulate(sharedSecret, ciphertext, secretKey).orFail("ML-KEM-768 decapsulation")
        return sharedSecret
    }
}

internal class NativeEd25519(private val native: ZekkeNative) : Ed25519 {
    override fun publicKey(seed: ByteArray): ByteArray {
        requireSize("an Ed25519 seed", seed, Ed25519.SEED_BYTES)
        val publicKey = ByteArray(Ed25519.PUBLIC_KEY_BYTES)
        native.ed25519PublicKey(publicKey, seed).orFail("Ed25519 public key")
        return publicKey
    }

    override fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        requireSize("an Ed25519 seed", seed, Ed25519.SEED_BYTES)
        val signature = ByteArray(Ed25519.SIGNATURE_BYTES)
        native.ed25519Sign(signature, message, seed).orFail("Ed25519 signature")
        return signature
    }

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != Ed25519.PUBLIC_KEY_BYTES || signature.size != Ed25519.SIGNATURE_BYTES) {
            return false
        }
        return native.ed25519Verify(signature, message, publicKey) == ZEKKE_NATIVE_OK
    }
}

internal class NativeRistretto255(private val native: ZekkeNative) : Ristretto255 {
    override fun isValidPoint(point: ByteArray): Boolean =
        point.size == Ristretto255.POINT_BYTES && native.ristretto255IsValidPoint(point) == ZEKKE_NATIVE_OK

    override fun fromUniformBytes(uniformBytes: ByteArray): ByteArray {
        requireSize("ristretto255 uniform bytes", uniformBytes, Ristretto255.UNIFORM_BYTES)
        val point = ByteArray(Ristretto255.POINT_BYTES)
        native.ristretto255FromUniformBytes(point, uniformBytes).orFail("ristretto255 one-way map")
        return point
    }

    override fun scalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        requireSize("a ristretto255 scalar", scalar, Ristretto255.SCALAR_BYTES)
        requireSize("a ristretto255 point", point, Ristretto255.POINT_BYTES)
        val result = ByteArray(Ristretto255.POINT_BYTES)
        native.ristretto255ScalarMult(result, scalar, point).orFail("ristretto255 scalar multiplication")
        return result
    }

    override fun scalarMultBase(scalar: ByteArray): ByteArray {
        requireSize("a ristretto255 scalar", scalar, Ristretto255.SCALAR_BYTES)
        val result = ByteArray(Ristretto255.POINT_BYTES)
        native.ristretto255ScalarMultBase(result, scalar).orFail("ristretto255 base multiplication")
        return result
    }

    override fun invertScalar(scalar: ByteArray): ByteArray {
        requireSize("a ristretto255 scalar", scalar, Ristretto255.SCALAR_BYTES)
        val inverse = ByteArray(Ristretto255.SCALAR_BYTES)
        native.ristretto255ScalarInvert(inverse, scalar).orFail("ristretto255 scalar inversion")
        return inverse
    }

    override fun reduceScalar(wideScalar: ByteArray): ByteArray {
        requireSize("a wide ristretto255 scalar", wideScalar, Ristretto255.UNIFORM_BYTES)
        val scalar = ByteArray(Ristretto255.SCALAR_BYTES)
        native.ristretto255ScalarReduce(scalar, wideScalar).orFail("ristretto255 scalar reduction")
        return scalar
    }

    override fun randomScalar(): ByteArray {
        val scalar = ByteArray(Ristretto255.SCALAR_BYTES)
        native.ristretto255ScalarRandom(scalar).orFail("ristretto255 random scalar")
        return scalar
    }
}

internal class NativeArgon2id(private val native: ZekkeNative) : Argon2id {
    override fun hash(password: ByteArray, salt: ByteArray, parameters: Argon2idParameters): ByteArray {
        require(parameters.iterations > 0 && parameters.memoryKib > 0 && parameters.parallelism > 0 && parameters.outputLength > 0) {
            "Argon2id parameters are positive"
        }
        val out = ByteArray(parameters.outputLength)
        native.argon2id(out, password, salt, parameters.iterations, parameters.memoryKib, parameters.parallelism)
            .orFail("Argon2id")
        return out
    }
}

internal class NativeSecureRandom(private val native: ZekkeNative) : SecureRandom {
    override fun nextBytes(size: Int): ByteArray {
        require(size >= 0) { "a random buffer has a non-negative size" }
        val out = ByteArray(size)
        if (size > 0) native.randomBytes(out)
        return out
    }
}
