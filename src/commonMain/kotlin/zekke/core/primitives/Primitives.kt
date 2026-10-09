package zekke.core.primitives

class Primitives(
    val sha2: Sha2,
    val hmacSha512: HmacSha512,
    val pbkdf2HmacSha512: Pbkdf2HmacSha512,
    val hkdf: Hkdf,
    val aesGcm: AesGcm,
    val ecdsaP256: EcdsaP256,
    val x25519: X25519,
    val mlKem768: MlKem768,
    val ed25519: Ed25519,
    val ristretto255: Ristretto255,
    val argon2id: Argon2id,
    val secureRandom: SecureRandom,
)

fun platformPrimitives(): Primitives = platformPrimitivesInstance

private val platformPrimitivesInstance: Primitives by lazy {
    val providers = CryptographyProviders(platformCryptographyProviders())
    val native = zekkeNative()
    Primitives(
        sha2 = ProviderSha2(providers),
        hmacSha512 = ProviderHmacSha512(providers),
        pbkdf2HmacSha512 = ProviderPbkdf2HmacSha512(providers),
        hkdf = ProviderHkdf(providers),
        aesGcm = ProviderAesGcm(providers),
        ecdsaP256 = ProviderEcdsaP256(providers),
        x25519 = NativeX25519(native),
        mlKem768 = NativeMlKem768(native),
        ed25519 = NativeEd25519(native),
        ristretto255 = NativeRistretto255(native),
        argon2id = NativeArgon2id(native),
        secureRandom = NativeSecureRandom(native),
    )
}
