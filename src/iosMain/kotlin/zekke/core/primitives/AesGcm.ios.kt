package zekke.core.primitives

internal actual fun platformAesGcm(providers: CryptographyProviders): AesGcm = ProviderAesGcm(providers)
