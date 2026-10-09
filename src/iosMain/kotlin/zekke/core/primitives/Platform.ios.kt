package zekke.core.primitives

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.providers.apple.Apple
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit

internal actual fun platformCryptographyProviders(): List<CryptographyProvider> =
    listOf(CryptographyProvider.CryptoKit, CryptographyProvider.Apple)

internal actual fun zekkeNative(): ZekkeNative = ZekkeNativeCinterop
