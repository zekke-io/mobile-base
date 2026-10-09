package zekke.core.primitives

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.providers.jdk.JDK

internal actual fun platformCryptographyProviders(): List<CryptographyProvider> = listOf(CryptographyProvider.JDK)

internal actual fun zekkeNative(): ZekkeNative = ZekkeNativeJni
