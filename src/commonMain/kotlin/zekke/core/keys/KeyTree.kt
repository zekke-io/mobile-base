package zekke.core.keys

import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.uncompressedPointToSpkiBase64
import zekke.core.encoding.utf8ToBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

val IDENTITY_PATH: List<Long> = listOf(9027L, 0L, 0L)
const val X25519_HKDF_INFO = "Cryple-Key-v1|x25519"
const val MLKEM768_HKDF_INFO = "Cryple-Key-v1|mlkem768"
const val VAULT_KEK_HKDF_INFO = "Cryple-Key-v1|vault-kek"
val ROOT_SIGNING_PATH: List<Long> = IDENTITY_PATH
const val ROOT_WRAP_HKDF_INFO = VAULT_KEK_HKDF_INFO

private const val X25519_KEY_LENGTH = 32
private const val MLKEM768_SEED_LENGTH = 64
private const val VAULT_KEK_LENGTH = 32

private val EMPTY_SALT = ByteArray(0)

class IdentityKey(
    val privateKey: SecretBytes,
    val chainCode: SecretBytes,
    val publicKeyUncompressed: ByteArray,
    val publicKeySpkiBase64: String,
)

class X25519Key(val privateKey: SecretBytes, val publicKey: ByteArray, val publicKeyBase64: String)

class MlKem768Key(val seed: SecretBytes, val secretKey: SecretBytes, val publicKey: ByteArray, val publicKeyBase64: String)

class ZekkeKeyTree(
    val seed: SecretBytes,
    val userAddress: String,
    val identity: IdentityKey,
    val x25519: X25519Key,
    val mlkem768: MlKem768Key,
    val vaultKek: SecretBytes,
)

class RootKeys(val userAddress: String, val signing: IdentityKey, val wrapKey: SecretBytes)

private fun hkdfSha512(primitives: Primitives, seed: SecretBytes, info: String, length: Int): SecretBytes =
    seed.withBytes { primitives.hkdf.sha512(it, EMPTY_SALT, utf8ToBytes(info), length) }.adoptAsSecret()

fun deriveUserAddress(seed: SecretBytes, primitives: Primitives = platformPrimitives()): String =
    bytesToHex(seed.withBytes { primitives.sha2.sha256(it) })

fun deriveIdentityKey(seed: SecretBytes, primitives: Primitives = platformPrimitives()): IdentityKey {
    val node = deriveHardenedPath(seed, IDENTITY_PATH, primitives)
    val publicKeyUncompressed = node.privateKey.withBytes { primitives.ecdsaP256.publicKey(it) }
    return IdentityKey(
        privateKey = node.privateKey,
        chainCode = node.chainCode,
        publicKeyUncompressed = publicKeyUncompressed,
        publicKeySpkiBase64 = uncompressedPointToSpkiBase64(publicKeyUncompressed),
    )
}

fun deriveX25519Key(seed: SecretBytes, primitives: Primitives = platformPrimitives()): X25519Key {
    val privateKey = hkdfSha512(primitives, seed, X25519_HKDF_INFO, X25519_KEY_LENGTH)
    val publicKey = privateKey.withBytes { primitives.x25519.publicKey(it) }
    return X25519Key(privateKey = privateKey, publicKey = publicKey, publicKeyBase64 = bytesToBase64(publicKey))
}

fun deriveMlKem768Key(seed: SecretBytes, primitives: Primitives = platformPrimitives()): MlKem768Key {
    val kemSeed = hkdfSha512(primitives, seed, MLKEM768_HKDF_INFO, MLKEM768_SEED_LENGTH)
    val keyPair = kemSeed.withBytes { primitives.mlKem768.keyPairFromSeed(it) }
    return MlKem768Key(
        seed = kemSeed,
        secretKey = keyPair.secretKey.adoptAsSecret(),
        publicKey = keyPair.publicKey,
        publicKeyBase64 = bytesToBase64(keyPair.publicKey),
    )
}

fun deriveVaultKek(seed: SecretBytes, primitives: Primitives = platformPrimitives()): SecretBytes =
    hkdfSha512(primitives, seed, VAULT_KEK_HKDF_INFO, VAULT_KEK_LENGTH)

fun deriveKeyTreeFromSeed(seed: SecretBytes, primitives: Primitives = platformPrimitives()): ZekkeKeyTree =
    ZekkeKeyTree(
        seed = seed,
        userAddress = deriveUserAddress(seed, primitives),
        identity = deriveIdentityKey(seed, primitives),
        x25519 = deriveX25519Key(seed, primitives),
        mlkem768 = deriveMlKem768Key(seed, primitives),
        vaultKek = deriveVaultKek(seed, primitives),
    )

fun deriveKeyTree(words: List<CharArray>, primitives: Primitives = platformPrimitives()): ZekkeKeyTree =
    deriveKeyTreeFromSeed(mnemonicToSeed(words, primitives), primitives)

fun deriveRootKeys(seed: SecretBytes, primitives: Primitives = platformPrimitives()): RootKeys =
    RootKeys(
        userAddress = deriveUserAddress(seed, primitives),
        signing = deriveIdentityKey(seed, primitives),
        wrapKey = deriveVaultKek(seed, primitives),
    )

fun deriveRootKeysFromMnemonic(words: List<CharArray>, primitives: Primitives = platformPrimitives()): RootKeys =
    mnemonicToSeed(words, primitives).use { seed -> deriveRootKeys(seed, primitives) }

fun zeroRootKeys(root: RootKeys) {
    zeroSecrets(root.signing.privateKey, root.signing.chainCode, root.wrapKey)
}

fun zeroKeyTree(tree: ZekkeKeyTree) {
    zeroSecrets(
        tree.seed,
        tree.identity.privateKey,
        tree.identity.chainCode,
        tree.x25519.privateKey,
        tree.mlkem768.seed,
        tree.mlkem768.secretKey,
        tree.vaultKek,
    )
}
