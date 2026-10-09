package zekke.core.keys

import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.uncompressedPointToSpkiBase64
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
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
    val privateKey: ByteArray,
    val chainCode: ByteArray,
    val publicKeyUncompressed: ByteArray,
    val publicKeySpkiBase64: String,
)

class X25519Key(val privateKey: ByteArray, val publicKey: ByteArray, val publicKeyBase64: String)

class MlKem768Key(val seed: ByteArray, val secretKey: ByteArray, val publicKey: ByteArray, val publicKeyBase64: String)

class ZekkeKeyTree(
    val seed: ByteArray,
    val userAddress: String,
    val identity: IdentityKey,
    val x25519: X25519Key,
    val mlkem768: MlKem768Key,
    val vaultKek: ByteArray,
)

class RootKeys(val userAddress: String, val signing: IdentityKey, val wrapKey: ByteArray)

private fun hkdfSha512(primitives: Primitives, inputKeyMaterial: ByteArray, info: String, length: Int): ByteArray =
    primitives.hkdf.sha512(inputKeyMaterial, EMPTY_SALT, utf8ToBytes(info), length)

fun deriveUserAddress(seed: ByteArray, primitives: Primitives = platformPrimitives()): String =
    bytesToHex(primitives.sha2.sha256(seed))

fun deriveIdentityKey(seed: ByteArray, primitives: Primitives = platformPrimitives()): IdentityKey {
    val node = deriveHardenedPath(seed, IDENTITY_PATH, primitives)
    val publicKeyUncompressed = primitives.ecdsaP256.publicKey(node.privateKey)
    return IdentityKey(
        privateKey = node.privateKey,
        chainCode = node.chainCode,
        publicKeyUncompressed = publicKeyUncompressed,
        publicKeySpkiBase64 = uncompressedPointToSpkiBase64(publicKeyUncompressed),
    )
}

fun deriveX25519Key(seed: ByteArray, primitives: Primitives = platformPrimitives()): X25519Key {
    val privateKey = hkdfSha512(primitives, seed, X25519_HKDF_INFO, X25519_KEY_LENGTH)
    val publicKey = primitives.x25519.publicKey(privateKey)
    return X25519Key(privateKey = privateKey, publicKey = publicKey, publicKeyBase64 = bytesToBase64(publicKey))
}

fun deriveMlKem768Key(seed: ByteArray, primitives: Primitives = platformPrimitives()): MlKem768Key {
    val kemSeed = hkdfSha512(primitives, seed, MLKEM768_HKDF_INFO, MLKEM768_SEED_LENGTH)
    val keyPair = primitives.mlKem768.keyPairFromSeed(kemSeed)
    return MlKem768Key(
        seed = kemSeed,
        secretKey = keyPair.secretKey,
        publicKey = keyPair.publicKey,
        publicKeyBase64 = bytesToBase64(keyPair.publicKey),
    )
}

fun deriveVaultKek(seed: ByteArray, primitives: Primitives = platformPrimitives()): ByteArray =
    hkdfSha512(primitives, seed, VAULT_KEK_HKDF_INFO, VAULT_KEK_LENGTH)

fun deriveKeyTreeFromSeed(seed: ByteArray, primitives: Primitives = platformPrimitives()): ZekkeKeyTree =
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

fun deriveRootKeys(seed: ByteArray, primitives: Primitives = platformPrimitives()): RootKeys =
    RootKeys(
        userAddress = deriveUserAddress(seed, primitives),
        signing = deriveIdentityKey(seed, primitives),
        wrapKey = deriveVaultKek(seed, primitives),
    )

fun deriveRootKeysFromMnemonic(words: List<CharArray>, primitives: Primitives = platformPrimitives()): RootKeys {
    val seed = mnemonicToSeed(words, primitives)
    try {
        return deriveRootKeys(seed, primitives)
    } finally {
        zeroBytes(seed)
    }
}

fun zeroRootKeys(root: RootKeys) {
    zeroBytes(root.signing.privateKey, root.signing.chainCode, root.wrapKey)
}

fun zeroKeyTree(tree: ZekkeKeyTree) {
    zeroBytes(
        tree.seed,
        tree.identity.privateKey,
        tree.identity.chainCode,
        tree.x25519.privateKey,
        tree.mlkem768.seed,
        tree.mlkem768.secretKey,
        tree.vaultKek,
    )
}
