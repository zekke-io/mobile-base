package zekke.core.pqxdh

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.concatBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.encoding.zeroBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.memory.zeroSecrets
import zekke.core.primitives.AesGcm
import zekke.core.primitives.MlKem768
import zekke.core.primitives.Primitives
import zekke.core.primitives.X25519
import zekke.core.primitives.platformPrimitives

const val PQXDH_VERSION: Byte = 0x01
const val KEM_CIPHERTEXT_LENGTH = MlKem768.CIPHERTEXT_BYTES
const val EPHEMERAL_PUBLIC_LENGTH = X25519.KEY_BYTES
const val IV_LENGTH = AesGcm.IV_BYTES
const val GCM_TAG_LENGTH = AesGcm.TAG_BYTES
const val SESSION_KEY_LENGTH = 32

const val PQXDH_INFO_PREFIX = "Cryple-PQXDH-v1|"

private const val IKM_PREFIX_BYTE: Byte = 0xff.toByte()
private const val IKM_PREFIX_LENGTH = 32
private const val HKDF_SALT_LENGTH = 32

private const val HEADER_LENGTH = 1 + KEM_CIPHERTEXT_LENGTH + EPHEMERAL_PUBLIC_LENGTH + IV_LENGTH
private const val MIN_BLOB_LENGTH = HEADER_LENGTH + GCM_TAG_LENGTH

enum class PqxdhUsage(val label: String) {
    ITEM_SHARE("item-share"),
    DEVICE_KEYRING("device-keyring"),
}

class UnsupportedPqxdhVersionException(val version: Byte) :
    IllegalArgumentException("unsupported PQXDH version byte 0x${(version.toInt() and 0xff).toString(16).padStart(2, '0')}")

class MalformedPqxdhBlobException(message: String) : IllegalArgumentException("malformed PQXDH blob: $message")

class PqxdhAuthenticationException : IllegalStateException("PQXDH blob did not authenticate under these keys and context")

class RecipientKeys(val x25519PublicKey: ByteArray, val mlkemPublicKey: ByteArray)

fun interface X25519Agreement {
    fun deriveSharedSecret(peerPublicKey: ByteArray): SecretBytes
}

fun rawX25519Agreement(privateKey: SecretBytes, primitives: Primitives = platformPrimitives()): X25519Agreement =
    X25519Agreement { peerPublicKey -> privateKey.withBytes { primitives.x25519.sharedSecret(it, peerPublicKey) }.adoptAsSecret() }

class RecipientSecrets(val x25519: X25519Agreement, val mlkemSecretKey: SecretBytes)

class PqxdhContext(val usage: PqxdhUsage, val senderUserAddress: String, val recipientUserAddress: String)

class ParsedBlob(
    val version: Byte,
    val kemCiphertext: ByteArray,
    val ephemeralPublicKey: ByteArray,
    val iv: ByteArray,
    val sealed: ByteArray,
)

fun deviceRecipientSlot(userAddress: String, deviceId: String): String = "$userAddress/$deviceId"

fun buildInfo(context: PqxdhContext): String =
    PQXDH_INFO_PREFIX + "${context.usage.label}|${context.senderUserAddress}|${context.recipientUserAddress}"

fun deriveSessionKey(
    ecdhSecret: SecretBytes,
    kemSecret: SecretBytes,
    context: PqxdhContext,
    primitives: Primitives = platformPrimitives(),
): SecretBytes {
    val ikm = ecdhSecret.withBytes { ecdh ->
        kemSecret.withBytes { kem -> concatBytes(ByteArray(IKM_PREFIX_LENGTH) { IKM_PREFIX_BYTE }, ecdh, kem) }
    }
    try {
        return primitives.hkdf.sha256(ikm, ByteArray(HKDF_SALT_LENGTH), utf8ToBytes(buildInfo(context)), SESSION_KEY_LENGTH)
            .adoptAsSecret()
    } finally {
        zeroBytes(ikm)
    }
}

fun parseBlob(blobBase64: String): ParsedBlob {
    val blob = base64ToBytes(blobBase64)
    if (blob.size < MIN_BLOB_LENGTH) {
        throw MalformedPqxdhBlobException("${blob.size} bytes, shorter than the $MIN_BLOB_LENGTH-byte minimum")
    }
    if (blob[0] != PQXDH_VERSION) throw UnsupportedPqxdhVersionException(blob[0])
    var offset = 1
    fun take(length: Int): ByteArray = blob.copyOfRange(offset, offset + length).also { offset += length }
    val kemCiphertext = take(KEM_CIPHERTEXT_LENGTH)
    val ephemeralPublicKey = take(EPHEMERAL_PUBLIC_LENGTH)
    val iv = take(IV_LENGTH)
    val sealed = blob.copyOfRange(offset, blob.size)
    return ParsedBlob(blob[0], kemCiphertext, ephemeralPublicKey, iv, sealed)
}

fun pqxdhWrap(
    payload: SecretBytes,
    recipient: RecipientKeys,
    context: PqxdhContext,
    primitives: Primitives = platformPrimitives(),
): String {
    val ephemeralPrivateKey = primitives.secureRandom.nextBytes(X25519.KEY_BYTES).adoptAsSecret()
    var ecdhSecret: SecretBytes? = null
    var kemSecret: SecretBytes? = null
    var sessionKey: SecretBytes? = null
    try {
        val ephemeralPublicKey = ephemeralPrivateKey.withBytes { primitives.x25519.publicKey(it) }
        ecdhSecret = ephemeralPrivateKey.withBytes { primitives.x25519.sharedSecret(it, recipient.x25519PublicKey) }.adoptAsSecret()
        val encapsulation = primitives.mlKem768.encapsulate(recipient.mlkemPublicKey)
        kemSecret = encapsulation.sharedSecret.adoptAsSecret()
        sessionKey = deriveSessionKey(ecdhSecret, kemSecret, context, primitives)
        val iv = primitives.secureRandom.nextBytes(IV_LENGTH)
        val sealed = sessionKey.withBytes { key -> payload.withBytes { primitives.aesGcm.encrypt(key, iv, it) } }
        return bytesToBase64(concatBytes(byteArrayOf(PQXDH_VERSION), encapsulation.ciphertext, ephemeralPublicKey, iv, sealed))
    } finally {
        zeroSecrets(ephemeralPrivateKey, ecdhSecret, kemSecret, sessionKey)
    }
}

fun pqxdhUnwrap(
    blobBase64: String,
    secrets: RecipientSecrets,
    context: PqxdhContext,
    primitives: Primitives = platformPrimitives(),
): SecretBytes {
    val blob = parseBlob(blobBase64)
    var ecdhSecret: SecretBytes? = null
    var kemSecret: SecretBytes? = null
    var sessionKey: SecretBytes? = null
    try {
        ecdhSecret = secrets.x25519.deriveSharedSecret(blob.ephemeralPublicKey)
        kemSecret = secrets.mlkemSecretKey.withBytes { primitives.mlKem768.decapsulate(it, blob.kemCiphertext) }.adoptAsSecret()
        sessionKey = deriveSessionKey(ecdhSecret, kemSecret, context, primitives)
        val payload = sessionKey.withBytes { primitives.aesGcm.decrypt(it, blob.iv, blob.sealed) } ?: throw PqxdhAuthenticationException()
        return payload.adoptAsSecret()
    } finally {
        zeroSecrets(ecdhSecret, kemSecret, sessionKey)
    }
}
