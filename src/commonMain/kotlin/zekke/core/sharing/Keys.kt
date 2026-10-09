package zekke.core.sharing

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.concatBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.pqxdh.PqxdhContext
import zekke.core.pqxdh.PqxdhUsage
import zekke.core.pqxdh.RecipientKeys
import zekke.core.pqxdh.RecipientSecrets
import zekke.core.pqxdh.pqxdhUnwrap
import zekke.core.pqxdh.pqxdhWrap
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

const val CONNECTION_KEY_BYTES = 32
const val WRAP_IV_BYTES = 12
const val FINGERPRINT_GROUPS = 6
const val FINGERPRINT_GROUP_SIZE = 4

open class ConnectionKeyException(message: String) : IllegalStateException(message)

class MalformedPartyAddressException(role: String) :
    ConnectionKeyException("the $role address is not 64 lowercase hex characters, so the key exchange cannot be reproduced")

private val USER_ADDRESS = Regex("^[0-9a-f]{64}$")

private fun assertParties(senderUserAddress: String, recipientUserAddress: String) {
    if (!USER_ADDRESS.matches(senderUserAddress)) throw MalformedPartyAddressException("sender")
    if (!USER_ADDRESS.matches(recipientUserAddress)) throw MalformedPartyAddressException("recipient")
}

fun createConnectionKey(primitives: Primitives = platformPrimitives()): SecretBytes =
    primitives.secureRandom.nextBytes(CONNECTION_KEY_BYTES).adoptAsSecret()

fun sealConnectionKey(
    connectionKey: SecretBytes,
    recipient: RecipientKeys,
    senderUserAddress: String,
    recipientUserAddress: String,
    primitives: Primitives = platformPrimitives(),
): String {
    assertParties(senderUserAddress, recipientUserAddress)
    return pqxdhWrap(connectionKey, recipient, PqxdhContext(PqxdhUsage.ITEM_SHARE, senderUserAddress, recipientUserAddress), primitives)
}

fun openConnectionKey(
    pqxdhBlob: String,
    secrets: RecipientSecrets,
    senderUserAddress: String,
    recipientUserAddress: String,
    primitives: Primitives = platformPrimitives(),
): SecretBytes {
    assertParties(senderUserAddress, recipientUserAddress)
    val key = pqxdhUnwrap(pqxdhBlob, secrets, PqxdhContext(PqxdhUsage.ITEM_SHARE, senderUserAddress, recipientUserAddress), primitives)
    if (key.size != CONNECTION_KEY_BYTES) {
        key.zero()
        throw ConnectionKeyException("the connection key has the wrong length")
    }
    return key
}

fun wrapUnderConnection(key: SecretBytes, payload: SecretBytes, primitives: Primitives = platformPrimitives()): String {
    val iv = primitives.secureRandom.nextBytes(WRAP_IV_BYTES)
    val sealed = key.withBytes { k -> payload.withBytes { primitives.aesGcm.encrypt(k, iv, it) } }
    return bytesToBase64(concatBytes(iv, sealed))
}

fun unwrapUnderConnection(key: SecretBytes, blobBase64: String, primitives: Primitives = platformPrimitives()): SecretBytes {
    val blob = base64ToBytes(blobBase64)
    if (blob.size <= WRAP_IV_BYTES) throw ConnectionKeyException("the wrapped payload is shorter than its IV")
    val iv = blob.copyOfRange(0, WRAP_IV_BYTES)
    val sealed = blob.copyOfRange(WRAP_IV_BYTES, blob.size)
    return (key.withBytes { primitives.aesGcm.decrypt(it, iv, sealed) } ?: throw ConnectionKeyException("the wrapped payload did not open under this key"))
        .adoptAsSecret()
}

fun publishedRecipientKeys(x25519PublicKey: String, mlkemPublicKey: String): RecipientKeys =
    RecipientKeys(base64ToBytes(x25519PublicKey), base64ToBytes(mlkemPublicKey))

fun rootFingerprint(rootPublicKeySpki: String, primitives: Primitives = platformPrimitives()): String {
    val hex = bytesToHex(primitives.sha2.sha256(base64ToBytes(rootPublicKeySpki))).uppercase()
    return (0 until FINGERPRINT_GROUPS).joinToString("-") { hex.substring(it * FINGERPRINT_GROUP_SIZE, (it + 1) * FINGERPRINT_GROUP_SIZE) }
}
