package zekke.core.sealed

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class SealedTest {
    private val key = TestVectors.hex("sealed_blob", "key_hex")
    private val plaintext = TestVectors.hex("sealed_blob", "plaintext_hex")

    @Test
    fun reproducesTheSealedBlobVector() {
        val blob = sealBytesWithIv(plaintext, key, TestVectors.hex("sealed_blob", "iv_hex"), primitives)
        assertEquals(TestVectors.string("sealed_blob", "blob_hex"), bytesToHex(blob))
        assertEquals(TestVectors.string("sealed_blob", "blob_base64"), bytesToBase64(blob))
        assertContentEquals(plaintext, openBlob(TestVectors.string("sealed_blob", "blob_base64"), key, primitives))
    }

    @Test
    fun reproducesTheRootKeyringWrap() {
        val wrapped = sealBytesWithIv(
            TestVectors.hex("device_keys", "root_wrap", "scope_kek_hex"),
            TestVectors.hex("vault_kek", "vault_kek_hex"),
            TestVectors.hex("device_keys", "root_wrap", "iv_hex"),
            primitives,
        )
        assertEquals(TestVectors.string("device_keys", "root_wrap", "wrapped_base64"), bytesToBase64(wrapped))
    }

    @Test
    fun everySealDrawsAFreshIv() {
        val first = sealBytes(plaintext, key, primitives)
        val second = sealBytes(plaintext, key, primitives)
        assertNotEquals(bytesToHex(first.copyOfRange(1, 13)), bytesToHex(second.copyOfRange(1, 13)))
        assertContentEquals(plaintext, openBytes(first, key, primitives))
    }

    @Test
    fun anUnknownVersionIsRefusedBeforeDecrypting() {
        val blob = base64ToBytes(TestVectors.string("sealed_blob", "blob_base64"))
        blob[0] = 0x02
        assertEquals(0x02.toByte(), assertFailsWith<UnsupportedSealedVersionException> { openBytes(blob, key, primitives) }.version)
    }

    @Test
    fun aBlobTooShortForAnIvAndTagIsMalformed() {
        assertFailsWith<MalformedSealedBlobException> { openBytes(ByteArray(28) { 1 }, key, primitives) }
        assertFailsWith<MalformedSealedBlobException> { sealBytesWithIv(plaintext, key, ByteArray(11), primitives) }
    }

    @Test
    fun aWrongKeyDoesNotOpen() {
        val wrongKey = key.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFailsWith<SealedBlobAuthenticationException> {
            openBlob(TestVectors.string("sealed_blob", "blob_base64"), wrongKey, primitives)
        }
    }

    @Test
    fun textRoundTrips() {
        assertEquals("Zekke — ünïcode ✓", openText(sealText("Zekke — ünïcode ✓", key, primitives), key, primitives))
    }
}
