package zekke.core.encoding

import zekke.core.primitives.TestVectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EncodingTest {
    private val identityPoint = TestVectors.hex("identity_key_p256", "public_key_uncompressed_hex")

    @Test
    fun hexIsLowercaseAndRoundTrips() {
        assertEquals("00ff10ab", bytesToHex(byteArrayOf(0x00, 0xff.toByte(), 0x10, 0xab.toByte())))
        assertContentEquals(byteArrayOf(0xab.toByte(), 0xcd.toByte()), hexToBytes("ABcd"))
    }

    @Test
    fun hexRejectsOddLengthAndNonHexInput() {
        assertFailsWith<IllegalArgumentException> { hexToBytes("abc") }
        assertFailsWith<IllegalArgumentException> { hexToBytes("zz") }
    }

    @Test
    fun theIdentityPointEncodesToTheRecordedSpki() {
        val spki = uncompressedPointToSpkiBase64(identityPoint)
        assertEquals(TestVectors.string("identity_key_p256", "public_key_spki_base64"), spki)
        assertEquals(P256_SPKI_BASE64_LENGTH, spki.length)
        assertContentEquals(identityPoint, spkiBase64ToUncompressedPoint(spki))
    }

    @Test
    fun theIdentityPointSplitsIntoTheOnChainCoordinates() {
        val coordinates = uncompressedPointToXY(identityPoint)
        assertEquals(TestVectors.string("identity_key_p256", "onchain_pubkey_x_hex"), bytesToHex(coordinates.x))
        assertEquals(TestVectors.string("identity_key_p256", "onchain_pubkey_y_hex"), bytesToHex(coordinates.y))
        assertContentEquals(identityPoint, xyToUncompressedPoint(coordinates.x, coordinates.y))
    }

    @Test
    fun anythingButAnUncompressedP256SpkiIsRejected() {
        val spki = uncompressedPointToSpkiDer(identityPoint)
        spki[5] = 0x00
        assertFailsWith<IllegalArgumentException> { spkiDerToUncompressedPoint(spki) }
        assertFailsWith<IllegalArgumentException> { spkiDerToUncompressedPoint(spki.copyOf(90)) }
        assertFailsWith<IllegalArgumentException> { uncompressedPointToSpkiDer(identityPoint.copyOf().also { it[0] = 0x02 }) }
    }

    @Test
    fun theEncryptionPublicKeysHaveTheirWireLengths() {
        assertEquals(44, TestVectors.string("x25519_key", "public_key_base64").length)
        assertEquals(1580, TestVectors.string("mlkem768_key", "public_key_base64").length)
        assertContentEquals(
            TestVectors.hex("x25519_key", "public_key_hex"),
            base64ToBytes(TestVectors.string("x25519_key", "public_key_base64")),
        )
    }

    @Test
    fun byteHelpersBehave() {
        assertContentEquals(byteArrayOf(1, 2, 3), concatBytes(byteArrayOf(1), byteArrayOf(), byteArrayOf(2, 3)))
        assertTrue(bytesEqual(byteArrayOf(1, 2), byteArrayOf(1, 2)))
        assertFalse(bytesEqual(byteArrayOf(1, 2), byteArrayOf(1, 3)))
        assertFalse(bytesEqual(byteArrayOf(1), byteArrayOf(1, 0)))
        val secret = byteArrayOf(9, 9)
        zeroBytes(secret, null)
        assertContentEquals(byteArrayOf(0, 0), secret)
        assertContentEquals(byteArrayOf(0xfb.toByte(), 0xff.toByte()), base64UrlToBytes("-_8"))
    }
}
