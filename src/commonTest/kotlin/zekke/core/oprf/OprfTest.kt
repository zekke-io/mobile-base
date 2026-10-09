package zekke.core.oprf

import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.bytesToUtf8
import zekke.core.encoding.utf8ToBytes
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OprfTest {
    private val pin = TestVectors.string("pin_oprf", "pin").toCharArray()

    @Test
    fun expandMessageXmdMatchesRfc9380() {
        val dst = utf8ToBytes("QUUX-V01-CS02-with-expander-SHA512-256")
        val message = utf8ToBytes("abcdef0123456789")
        assertEquals(
            "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58",
            bytesToHex(expandMessageXmd(message, dst, 0x20, primitives)),
        )
        assertEquals(
            "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfb" +
                "f85ae612ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed82" +
                "7feecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac",
            bytesToHex(expandMessageXmd(message, dst, 0x80, primitives)),
        )
    }

    @Test
    fun theSuiteAndDstAreRfc9497s() {
        assertEquals(OPRF_SUITE, Rfc9497Vectors.string("identifier"))
        assertEquals("0", Rfc9497Vectors.string("mode"))
        assertEquals(OPRF_HASH_TO_GROUP_DST, bytesToUtf8(hex(Rfc9497Vectors.string("groupDST"))))
    }

    @Test
    fun derivesTheRfcServerKey() {
        val key = deriveServerKeyForTests(hex(Rfc9497Vectors.string("seed")), hex(Rfc9497Vectors.string("keyInfo")), primitives)
        assertEquals(Rfc9497Vectors.string("skSm"), bytesToHex(key))
    }

    @Test
    fun reproducesEveryRfc9497BaseModeVector() {
        val serverKey = hex(Rfc9497Vectors.string("skSm"))
        for ((index, vector) in Rfc9497Vectors.vectors.withIndex()) {
            val blinded = blindInputWithScalar(hex(vector.getValue("Input")), hex(vector.getValue("Blind")), primitives)
            assertEquals(vector.getValue("BlindedElement"), bytesToHex(base64ToBytes(blinded.blindedElement)), "vector $index")
            val evaluated = primitives.ristretto255.scalarMult(serverKey, base64ToBytes(blinded.blindedElement))
            assertEquals(vector.getValue("EvaluationElement"), bytesToHex(evaluated), "vector $index")
            assertEquals(vector.getValue("Output"), bytesToHex(finalizePin(blinded, bytesToBase64(evaluated), primitives)), "vector $index")
        }
    }

    @Test
    fun reproducesThePinOprfServerKeyAndTestBlind() {
        val serverKey = deriveServerKeyForTests(
            TestVectors.hex("pin_oprf", "server", "seed_hex"),
            utf8ToBytes(TestVectors.string("pin_oprf", "server", "info")),
            primitives,
        )
        assertEquals(TestVectors.string("pin_oprf", "server", "private_key_hex"), bytesToHex(serverKey))
        val blind = hashToScalar(utf8ToBytes("blind"), utf8ToBytes("Cryple-PIN-v1|test-blind"), primitives)
        assertEquals(TestVectors.string("pin_oprf", "blind", "blind_hex"), bytesToHex(blind))
    }

    @Test
    fun reproducesTheBlindedPinTheEvaluationAndTheOutput() {
        val blinded = blindPinWithScalar(pin, TestVectors.hex("pin_oprf", "blind", "blind_hex"), primitives)
        assertEquals(TestVectors.string("pin_oprf", "blind", "blinded_element"), blinded.blindedElement)
        val evaluated = primitives.ristretto255.scalarMult(
            TestVectors.hex("pin_oprf", "server", "private_key_hex"),
            base64ToBytes(blinded.blindedElement),
        )
        assertEquals(TestVectors.string("pin_oprf", "evaluation", "evaluated_element"), bytesToBase64(evaluated))
        assertEquals(
            TestVectors.string("pin_oprf", "evaluation", "oprf_output_hex"),
            bytesToHex(finalizePin(blinded, TestVectors.string("pin_oprf", "evaluation", "evaluated_element"), primitives)),
        )
        assertTrue(blinded.blind.all { it == 0.toByte() } && blinded.input.all { it == 0.toByte() })
    }

    @Test
    fun aFreshBlindIsDrawnEveryTime() {
        val first = blindPin(pin, primitives)
        val second = blindPin(pin, primitives)
        assertTrue(first.blindedElement != second.blindedElement)
    }

    @Test
    fun aMalformedEvaluatedElementIsRefused() {
        val invalid = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        for (element in listOf("not base64!", bytesToBase64(ByteArray(31)), bytesToBase64(hex(invalid)), bytesToBase64(ByteArray(32)))) {
            val blinded = blindPin(pin, primitives)
            assertFailsWith<MalformedElementException>(element) { finalizePin(blinded, element, primitives) }
        }
    }
}
