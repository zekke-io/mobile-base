package zekke.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals

class Sha2AndHmacTest {
    @Test
    fun userAddressIsSha256OfTheRawSeedBytes() {
        val seed = TestVectors.hex("seed_and_user_address", "seed_hex")
        assertEquals(
            TestVectors.string("seed_and_user_address", "user_address"),
            primitives.sha2.sha256(seed).toHex(),
        )
    }

    @Test
    fun sha256OfTheSignedActionPayloadIsItsDigest() {
        val payload = TestVectors.string("pin_oprf", "account_registration", "example_action_payload").utf8()
        assertEquals(
            TestVectors.string("pin_oprf", "account_registration", "example_action_digest"),
            primitives.sha2.sha256(payload).toHex(),
        )
    }

    @Test
    fun sha512MatchesFips180Example() {
        assertEquals(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            primitives.sha2.sha512("abc".utf8()).toHex(),
        )
    }

    @Test
    fun hmacSha512MatchesRfc4231TestCase2() {
        assertEquals(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            primitives.hmacSha512.mac("Jefe".utf8(), "what do ya want for nothing?".utf8()).toHex(),
        )
    }
}
