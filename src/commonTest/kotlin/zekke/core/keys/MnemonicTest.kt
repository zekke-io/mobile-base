package zekke.core.keys

import zekke.core.encoding.bytesToHex
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MnemonicTest {
    private val vectorWords = words(TestVectors.string("seed_and_user_address", "mnemonic"))

    @Test
    fun theShippedWordlistIsTheCanonicalBip39EnglishList() {
        val joined = (BIP39_ENGLISH_WORDLIST.joinToString("\n") + "\n").encodeToByteArray()
        assertEquals(2048, BIP39_ENGLISH_WORDLIST.size)
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", bytesToHex(primitives.sha2.sha256(joined)))
        assertEquals(BIP39_ENGLISH_WORDLIST.sorted(), BIP39_ENGLISH_WORDLIST)
    }

    @Test
    fun theVectorMnemonicGivesTheVectorSeed() {
        assertTrue(isValidMnemonic(vectorWords, primitives))
        assertEquals(TestVectors.string("seed_and_user_address", "seed_hex"), bytesToHex(mnemonicToSeed(vectorWords, primitives)))
    }

    @Test
    fun aWrongChecksumIsRefused() {
        val swapped = vectorWords.dropLast(1) + listOf("abandon".toCharArray())
        assertFalse(isValidMnemonic(swapped, primitives))
        assertFailsWith<InvalidMnemonicException> { mnemonicToSeed(swapped, primitives) }
    }

    @Test
    fun onlyTwelveOrTwentyFourKnownWordsAreAccepted() {
        assertFalse(isValidMnemonic(words("abandon ".repeat(14) + "able"), primitives))
        assertFalse(isValidMnemonic(vectorWords.dropLast(1) + listOf("zekke".toCharArray()), primitives))
        assertFalse(isValidMnemonic(vectorWords.dropLast(1) + listOf("ABOUT".toCharArray()), primitives))
        assertTrue(isValidMnemonic(words("abandon ".repeat(23) + "art"), primitives))
    }

    @Test
    fun aGeneratedMnemonicIsValid() {
        for (count in SUPPORTED_WORD_COUNTS) {
            val generated = generateMnemonic(count, primitives)
            assertEquals(count, generated.size)
            assertTrue(isValidMnemonic(generated, primitives), "$count words")
        }
    }

    private fun words(phrase: String): List<CharArray> = phrase.trim().split(' ').map { it.toCharArray() }
}
