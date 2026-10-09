package zekke.core.keys

import zekke.core.encoding.zeroBytes
import zekke.core.memory.SecretBytes
import zekke.core.memory.adoptAsSecret
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives

const val SEED_LENGTH = 64
val SUPPORTED_WORD_COUNTS: List<Int> = listOf(12, 24)

private const val BIP39_ITERATIONS = 2048
private const val BIP39_SALT = "mnemonic"
private const val BITS_PER_WORD = 11
private const val WORD_SEPARATOR = ' '.code.toByte()

class InvalidMnemonicException : IllegalArgumentException("invalid mnemonic: unsupported word count or failed checksum")

fun isValidMnemonic(words: List<CharArray>, primitives: Primitives = platformPrimitives()): Boolean {
    if (words.size !in SUPPORTED_WORD_COUNTS) return false
    val indices = IntArray(words.size)
    for ((position, word) in words.withIndex()) {
        val index = wordIndex(word)
        if (index < 0) return false
        indices[position] = index
    }
    val totalBits = words.size * BITS_PER_WORD
    val checksumBits = totalBits / 33
    val entropy = ByteArray((totalBits - checksumBits) / 8)
    val digest: ByteArray
    try {
        for (bit in 0 until entropy.size * 8) {
            if (bitOf(indices, bit)) entropy[bit / 8] = (entropy[bit / 8].toInt() or (0x80 ushr (bit % 8))).toByte()
        }
        digest = primitives.sha2.sha256(entropy)
    } finally {
        zeroBytes(entropy)
    }
    try {
        for (bit in 0 until checksumBits) {
            val expected = (digest[bit / 8].toInt() ushr (7 - bit % 8)) and 1 == 1
            if (bitOf(indices, entropy.size * 8 + bit) != expected) return false
        }
        return true
    } finally {
        zeroBytes(digest)
        indices.fill(0)
    }
}

fun assertValidMnemonic(words: List<CharArray>, primitives: Primitives = platformPrimitives()) {
    if (!isValidMnemonic(words, primitives)) throw InvalidMnemonicException()
}

fun generateMnemonic(wordCount: Int = 12, primitives: Primitives = platformPrimitives()): List<CharArray> {
    require(wordCount in SUPPORTED_WORD_COUNTS) { "a mnemonic has 12 or 24 words" }
    val totalBits = wordCount * BITS_PER_WORD
    val checksumBits = totalBits / 33
    val entropy = primitives.secureRandom.nextBytes((totalBits - checksumBits) / 8)
    val digest = primitives.sha2.sha256(entropy)
    try {
        return List(wordCount) { position ->
            var index = 0
            for (offset in 0 until BITS_PER_WORD) {
                val bit = position * BITS_PER_WORD + offset
                val source = if (bit < entropy.size * 8) entropy[bit / 8] else digest[(bit - entropy.size * 8) / 8]
                val bitInByte = if (bit < entropy.size * 8) bit % 8 else (bit - entropy.size * 8) % 8
                index = (index shl 1) or ((source.toInt() ushr (7 - bitInByte)) and 1)
            }
            BIP39_ENGLISH_WORDLIST[index].toCharArray()
        }
    } finally {
        zeroBytes(entropy, digest)
    }
}

fun mnemonicToSeed(words: List<CharArray>, primitives: Primitives = platformPrimitives()): SecretBytes {
    assertValidMnemonic(words, primitives)
    val password = ByteArray(words.sumOf { it.size } + words.size - 1)
    var offset = 0
    for ((position, word) in words.withIndex()) {
        if (position > 0) password[offset++] = WORD_SEPARATOR
        for (character in word) password[offset++] = character.code.toByte()
    }
    try {
        return primitives.pbkdf2HmacSha512.derive(password, BIP39_SALT.encodeToByteArray(), BIP39_ITERATIONS, SEED_LENGTH).adoptAsSecret()
    } finally {
        zeroBytes(password)
    }
}

private fun bitOf(indices: IntArray, bit: Int): Boolean =
    (indices[bit / BITS_PER_WORD] ushr (BITS_PER_WORD - 1 - bit % BITS_PER_WORD)) and 1 == 1

private fun wordIndex(word: CharArray): Int {
    var low = 0
    var high = BIP39_ENGLISH_WORDLIST.size - 1
    while (low <= high) {
        val middle = (low + high) ushr 1
        val comparison = compare(word, BIP39_ENGLISH_WORDLIST[middle])
        when {
            comparison == 0 -> return middle
            comparison < 0 -> high = middle - 1
            else -> low = middle + 1
        }
    }
    return -1
}

private fun compare(word: CharArray, candidate: String): Int {
    val shared = minOf(word.size, candidate.length)
    for (index in 0 until shared) {
        val difference = word[index] - candidate[index]
        if (difference != 0) return difference
    }
    return word.size - candidate.length
}
