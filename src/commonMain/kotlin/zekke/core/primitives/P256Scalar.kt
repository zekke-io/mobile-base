package zekke.core.primitives

object P256Scalar {
    const val BYTES = 32

    private const val WORDS = 8
    private const val WORD_MASK = 0xffffffffL

    private val orderWords = intArrayOf(
        0xfc632551.toInt(), 0xf3b9cac2.toInt(), 0xa7179e84.toInt(), 0xbce6faad.toInt(),
        0xffffffff.toInt(), 0xffffffff.toInt(), 0x00000000, 0xffffffff.toInt(),
    )

    fun isValidPrivateKey(scalar: ByteArray): Boolean {
        require(scalar.size == BYTES) { "a P-256 scalar is $BYTES bytes" }
        val words = toWords(scalar)
        return !isZero(words) && isBelowOrder(words)
    }

    fun addModOrder(left: ByteArray, right: ByteArray): ByteArray {
        require(left.size == BYTES && right.size == BYTES) { "a P-256 scalar is $BYTES bytes" }
        val leftWords = toWords(left)
        val rightWords = toWords(right)
        require(isBelowOrder(leftWords) && isBelowOrder(rightWords)) { "both scalars must be below the P-256 order" }

        val sum = IntArray(WORDS)
        var carry = 0L
        for (index in 0 until WORDS) {
            val total = (leftWords[index].toLong() and WORD_MASK) + (rightWords[index].toLong() and WORD_MASK) + carry
            sum[index] = total.toInt()
            carry = total ushr 32
        }

        val reduced = IntArray(WORDS)
        var borrow = 0L
        for (index in 0 until WORDS) {
            val difference = (sum[index].toLong() and WORD_MASK) - (orderWords[index].toLong() and WORD_MASK) - borrow
            reduced[index] = difference.toInt()
            borrow = (difference ushr 63) and 1L
        }

        val useReduced = (carry or (1L - borrow)).toInt()
        val mask = -useReduced
        val result = IntArray(WORDS) { index -> (reduced[index] and mask) or (sum[index] and mask.inv()) }
        return fromWords(result)
    }

    private fun isBelowOrder(words: IntArray): Boolean {
        var borrow = 0L
        for (index in 0 until WORDS) {
            val difference = (words[index].toLong() and WORD_MASK) - (orderWords[index].toLong() and WORD_MASK) - borrow
            borrow = (difference ushr 63) and 1L
        }
        return borrow == 1L
    }

    private fun isZero(words: IntArray): Boolean = words.fold(0) { accumulator, word -> accumulator or word } == 0

    private fun toWords(bigEndian: ByteArray): IntArray = IntArray(WORDS) { index ->
        val offset = BYTES - 4 * (index + 1)
        ((bigEndian[offset].toInt() and 0xff) shl 24) or
            ((bigEndian[offset + 1].toInt() and 0xff) shl 16) or
            ((bigEndian[offset + 2].toInt() and 0xff) shl 8) or
            (bigEndian[offset + 3].toInt() and 0xff)
    }

    private fun fromWords(words: IntArray): ByteArray {
        val bigEndian = ByteArray(BYTES)
        for (index in 0 until WORDS) {
            val offset = BYTES - 4 * (index + 1)
            bigEndian[offset] = (words[index] ushr 24).toByte()
            bigEndian[offset + 1] = (words[index] ushr 16).toByte()
            bigEndian[offset + 2] = (words[index] ushr 8).toByte()
            bigEndian[offset + 3] = words[index].toByte()
        }
        return bigEndian
    }
}
