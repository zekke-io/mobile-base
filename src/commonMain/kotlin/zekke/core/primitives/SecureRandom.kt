package zekke.core.primitives

interface SecureRandom {
    fun nextBytes(size: Int): ByteArray
}
