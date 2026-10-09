package zekke.core.primitives

interface Ristretto255 {
    fun isValidPoint(point: ByteArray): Boolean
    fun fromUniformBytes(uniformBytes: ByteArray): ByteArray
    fun scalarMult(scalar: ByteArray, point: ByteArray): ByteArray
    fun scalarMultBase(scalar: ByteArray): ByteArray
    fun invertScalar(scalar: ByteArray): ByteArray
    fun reduceScalar(wideScalar: ByteArray): ByteArray
    fun randomScalar(): ByteArray

    companion object {
        const val POINT_BYTES = 32
        const val SCALAR_BYTES = 32
        const val UNIFORM_BYTES = 64
    }
}
