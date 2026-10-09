package zekke.core.oprf

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import zekke.core.encoding.concatBytes
import zekke.core.encoding.hexToBytes
import zekke.core.encoding.utf8ToBytes
import zekke.core.fixtures.RFC9497_RISTRETTO255_SHA512_OPRF_JSON
import zekke.core.primitives.Primitives

internal object Rfc9497Vectors {
    private val root: JsonObject = Json.parseToJsonElement(RFC9497_RISTRETTO255_SHA512_OPRF_JSON).jsonObject

    fun string(key: String): String = root.getValue(key).jsonPrimitive.content

    val vectors: List<Map<String, String>> = root.getValue("vectors").jsonArray.map { vector ->
        vector.jsonObject.mapValues { it.value.jsonPrimitive.content }
    }
}

internal fun deriveServerKeyForTests(seed: ByteArray, info: ByteArray, primitives: Primitives): ByteArray {
    val deriveInput = concatBytes(seed, i2osp(info.size, 2), info)
    val dst = utf8ToBytes("DeriveKeyPair$OPRF_CONTEXT_STRING")
    for (counter in 0..255) {
        val scalar = hashToScalar(concatBytes(deriveInput, i2osp(counter, 1)), dst, primitives)
        if (scalar.any { it != 0.toByte() }) return scalar
    }
    error("no key after 256 attempts")
}

internal fun hex(value: String): ByteArray = hexToBytes(value)
