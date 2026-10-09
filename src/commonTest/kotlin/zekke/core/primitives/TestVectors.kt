package zekke.core.primitives

import zekke.core.memory.adoptAsSecret
import zekke.core.memory.SecretBytes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import zekke.core.fixtures.TEST_VECTORS_JSON

internal object TestVectors {
    private val root: JsonObject = Json.parseToJsonElement(TEST_VECTORS_JSON).jsonObject

    fun string(vararg path: Any): String = path.fold<Any, JsonElement>(root) { element, key ->
        when (key) {
            is String -> element.jsonObject.getValue(key)
            is Int -> (element as JsonArray)[key]
            else -> error("a vector path is made of names and indices")
        }
    }.jsonPrimitive.content

    fun hex(vararg path: Any): ByteArray = string(*path).hexToBytes()

    fun base64(vararg path: Any): ByteArray = Base64.decode(string(*path))

    fun secret(vararg path: Any): SecretBytes = hex(*path).adoptAsSecret()
}

internal fun String.hexToBytes(): ByteArray = hexToByteArray()

internal fun ByteArray.toHex(): String = toHexString()

internal fun SecretBytes.toHex(): String = withBytes { it.toHexString() }

internal fun String.utf8(): ByteArray = encodeToByteArray()

internal val primitives: Primitives by lazy { platformPrimitives() }
