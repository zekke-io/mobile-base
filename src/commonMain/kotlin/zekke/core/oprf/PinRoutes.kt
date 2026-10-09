package zekke.core.oprf

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import zekke.core.api.ApiError
import zekke.core.api.Method
import zekke.core.api.NetworkError
import zekke.core.api.ZekkeApi
import zekke.core.api.assertCanonicalUuid
import zekke.core.auth.putEnvelope
import zekke.core.memory.zeroSecrets
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.signing.Action
import zekke.core.signing.PinProofSigner
import zekke.core.signing.Signer
import zekke.core.signing.signRootAction

class DeviceRegistrationGoneException : IllegalStateException("this device PIN registration no longer exists")

class OfflineException(cause: Throwable? = null) : IllegalStateException("the server could not be reached", cause)

@Serializable
private class RegistrationAnswer(
    @SerialName("registration_id") val registrationId: String,
    @SerialName("evaluated_element") val evaluatedElement: String,
)

@Serializable
private class EvaluationAnswer(
    @SerialName("evaluated_element") val evaluatedElement: String,
    @SerialName("attempt_id") val attemptId: String,
    @SerialName("attempts_remaining") val attemptsRemaining: Int,
)

@Serializable
private class EvaluatedElement(@SerialName("evaluated_element") val evaluatedElement: String)

class DeviceRegistration(val registrationId: String, val salt: ByteArray, val keys: DevicePinKeys)

class DevicePinEvaluation(val keys: DevicePinKeys, val attemptId: String, val attemptsRemaining: Int)

class AccountPinProof(val key: AccountProofKey, val sign: PinProofSigner)

suspend fun registerDevicePin(api: ZekkeApi, pin: CharArray, primitives: Primitives = platformPrimitives()): DeviceRegistration {
    val token = api.tokens.require()
    val salt = generateDeviceSalt(primitives)
    val blinded = blindPin(pin, primitives)
    val answer = try {
        api.request(Method.POST, "/oprf/devices", body = buildJsonObject { put("blinded_element", blinded.blindedElement) }, token = token)
            .decode(RegistrationAnswer.serializer())
    } catch (error: Exception) {
        zeroSecrets(blinded.blind, blinded.input)
        throw error
    }
    val registrationId = assertCanonicalUuid(answer.registrationId)
    val keys = deriveDevicePinKeys(finalizePin(blinded, answer.evaluatedElement, primitives), pin, salt, primitives)
    try {
        api.request(
            Method.POST,
            "/oprf/devices/$registrationId/commit",
            body = buildJsonObject { put("confirm_public_key", keys.confirmPublicKey) },
            token = token,
        )
    } catch (error: Exception) {
        zeroDevicePinKeys(keys)
        throw error
    }
    return DeviceRegistration(registrationId, salt, keys)
}

suspend fun evaluateDevicePin(
    api: ZekkeApi,
    registrationId: String,
    pin: CharArray,
    salt: ByteArray,
    primitives: Primitives = platformPrimitives(),
): DevicePinEvaluation {
    val blinded = blindPin(pin, primitives)
    val answer = try {
        api.request(
            Method.POST,
            "/oprf/devices/${assertCanonicalUuid(registrationId)}/evaluate",
            body = buildJsonObject { put("blinded_element", blinded.blindedElement) },
        ).decode(EvaluationAnswer.serializer())
    } catch (error: Exception) {
        zeroSecrets(blinded.blind, blinded.input)
        if (error is ApiError && error.status == 404) throw DeviceRegistrationGoneException()
        if (error is NetworkError) throw OfflineException(error)
        throw error
    }
    val keys = deriveDevicePinKeys(finalizePin(blinded, answer.evaluatedElement, primitives), pin, salt, primitives)
    return DevicePinEvaluation(keys, assertCanonicalUuid(answer.attemptId), answer.attemptsRemaining)
}

suspend fun confirmDevicePin(api: ZekkeApi, registrationId: String, evaluation: DevicePinEvaluation, primitives: Primitives = platformPrimitives()) {
    val proof = signDeviceConfirmation(evaluation.keys.confirmSeed, registrationId, evaluation.attemptId, primitives)
    api.request(
        Method.POST,
        "/oprf/devices/${assertCanonicalUuid(registrationId)}/confirm",
        body = buildJsonObject {
            put("attempt_id", evaluation.attemptId)
            put("proof", proof)
        },
    )
}

suspend fun deleteDevicePin(api: ZekkeApi, registrationId: String) {
    api.request(Method.DELETE, "/oprf/devices/${assertCanonicalUuid(registrationId)}", token = api.tokens.require())
}

suspend fun accountPinProof(
    api: ZekkeApi,
    root: Signer,
    userAddress: String,
    pin: CharArray,
    primitives: Primitives = platformPrimitives(),
): AccountPinProof {
    val blinded = blindPin(pin, primitives)
    val answer = try {
        val envelope = signRootAction(Action.PIN_EVALUATE, listOf(userAddress, blinded.blindedElement), root, primitives = primitives)
        api.request(
            Method.POST,
            "/oprf/account/evaluate",
            body = buildJsonObject {
                put("user_address", userAddress)
                put("blinded_element", blinded.blindedElement)
                putEnvelope(envelope)
            },
        ).decode(EvaluatedElement.serializer())
    } catch (error: Exception) {
        zeroSecrets(blinded.blind, blinded.input)
        throw error
    }
    val key = deriveAccountProofKey(finalizePin(blinded, answer.evaluatedElement, primitives), pin, userAddress, primitives)
    return AccountPinProof(key, proofSigner(key, primitives))
}

private suspend fun beginAccountPin(
    api: ZekkeApi,
    root: Signer,
    userAddress: String,
    newPin: CharArray,
    currentProof: PinProofSigner?,
    primitives: Primitives,
): AccountProofKey {
    val blinded = blindPin(newPin, primitives)
    val answer = try {
        val envelope = signRootAction(Action.SECOND_FACTOR_BEGIN, listOf(userAddress, blinded.blindedElement), root, currentProof, primitives)
        api.request(
            Method.POST,
            "/oprf/account/begin",
            body = buildJsonObject {
                put("blinded_element", blinded.blindedElement)
                putEnvelope(envelope)
            },
            token = api.tokens.require(),
        ).decode(EvaluatedElement.serializer())
    } catch (error: Exception) {
        zeroSecrets(blinded.blind, blinded.input)
        throw error
    }
    return deriveAccountProofKey(finalizePin(blinded, answer.evaluatedElement, primitives), newPin, userAddress, primitives)
}

suspend fun enableParanoid(api: ZekkeApi, root: Signer, userAddress: String, pin: CharArray, primitives: Primitives = platformPrimitives()) {
    val key = beginAccountPin(api, root, userAddress, pin, null, primitives)
    try {
        val envelope = signRootAction(Action.ENABLE_SECOND_FACTOR, listOf(key.publicKey), root, primitives = primitives)
        api.request(
            Method.POST,
            "/oprf/account/enable",
            body = buildJsonObject {
                put("proof_public_key", key.publicKey)
                putEnvelope(envelope)
            },
            token = api.tokens.require(),
        )
    } finally {
        zeroAccountProofKey(key)
    }
}

suspend fun rotateAccountPin(
    api: ZekkeApi,
    root: Signer,
    userAddress: String,
    currentPin: CharArray,
    newPin: CharArray,
    primitives: Primitives = platformPrimitives(),
) {
    val current = accountPinProof(api, root, userAddress, currentPin, primitives)
    try {
        val next = beginAccountPin(api, root, userAddress, newPin, current.sign, primitives)
        try {
            val envelope = signRootAction(Action.ROTATE_SECOND_FACTOR, listOf(next.publicKey), root, current.sign, primitives)
            api.request(
                Method.POST,
                "/oprf/account/rotate",
                body = buildJsonObject {
                    put("proof_public_key", next.publicKey)
                    putEnvelope(envelope)
                },
                token = api.tokens.require(),
            )
        } finally {
            zeroAccountProofKey(next)
        }
    } finally {
        zeroAccountProofKey(current.key)
    }
}
