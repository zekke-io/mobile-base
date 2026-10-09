package zekke.core.account

import zekke.core.api.ApiError
import zekke.core.api.ZekkeApi
import zekke.core.auth.AuthRejectedException
import zekke.core.auth.enrolWithRoot
import zekke.core.auth.readChainWithRoot
import zekke.core.auth.signInDevice
import zekke.core.auth.signUpWithGenesis
import zekke.core.chain.ChainState
import zekke.core.chain.InvalidChainException
import zekke.core.chain.StoredChainEvent
import zekke.core.device.DeviceIdentity
import zekke.core.device.DeviceKeys
import zekke.core.device.DeviceRecord
import zekke.core.device.DeviceVault
import zekke.core.device.WrongDevicePinException
import zekke.core.device.deviceDeclaration
import zekke.core.device.deviceSecrets
import zekke.core.device.deviceSigner
import zekke.core.device.generateDeviceKeys
import zekke.core.device.loadDeviceRecord
import zekke.core.device.openDeviceRecord
import zekke.core.device.recordIdentity
import zekke.core.device.saveDeviceRecord
import zekke.core.device.sealDeviceRecord
import zekke.core.device.zeroDeviceKeys
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.keyrings.BatchAuthor
import zekke.core.keyrings.BuiltBatch
import zekke.core.keyrings.DeviceRecipient
import zekke.core.keyrings.KeyringWrap
import zekke.core.keyrings.RootWrapper
import zekke.core.keyrings.applyDeviceBatch
import zekke.core.keyrings.buildDeviceRemoval
import zekke.core.keyrings.buildEnrolment
import zekke.core.keyrings.buildGenesis
import zekke.core.keyrings.buildSelfRemoval
import zekke.core.keyrings.currentFrom
import zekke.core.keyrings.fetchChain
import zekke.core.keyrings.loadKeyrings
import zekke.core.keyrings.openRootKeyrings
import zekke.core.keyrings.postOwnWraps
import zekke.core.keyrings.wrapKekForDevice
import zekke.core.keyrings.wrapKekForRoot
import zekke.core.keyrings.zeroCreated
import zekke.core.keyrings.zeroSharingKeys
import zekke.core.keys.RootKeys
import zekke.core.keys.deriveRootKeysFromMnemonic
import zekke.core.keys.zeroRootKeys
import zekke.core.oprf.AccountPinProof
import zekke.core.oprf.DeviceRegistrationGoneException
import zekke.core.oprf.OfflineException
import zekke.core.oprf.accountPinProof
import zekke.core.oprf.confirmDevicePin
import zekke.core.oprf.deleteDevicePin
import zekke.core.oprf.enableParanoid
import zekke.core.oprf.evaluateDevicePin
import zekke.core.oprf.registerDevicePin
import zekke.core.oprf.rotateAccountPin
import zekke.core.oprf.zeroAccountProofKey
import zekke.core.oprf.zeroDevicePinKeys
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.FULL_DEVICE_SCOPES
import zekke.core.scopes.Scope
import zekke.core.session.KeyringEntry
import zekke.core.session.SessionKeys
import zekke.core.session.SessionKeystore
import zekke.core.signing.Signer
import zekke.core.signing.rawKeySigner
import zekke.core.users.deleteAccount
import zekke.core.users.getMe
import zekke.core.users.lookupUsername

class AccountServices(
    val api: ZekkeApi,
    val session: SessionKeystore,
    val vault: DeviceVault,
    val primitives: Primitives = platformPrimitives(),
)

class DeviceRemovedException : IllegalStateException("this device is no longer enrolled in the account")

class ChainNotVerifiedException(cause: Throwable) : IllegalStateException("the account event chain does not verify from the root key", cause)

class NoAccountForPhraseException : IllegalStateException("no account uses this recovery phrase")

class PhraseMismatchException : IllegalArgumentException("that recovery phrase belongs to a different account")

class NoDeviceRecordException : IllegalStateException("this phone holds no device record")

class ParanoidPinRequiredException : IllegalArgumentException("a Paranoid account needs its account PIN here")

class DeviceSummary(val id: String, val scopes: String, val createdAt: String)

class TooManyDevicesException(val devices: List<DeviceSummary>) : IllegalStateException("the account already holds the maximum number of devices")

fun verifyOwnChain(
    userAddress: String,
    rootPublicKey: String,
    deviceId: String,
    events: List<StoredChainEvent>,
    primitives: Primitives = platformPrimitives(),
): ChainState {
    val state = try {
        ChainState.replay(userAddress, rootPublicKey, events, primitives)
    } catch (error: InvalidChainException) {
        throw ChainNotVerifiedException(error)
    }
    if (state.devices[deviceId]?.active != true) throw DeviceRemovedException()
    return state
}

suspend fun readVerifiedChain(services: AccountServices, userAddress: String, rootPublicKey: String, deviceId: String): ChainState =
    verifyOwnChain(userAddress, rootPublicKey, deviceId, fetchChain(services.api), services.primitives)

private fun rootWrapper(root: RootKeys, primitives: Primitives) = RootWrapper { kek -> wrapKekForRoot(root.wrapKey, kek, primitives) }

private suspend fun persistDevice(services: AccountServices, keys: DeviceKeys, identity: DeviceIdentity, pin: CharArray): DeviceRecord {
    val registration = registerDevicePin(services.api, pin, services.primitives)
    try {
        val record = sealDeviceRecord(keys, identity, registration.registrationId, registration.salt, registration.keys.wrapKey, services.primitives)
        saveDeviceRecord(services.vault, record)
        return record
    } finally {
        zeroDevicePinKeys(registration.keys)
    }
}

private fun openSession(
    services: AccountServices,
    identity: DeviceIdentity,
    registrationId: String,
    device: DeviceKeys,
    keyrings: List<KeyringEntry>,
    current: Map<Scope, Int>,
) {
    services.session.open(
        SessionKeys(identity.userAddress, identity.rootPublicKey, device.deviceId, registrationId, identity.scopes, device, keyrings, current),
    )
}

class SignUpDraft internal constructor(val root: RootKeys, val device: DeviceKeys, val built: BuiltBatch)

fun draftSignUp(words: List<CharArray>, primitives: Primitives = platformPrimitives()): SignUpDraft {
    val root = deriveRootKeysFromMnemonic(words, primitives)
    val device = generateDeviceKeys(primitives = primitives)
    try {
        val built = buildGenesis(
            root.userAddress,
            root.signing.publicKeySpkiBase64,
            rawKeySigner(root.signing.privateKey, primitives),
            rootWrapper(root, primitives),
            deviceDeclaration(device, FULL_DEVICE_SCOPES),
            primitives,
        )
        return SignUpDraft(root, device, built)
    } catch (error: Throwable) {
        zeroRootKeys(root)
        zeroDeviceKeys(device)
        throw error
    }
}

fun discardSignUpDraft(draft: SignUpDraft?) {
    if (draft == null) return
    zeroRootKeys(draft.root)
    zeroDeviceKeys(draft.device)
    zeroCreated(draft.built.created)
}

class SignUpResult(val created: Boolean, val paranoid: Boolean, val paranoidFailure: Throwable?)

class GenesisDeviceMismatchException : IllegalStateException("the server answered for another device than the genesis names")

suspend fun completeSignUp(services: AccountServices, draft: SignUpDraft, pin: CharArray, paranoid: Boolean): SignUpResult {
    val primitives = services.primitives
    val root = draft.root
    val rootSigner = rawKeySigner(root.signing.privateKey, primitives)
    val identity = DeviceIdentity(root.userAddress, root.signing.publicKeySpkiBase64, FULL_DEVICE_SCOPES)

    val outcome = signUpWithGenesis(services.api, root.userAddress, root.signing.publicKeySpkiBase64, rootSigner, draft.built.batch, primitives)
    if (outcome.grant.deviceId != draft.device.deviceId) throw GenesisDeviceMismatchException()

    readVerifiedChain(services, identity.userAddress, identity.rootPublicKey, draft.device.deviceId)
    val record = persistDevice(services, draft.device, identity, pin)

    var paranoidFailure: Throwable? = null
    if (paranoid) {
        try {
            enableParanoid(services.api, rootSigner, root.userAddress, pin, primitives)
        } catch (error: ApiError) {
            paranoidFailure = error
        }
    }

    val sealed = draft.built.batch.materials.firstOrNull { it.scope == Scope.SHARING }
    val keyrings = draft.built.created.map {
        KeyringEntry(it.scope, it.generation, it.kek, if (it.scope == Scope.SHARING) sealed?.sealedMaterial else null)
    }
    draft.built.created.forEach { zeroSharingKeys(it.sharingKeys) }
    zeroRootKeys(root)

    openSession(services, identity, record.registrationId, draft.device, keyrings, draft.built.created.associate { it.scope to it.generation })
    return SignUpResult(outcome.created, paranoid && paranoidFailure == null, paranoidFailure)
}

sealed interface UnlockOutcome {
    data class Unlocked(val chainProblem: ChainNotVerifiedException?) : UnlockOutcome

    data object NoDevice : UnlockOutcome

    data class WrongPin(val attemptsRemaining: Int) : UnlockOutcome

    data object Forgotten : UnlockOutcome

    data object Removed : UnlockOutcome

    data object Offline : UnlockOutcome

    data class RateLimited(val retryAfterSeconds: Long?) : UnlockOutcome
}

suspend fun unlockWithPin(services: AccountServices, pin: CharArray): UnlockOutcome {
    val record = loadDeviceRecord(services.vault) ?: return UnlockOutcome.NoDevice
    services.session.beginUnlock()
    try {
        return unlock(services, record, pin).also { if (it !is UnlockOutcome.Unlocked) services.session.unlockFailed() }
    } catch (error: Throwable) {
        services.session.unlockFailed()
        throw error
    }
}

private suspend fun unlock(services: AccountServices, record: DeviceRecord, pin: CharArray): UnlockOutcome {
    val api = services.api
    val primitives = services.primitives
    val evaluation = try {
        evaluateDevicePin(api, record.registrationId, pin, base64ToBytes(record.salt), primitives)
    } catch (_: DeviceRegistrationGoneException) {
        forgetThisDevice(services)
        return UnlockOutcome.Forgotten
    } catch (_: OfflineException) {
        return UnlockOutcome.Offline
    } catch (error: ApiError) {
        if (error.isRateLimited) return UnlockOutcome.RateLimited(error.retryAfterSeconds)
        throw error
    }

    val device = try {
        openDeviceRecord(record, evaluation.keys.wrapKey, primitives)
    } catch (_: WrongDevicePinException) {
        zeroDevicePinKeys(evaluation.keys)
        if (evaluation.attemptsRemaining <= 0) {
            forgetThisDevice(services)
            return UnlockOutcome.Forgotten
        }
        return UnlockOutcome.WrongPin(evaluation.attemptsRemaining)
    }

    try {
        confirmDevicePin(api, record.registrationId, evaluation, primitives)
    } finally {
        zeroDevicePinKeys(evaluation.keys)
    }

    try {
        signInDevice(api, record.deviceId, deviceSigner(device, primitives), primitives)
    } catch (_: AuthRejectedException) {
        zeroDeviceKeys(device)
        services.vault.delete()
        services.session.markRemoved()
        return UnlockOutcome.Removed
    } catch (error: Throwable) {
        zeroDeviceKeys(device)
        throw error
    }

    var identity = recordIdentity(record)
    var chainProblem: ChainNotVerifiedException? = null
    try {
        val state = readVerifiedChain(services, identity.userAddress, identity.rootPublicKey, record.deviceId)
        state.devices[record.deviceId]?.scopes?.let { held -> identity = DeviceIdentity(identity.userAddress, identity.rootPublicKey, FULL_DEVICE_SCOPES.filter { it in held }) }
    } catch (_: DeviceRemovedException) {
        zeroDeviceKeys(device)
        api.tokens.clear()
        services.vault.delete()
        services.session.markRemoved()
        return UnlockOutcome.Removed
    } catch (error: ChainNotVerifiedException) {
        chainProblem = error
    } catch (error: Throwable) {
        zeroDeviceKeys(device)
        api.tokens.clear()
        throw error
    }

    try {
        val opened = loadKeyrings(api, identity.userAddress, deviceSecrets(device, primitives), primitives)
        openSession(services, identity, record.registrationId, device, opened.entries, opened.current)
    } catch (error: Throwable) {
        zeroDeviceKeys(device)
        api.tokens.clear()
        throw error
    }
    return UnlockOutcome.Unlocked(chainProblem)
}

suspend fun renewSignIn(services: AccountServices) {
    try {
        signInDevice(services.api, services.session.deviceId, services.session.signer(), services.primitives)
    } catch (_: AuthRejectedException) {
        throw DeviceRemovedException()
    }
}

suspend fun forgetThisDevice(services: AccountServices) {
    if (services.session.isUnlocked) {
        try {
            signOff(services)
        } catch (error: ApiError) {
            if (error.isRateLimited) throw error
        } catch (_: AuthRejectedException) {
        } catch (_: DeviceRemovedException) {
        }
    }
    services.api.tokens.clear()
    services.session.lock()
    services.vault.delete()
}

suspend fun removeThisDevice(services: AccountServices) {
    loadDeviceRecord(services.vault) ?: throw NoDeviceRecordException()
    signOff(services)
    services.api.tokens.clear()
    services.session.lock()
    services.vault.delete()
}

private suspend fun signOff(services: AccountServices) {
    val session = services.session
    if (services.api.tokens.get() == null) renewSignIn(services)
    val state = readVerifiedChain(services, session.userAddress, session.rootPublicKey, session.deviceId)
    applyDeviceBatch(services.api, buildSelfRemoval(state, BatchAuthor(session.deviceId, session.signer()), services.primitives))
}

suspend fun changeDevicePin(services: AccountServices, newPin: CharArray) {
    val record = loadDeviceRecord(services.vault) ?: throw NoDeviceRecordException()
    val next = persistDevice(services, services.session.device, recordIdentity(record), newPin)
    services.session.setRegistration(next.registrationId)
    try {
        deleteDevicePin(services.api, record.registrationId)
    } catch (_: ApiError) {
    }
}

suspend fun accountExists(api: ZekkeApi, userAddress: String): Boolean = try {
    lookupUsername(api, userAddress)
    true
} catch (error: ApiError) {
    if (error.status == 404) false else throw error
}

private class RootAccess(val chain: zekke.core.auth.RootChainAnswer, val proof: AccountPinProof?)

private suspend fun readChainAsOwner(services: AccountServices, root: RootKeys, accountPin: CharArray?): RootAccess {
    val signer = rawKeySigner(root.signing.privateKey, services.primitives)
    try {
        return RootAccess(readChainWithRoot(services.api, root.userAddress, signer, primitives = services.primitives), null)
    } catch (error: AuthRejectedException) {
        if (accountPin == null) throw error
    }
    val proof = accountPinProof(services.api, signer, root.userAddress, accountPin, services.primitives)
    try {
        return RootAccess(readChainWithRoot(services.api, root.userAddress, signer, proof.sign, services.primitives), proof)
    } catch (error: Throwable) {
        zeroAccountProofKey(proof.key)
        throw error
    }
}

sealed interface DevicesToRemove {
    data object None : DevicesToRemove

    data object All : DevicesToRemove

    data class Listed(val ids: List<String>) : DevicesToRemove
}

class EnrolmentResult(val paranoid: Boolean, val removed: List<String>)

suspend fun enrolThisDevice(
    services: AccountServices,
    words: List<CharArray>,
    pin: CharArray,
    remove: DevicesToRemove = DevicesToRemove.None,
): EnrolmentResult {
    val primitives = services.primitives
    val api = services.api
    val root = deriveRootKeysFromMnemonic(words, primitives)
    val rootPublicKey = root.signing.publicKeySpkiBase64
    val signer = rawKeySigner(root.signing.privateKey, primitives)
    var device: DeviceKeys? = null
    var access: RootAccess? = null
    try {
        if (!accountExists(api, root.userAddress)) throw NoAccountForPhraseException()
        access = readChainAsOwner(services, root, pin)
        val state = try {
            ChainState.replay(root.userAddress, rootPublicKey, access.chain.chain, primitives)
        } catch (error: InvalidChainException) {
            throw ChainNotVerifiedException(error)
        }
        val removeIds = when (remove) {
            DevicesToRemove.None -> emptyList()
            DevicesToRemove.All -> state.activeDeviceIds()
            is DevicesToRemove.Listed -> remove.ids
        }

        val newDevice = generateDeviceKeys(primitives = primitives)
        device = newDevice
        val identity = DeviceIdentity(root.userAddress, rootPublicKey, FULL_DEVICE_SCOPES)
        val built = buildEnrolment(state, signer, rootWrapper(root, primitives), deviceDeclaration(newDevice, FULL_DEVICE_SCOPES), removeIds, primitives)
        val created = built.created.map { it.scope to it.generation }.toSet()
        zeroCreated(built.created)

        val answer = try {
            enrolWithRoot(api, root.userAddress, signer, built.batch, access.proof?.sign, primitives)
        } catch (error: ApiError) {
            if (error.isTooManyDevices) throw TooManyDevicesException(access.chain.devices.map { DeviceSummary(it.id, it.scopes, it.createdAt) })
            throw error
        }

        val enrolled = verifyOwnChain(root.userAddress, rootPublicKey, newDevice.deviceId, answer.chain, primitives)
        val rootEntries = openRootKeyrings(answer.rootKeyrings, root.wrapKey, primitives)
        val recipient = DeviceRecipient(newDevice.deviceId, bytesToBase64(newDevice.x25519PublicKey), bytesToBase64(newDevice.mlkemPublicKey))
        val held = identity.scopes.toSet()
        val wraps = rootEntries
            .filter { it.scope in held && (it.scope to it.generation) !in created }
            .map { KeyringWrap(it.scope, it.generation, newDevice.deviceId, wrapKekForDevice(it.kek, root.userAddress, recipient, primitives)) }
        postOwnWraps(api, wraps)

        val record = persistDevice(services, newDevice, identity, pin)
        val (kept, dropped) = rootEntries.partition { it.scope in held }
        dropped.forEach { it.kek.zero() }
        openSession(services, identity, record.registrationId, newDevice, kept, currentFrom(answer.rootKeyrings))
        device = null

        return EnrolmentResult(access.proof != null, removeIds.filter { enrolled.devices[it]?.active != true })
    } finally {
        zeroRootKeys(root)
        access?.proof?.let { zeroAccountProofKey(it.key) }
        zeroDeviceKeys(device)
    }
}

private suspend fun <T> withAccountRoot(services: AccountServices, words: List<CharArray>, run: suspend (RootKeys) -> T): T {
    val root = deriveRootKeysFromMnemonic(words, services.primitives)
    try {
        if (root.userAddress != services.session.userAddress) throw PhraseMismatchException()
        return run(root)
    } finally {
        zeroRootKeys(root)
    }
}

private suspend fun removeDevicesWithRoot(services: AccountServices, root: RootKeys, deviceIds: List<String>): List<Scope> {
    if (deviceIds.isEmpty()) return emptyList()
    val session = services.session
    val state = readVerifiedChain(services, session.userAddress, session.rootPublicKey, session.deviceId)
    val built = buildDeviceRemoval(state, BatchAuthor(session.deviceId, session.signer()), rootWrapper(root, services.primitives), deviceIds, services.primitives)
    try {
        applyDeviceBatch(services.api, built.batch)
    } catch (error: Throwable) {
        zeroCreated(built.created)
        throw error
    }
    val sealed = built.batch.materials.firstOrNull { it.scope == Scope.SHARING }
    session.addKeyrings(
        built.created.filter { session.holds(it.scope) }.map {
            KeyringEntry(it.scope, it.generation, it.kek, if (it.scope == Scope.SHARING && sealed?.generation == it.generation) sealed.sealedMaterial else null)
        },
        built.created.associate { it.scope to it.generation },
    )
    built.created.filter { !session.holds(it.scope) }.forEach { it.kek.zero() }
    built.created.forEach { zeroSharingKeys(it.sharingKeys) }
    return built.created.map { it.scope }
}

suspend fun removeOtherDevices(services: AccountServices, words: List<CharArray>, deviceIds: List<String>): List<Scope> =
    withAccountRoot(services, words) { root -> removeDevicesWithRoot(services, root, deviceIds) }

private suspend fun otherFullDevices(services: AccountServices): List<String> {
    val session = services.session
    val state = readVerifiedChain(services, session.userAddress, session.rootPublicKey, session.deviceId)
    return state.activeDevicesWith(Scope.ADMIN).filter { it != session.deviceId }
}

class AccountPinChange(val removedFullDevices: List<String>)

suspend fun turnOnParanoid(services: AccountServices, words: List<CharArray>, pin: CharArray): AccountPinChange =
    withAccountRoot(services, words) { root ->
        enableParanoid(services.api, rawKeySigner(root.signing.privateKey, services.primitives), root.userAddress, pin, services.primitives)
        changeDevicePin(services, pin)
        val others = otherFullDevices(services)
        removeDevicesWithRoot(services, root, others)
        AccountPinChange(others)
    }

suspend fun changeAccountPin(services: AccountServices, words: List<CharArray>, currentPin: CharArray, newPin: CharArray): AccountPinChange =
    withAccountRoot(services, words) { root ->
        rotateAccountPin(services.api, rawKeySigner(root.signing.privateKey, services.primitives), root.userAddress, currentPin, newPin, services.primitives)
        changeDevicePin(services, newPin)
        val others = otherFullDevices(services)
        removeDevicesWithRoot(services, root, others)
        AccountPinChange(others)
    }

suspend fun deleteAccountWithPhrase(services: AccountServices, words: List<CharArray>, accountPin: CharArray? = null) {
    val paranoid = getMe(services.api).paranoid
    withAccountRoot(services, words) { root ->
        val signer: Signer = rawKeySigner(root.signing.privateKey, services.primitives)
        var proof: AccountPinProof? = null
        try {
            if (paranoid) {
                val pin = accountPin ?: throw ParanoidPinRequiredException()
                proof = accountPinProof(services.api, signer, root.userAddress, pin, services.primitives)
            }
            deleteAccount(services.api, root.userAddress, signer, proof?.sign, services.primitives)
        } finally {
            proof?.let { zeroAccountProofKey(it.key) }
        }
    }
    services.api.tokens.clear()
    services.session.lock()
    services.vault.delete()
}
