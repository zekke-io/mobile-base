package zekke.core.session

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import zekke.core.device.DeviceKeys
import zekke.core.device.deviceSecrets
import zekke.core.device.deviceSigner
import zekke.core.keyrings.DeviceSecrets
import zekke.core.keyrings.SharingKeyPair
import zekke.core.keyrings.openSharingMaterial
import zekke.core.memory.SecretBytes
import zekke.core.memory.SecretRegistry
import zekke.core.memory.newPlatformLock
import zekke.core.memory.withLock
import zekke.core.primitives.Primitives
import zekke.core.primitives.platformPrimitives
import zekke.core.scopes.Scope
import zekke.core.scopes.isFullDevice
import zekke.core.signing.Signer
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

val DEFAULT_IDLE_TIMEOUT: Duration = 15.minutes

enum class SessionState { LOCKED, UNLOCKING, UNLOCKED, REMOVED }

class KeyringEntry(val scope: Scope, val generation: Int, val kek: SecretBytes, val sealedMaterial: String? = null)

class SessionKeys(
    val userAddress: String,
    val rootPublicKey: String,
    val deviceId: String,
    val registrationId: String?,
    val scopes: List<Scope>,
    val device: DeviceKeys,
    val keyrings: List<KeyringEntry>,
    val current: Map<Scope, Int>,
)

class ScopeNotHeldException(val scope: Scope) : IllegalStateException("this device does not hold the ${scope.wire} scope")

class MissingGenerationException(val scope: Scope, val generation: Int) : IllegalStateException(
    "this device holds no wrap of ${scope.wire} generation $generation. That is a bug to report: " +
        "every generation of a held scope must be wrapped to every device holding it",
)

class SessionLockedException : IllegalStateException("the session is locked: unlock with the PIN first")

class CurrentKek(val generation: Int, val kek: SecretBytes)

private class OpenSession(
    val keys: SessionKeys,
    val keks: MutableMap<Pair<Scope, Int>, KeyringEntry>,
    val current: MutableMap<Scope, Int>,
    var registrationId: String?,
    val sharing: MutableMap<Int, SharingKeyPair> = LinkedHashMap(),
)

class SessionKeystore(
    private val idleTimeout: Duration = DEFAULT_IDLE_TIMEOUT,
    private val timerScope: CoroutineScope? = null,
    private val primitives: Primitives = platformPrimitives(),
) {
    private val guard = newPlatformLock()
    private var open: OpenSession? = null
    private var idleJob: Job? = null
    private val lockListeners = LinkedHashSet<() -> Unit>()
    private val mutableState = MutableStateFlow(SessionState.LOCKED)

    val state: StateFlow<SessionState> = mutableState.asStateFlow()

    val isUnlocked: Boolean get() = guard.withLock { open != null }

    fun beginUnlock() {
        guard.withLock {
            if (open == null && mutableState.value != SessionState.REMOVED) mutableState.value = SessionState.UNLOCKING
        }
    }

    fun unlockFailed() {
        guard.withLock { if (mutableState.value == SessionState.UNLOCKING) mutableState.value = SessionState.LOCKED }
    }

    fun open(keys: SessionKeys) {
        val previous = guard.withLock {
            idleJob?.cancel()
            idleJob = null
            open.also { open = null }
        }
        previous?.let { zeroContents(it, keeping = keys) }
        guard.withLock {
            open = OpenSession(
                keys = keys,
                keks = keys.keyrings.associateByTo(LinkedHashMap()) { it.scope to it.generation },
                current = LinkedHashMap(keys.current),
                registrationId = keys.registrationId,
            )
            mutableState.value = SessionState.UNLOCKED
        }
        touch()
    }

    fun addKeyrings(entries: List<KeyringEntry>, current: Map<Scope, Int>) {
        val session = require()
        guard.withLock {
            for (entry in entries) {
                val id = entry.scope to entry.generation
                val existing = session.keks[id]
                if (existing != null && existing.kek !== entry.kek) existing.kek.zero()
                session.keks[id] = entry
            }
            for ((scope, generation) in current) {
                if (generation > (session.current[scope] ?: 0)) session.current[scope] = generation
            }
        }
    }

    fun setRegistration(registrationId: String) {
        val session = require()
        guard.withLock { session.registrationId = registrationId }
    }

    fun lock() {
        val (wasOpen, listeners) = guard.withLock {
            idleJob?.cancel()
            idleJob = null
            val wasOpen = open != null
            open = null
            if (mutableState.value != SessionState.REMOVED) mutableState.value = SessionState.LOCKED
            wasOpen to lockListeners.toList()
        }
        SecretRegistry.zeroAll()
        if (wasOpen) listeners.forEach { it() }
    }

    fun markRemoved() {
        lock()
        guard.withLock { mutableState.value = SessionState.REMOVED }
    }

    fun onLock(listener: () -> Unit): () -> Unit {
        guard.withLock { lockListeners.add(listener) }
        return { guard.withLock { lockListeners.remove(listener) } }
    }

    fun touch() {
        val scope = timerScope ?: return
        guard.withLock {
            idleJob?.cancel()
            idleJob = null
            if (open != null && idleTimeout.isPositive()) {
                idleJob = scope.launch {
                    delay(idleTimeout)
                    lock()
                }
            }
        }
    }

    val userAddress: String get() = require().keys.userAddress

    val rootPublicKey: String get() = require().keys.rootPublicKey

    val deviceId: String get() = require().keys.deviceId

    val registrationId: String? get() = require().registrationId

    val scopes: List<Scope> get() = require().keys.scopes

    val isFullDevice: Boolean get() = isFullDevice(scopes)

    val device: DeviceKeys get() = require().keys.device

    fun holds(scope: Scope): Boolean = guard.withLock { open?.keys?.scopes?.contains(scope) ?: false }

    fun requireScope(scope: Scope) {
        if (!holds(scope)) throw ScopeNotHeldException(scope)
    }

    fun signer(): Signer = deviceSigner(require().keys.device, primitives)

    fun deviceSecrets(): DeviceSecrets = deviceSecrets(require().keys.device, primitives)

    fun currentGeneration(scope: Scope): Int {
        requireScope(scope)
        return guard.withLock { require().current[scope] } ?: throw MissingGenerationException(scope, 0)
    }

    fun currentGenerations(): Map<Scope, Int> = guard.withLock { LinkedHashMap(require().current) }

    fun kek(scope: Scope, generation: Int): SecretBytes {
        requireScope(scope)
        return guard.withLock { require().keks[scope to generation]?.kek } ?: throw MissingGenerationException(scope, generation)
    }

    fun hasKek(scope: Scope, generation: Int): Boolean = guard.withLock { open?.keks?.containsKey(scope to generation) ?: false }

    fun currentKek(scope: Scope): CurrentKek {
        val generation = currentGeneration(scope)
        return CurrentKek(generation, kek(scope, generation))
    }

    fun heldGenerations(): List<Pair<Scope, Int>> = guard.withLock { require().keks.keys.toList() }

    fun sharingKeys(generation: Int): SharingKeyPair {
        val session = require()
        guard.withLock { session.sharing[generation] }?.let { return it }
        val entry = guard.withLock { session.keks[Scope.SHARING to generation] } ?: throw MissingGenerationException(Scope.SHARING, generation)
        val sealed = entry.sealedMaterial ?: throw MissingGenerationException(Scope.SHARING, generation)
        val opened = openSharingMaterial(entry.kek, sealed, primitives)
        guard.withLock { session.sharing.getOrPut(generation) { opened } }
        return opened
    }

    private fun zeroContents(session: OpenSession, keeping: SessionKeys) {
        val kept = keeping.keyrings.map { it.kek } + with(keeping.device) {
            listOf(signingPrivateKey, x25519PrivateKey, mlkemSeed, mlkemSecretKey)
        }
        val previous = session.keks.values.map { it.kek } +
            session.sharing.values.flatMap { listOf(it.x25519PrivateKey, it.mlkemSeed, it.mlkemSecretKey) } +
            with(session.keys.device) { listOf(signingPrivateKey, x25519PrivateKey, mlkemSeed, mlkemSecretKey) }
        previous.filter { old -> kept.none { it === old } }.forEach { it.zero() }
    }

    private fun require(): OpenSession {
        val session = guard.withLock { open } ?: throw SessionLockedException()
        touch()
        return session
    }
}
