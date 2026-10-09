package zekke.core.session

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import zekke.core.device.DeviceKeys
import zekke.core.device.generateDeviceKeys
import zekke.core.keyrings.generateScopeKek
import zekke.core.keyrings.generateSharingKeys
import zekke.core.keyrings.sealSharingMaterial
import zekke.core.memory.SecretRegistry
import zekke.core.memory.SecretZeroedException
import zekke.core.primitives.primitives
import zekke.core.scopes.FULL_DEVICE_SCOPES
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import zekke.core.signing.signPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes

class SessionKeystoreTest {
    private class Opened(val keys: SessionKeys, val sharingMaterial: String)

    private fun sessionKeys(scopes: List<Scope> = FULL_DEVICE_SCOPES, device: DeviceKeys = generateDeviceKeys(primitives = primitives)): Opened {
        val keyrings = KEYRING_SCOPES.filter { it in scopes }.map { KeyringEntry(it, 1, generateScopeKek(primitives)) }
        val sharingKek = keyrings.firstOrNull { it.scope == Scope.SHARING }
        val material = sharingKek?.let { sealSharingMaterial(it.kek, generateSharingKeys(primitives), primitives) }.orEmpty()
        val entries = keyrings.map { if (it.scope == Scope.SHARING) KeyringEntry(it.scope, it.generation, it.kek, material) else it }
        return Opened(
            SessionKeys("a".repeat(64), "root", device.deviceId, "registration", scopes, device, entries, entries.associate { it.scope to 1 }),
            material,
        )
    }

    @Test
    fun holdsTheDeviceKeyTheScopeKeksByGenerationAndTheCurrentGenerationOfEach() {
        val keystore = SessionKeystore(primitives = primitives)
        val opened = sessionKeys()
        keystore.open(opened.keys)
        assertEquals(SessionState.UNLOCKED, keystore.state.value)
        assertEquals(1, keystore.currentGeneration(Scope.NOTES))
        assertSame(opened.keys.keyrings.first { it.scope == Scope.NOTES }.kek, keystore.currentKek(Scope.NOTES).kek)
        assertTrue(keystore.isFullDevice)
        assertEquals(64, signPayload("challenge:1", keystore.signer()).let { zekke.core.encoding.base64ToBytes(it).size })
    }

    @Test
    fun refusesAScopeThisDeviceDoesNotHold() {
        val keystore = SessionKeystore(primitives = primitives)
        keystore.open(sessionKeys(listOf(Scope.PASSWORDS)).keys)
        assertFalse(keystore.isFullDevice)
        assertFailsWith<ScopeNotHeldException> { keystore.kek(Scope.NOTES, 1) }
    }

    @Test
    fun reportsAGenerationItHoldsNoWrapOfAsABug() {
        val keystore = SessionKeystore(primitives = primitives)
        keystore.open(sessionKeys().keys)
        assertFailsWith<MissingGenerationException> { keystore.kek(Scope.NOTES, 2) }
    }

    @Test
    fun opensTheSharingMaterialOfAGenerationOnDemandOnce() {
        val keystore = SessionKeystore(primitives = primitives)
        keystore.open(sessionKeys().keys)
        assertSame(keystore.sharingKeys(1), keystore.sharingKeys(1))
    }

    @Test
    fun addsARotatedGenerationWithoutDroppingTheOnesBefore() {
        val keystore = SessionKeystore(primitives = primitives)
        keystore.open(sessionKeys().keys)
        keystore.addKeyrings(listOf(KeyringEntry(Scope.NOTES, 2, generateScopeKek(primitives))), mapOf(Scope.NOTES to 2))
        assertEquals(2, keystore.currentGeneration(Scope.NOTES))
        assertTrue(keystore.hasKek(Scope.NOTES, 1) && keystore.hasKek(Scope.NOTES, 2))
    }

    @Test
    fun lockingZeroesEveryKeyInTheProcessAndRefusesAccessAfterwards() {
        val keystore = SessionKeystore(primitives = primitives)
        val opened = sessionKeys()
        keystore.open(opened.keys)
        val signer = keystore.signer()
        val sharing = keystore.sharingKeys(1)
        keystore.lock()
        assertEquals(SessionState.LOCKED, keystore.state.value)
        assertEquals(0, SecretRegistry.liveCount)
        assertTrue(opened.keys.keyrings.all { it.kek.isZeroed })
        assertTrue(opened.keys.device.signingPrivateKey.isZeroed && opened.keys.device.mlkemSecretKey.isZeroed)
        assertTrue(sharing.x25519PrivateKey.isZeroed)
        assertFailsWith<SecretZeroedException> { signPayload("challenge:1", signer) }
        assertFailsWith<SessionLockedException> { keystore.deviceId }
    }

    @Test
    fun notifiesLockListenersOncePerLockAndNotAfterUnsubscribing() {
        val keystore = SessionKeystore(primitives = primitives)
        var calls = 0
        val unsubscribe = keystore.onLock { calls++ }
        keystore.open(sessionKeys().keys)
        keystore.lock()
        keystore.lock()
        assertEquals(1, calls)
        unsubscribe()
        keystore.open(sessionKeys().keys)
        keystore.lock()
        assertEquals(1, calls)
    }

    @Test
    fun reopeningZeroesThePreviousSessionButNotTheNewOne() {
        val keystore = SessionKeystore(primitives = primitives)
        val first = sessionKeys()
        val second = sessionKeys()
        keystore.open(first.keys)
        keystore.open(second.keys)
        assertTrue(first.keys.keyrings.all { it.kek.isZeroed })
        assertFalse(second.keys.keyrings.any { it.kek.isZeroed })
        assertEquals(second.keys.deviceId, keystore.deviceId)
    }

    @Test
    fun aRemovedDeviceStaysRemoved() {
        val keystore = SessionKeystore(primitives = primitives)
        keystore.open(sessionKeys().keys)
        keystore.markRemoved()
        assertEquals(SessionState.REMOVED, keystore.state.value)
        keystore.beginUnlock()
        assertEquals(SessionState.REMOVED, keystore.state.value)
    }

    @Test
    fun anUnlockInProgressAndOneThatFailed() {
        val keystore = SessionKeystore(primitives = primitives)
        keystore.beginUnlock()
        assertEquals(SessionState.UNLOCKING, keystore.state.value)
        keystore.unlockFailed()
        assertEquals(SessionState.LOCKED, keystore.state.value)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun locksAfterTheIdleWindowAndReArmsOnActivity() = runTest {
        val keystore = SessionKeystore(idleTimeout = 15.minutes, timerScope = backgroundScope, primitives = primitives)
        keystore.open(sessionKeys().keys)
        advanceTimeBy(10.minutes)
        runCurrent()
        keystore.touch()
        advanceTimeBy(10.minutes)
        runCurrent()
        assertTrue(keystore.isUnlocked)
        advanceTimeBy(6.minutes)
        runCurrent()
        assertFalse(keystore.isUnlocked)
        assertEquals(SessionState.LOCKED, keystore.state.value)
    }
}
