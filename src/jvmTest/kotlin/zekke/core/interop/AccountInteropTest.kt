package zekke.core.interop

import kotlinx.coroutines.runBlocking
import zekke.core.account.DevicesToRemove
import zekke.core.account.UnlockOutcome
import zekke.core.account.changeAccountPin
import zekke.core.account.changeDevicePin
import zekke.core.account.completeSignUp
import zekke.core.account.draftSignUp
import zekke.core.account.enrolThisDevice
import zekke.core.account.removeOtherDevices
import zekke.core.account.renewSignIn
import zekke.core.account.unlockWithPin
import zekke.core.auth.AuthRejectedException
import zekke.core.chain.ChainState
import zekke.core.keyrings.fetchChain
import zekke.core.keyrings.listDevices
import zekke.core.scopes.KEYRING_SCOPES
import zekke.core.scopes.Scope
import zekke.core.users.getMe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AccountInteropTest {
    private fun pin(digits: String) = digits.toCharArray()

    @Test
    fun aStandardAccountSignsUpLocksUnlocksAndChangesItsDevicePin() = runBlocking {
        val words = newPhrase()
        val phone = Phone()
        val draft = draftSignUp(phraseCopy(words))
        val signUp = patiently { completeSignUp(phone.services, draft, pin("428193"), paranoid = false) }
        try {
            assertTrue(signUp.created)
            assertFalse(signUp.paranoid)
            assertTrue(phone.services.session.isUnlocked)
            assertEquals(1, phone.services.session.currentGeneration(Scope.NOTES))
            assertFalse(getMe(phone.api).paranoid)

            phone.services.session.lock()
            assertIs<UnlockOutcome.WrongPin>(patiently { unlockWithPin(phone.services, pin("193428")) })
            assertEquals(UnlockOutcome.Unlocked(null), patiently { unlockWithPin(phone.services, pin("428193")) })
            assertEquals(KEYRING_SCOPES.toSet(), phone.services.session.currentGenerations().keys)
            patiently { renewSignIn(phone.services) }

            patiently { changeDevicePin(phone.services, pin("615372")) }
            phone.services.session.lock()
            assertEquals(UnlockOutcome.Unlocked(null), patiently { unlockWithPin(phone.services, pin("615372")) })
        } finally {
            deleteWithPhrase(phone, words)
        }
    }

    @Test
    fun aSecondFullDeviceEntersWithThePhraseAndTheFirstRemovesItWithARotation() = runBlocking {
        val words = newPhrase()
        val first = Phone()
        patiently { completeSignUp(first.services, draftSignUp(phraseCopy(words)), pin("428193"), paranoid = false) }
        try {
            val second = Phone()
            val enrolled = patiently { enrolThisDevice(second.services, phraseCopy(words), pin("739164")) }
            assertFalse(enrolled.paranoid)
            assertTrue(second.services.session.isFullDevice)
            assertEquals(2, patiently { listDevices(first.api) }.devices.size)

            val secondId = second.services.session.deviceId
            val rotated = patiently { removeOtherDevices(first.services, phraseCopy(words), listOf(secondId)) }
            assertEquals(KEYRING_SCOPES, rotated)
            assertEquals(2, first.services.session.currentGeneration(Scope.SECRETS))

            val chain = patiently { fetchChain(first.api) }
            val state = ChainState.replay(first.services.session.userAddress, first.services.session.rootPublicKey, chain)
            assertEquals(listOf(first.services.session.deviceId), state.activeDeviceIds())

            assertEquals(UnlockOutcome.Forgotten, patiently { unlockWithPin(second.services, pin("739164")) })
            assertNull(second.services.vault.load())
        } finally {
            deleteWithPhrase(first, words)
        }
    }

    @Test
    fun aParanoidAccountNeedsItsPinToEnterAndChangingItSignsOutTheOtherFullDevices() = runBlocking {
        val words = newPhrase()
        val first = Phone()
        val signUp = patiently { completeSignUp(first.services, draftSignUp(phraseCopy(words)), pin("428193"), paranoid = true) }
        var accountPin = pin("428193")
        try {
            assertTrue(signUp.paranoid)
            assertTrue(getMe(first.api).paranoid)

            val intruder = Phone()
            assertFailsWith<AuthRejectedException> { patiently { enrolThisDevice(intruder.services, phraseCopy(words), pin("901276")) } }

            val second = Phone()
            val enrolled = patiently { enrolThisDevice(second.services, phraseCopy(words), pin("428193"), DevicesToRemove.None) }
            assertTrue(enrolled.paranoid)

            val change = patiently { changeAccountPin(first.services, phraseCopy(words), pin("428193"), pin("562839")) }
            accountPin = pin("562839")
            assertEquals(listOf(second.services.session.deviceId), change.removedFullDevices)

            first.services.session.lock()
            assertEquals(UnlockOutcome.Unlocked(null), patiently { unlockWithPin(first.services, pin("562839")) })
            assertEquals(UnlockOutcome.Forgotten, patiently { unlockWithPin(second.services, pin("428193")) })
            assertNull(second.services.vault.load())
        } finally {
            deleteWithPhrase(first, words, accountPin)
        }
    }
}
