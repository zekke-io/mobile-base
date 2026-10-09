package zekke.core.scopes

import zekke.core.primitives.TestVectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScopesTest {
    @Test
    fun theCanonicalListIsTheVectors() {
        assertEquals(TestVectors.string("device_keys", "canonical_scopes"), CANONICAL_SCOPE_LIST)
        assertEquals(TestVectors.string("device_keys", "genesis_device", "scopes"), formatScopeList(FULL_DEVICE_SCOPES))
    }

    @Test
    fun aListIsParsedOnlyInCanonicalOrderWithoutDuplicates() {
        assertEquals(listOf(Scope.SECRETS, Scope.NOTES), parseScopeList("secrets,notes"))
        for (list in listOf("", "notes,secrets", "notes,notes", "notes,", "vault", "Notes")) {
            assertFailsWith<InvalidScopeListException>(list) { parseScopeList(list) }
        }
    }

    @Test
    fun formattingOrdersAndRefusesEmpty() {
        assertEquals("passwords,files", formatScopeList(listOf(Scope.FILES, Scope.PASSWORDS, Scope.FILES)))
        assertFailsWith<InvalidScopeListException> { formatScopeList(emptyList()) }
    }

    @Test
    fun adminMakesAFullDeviceAndIsNoKeyring() {
        assertTrue(isFullDevice(listOf(Scope.ADMIN, Scope.NOTES)))
        assertFalse(isFullDevice(listOf(Scope.NOTES)))
        assertEquals(KEYRING_SCOPES, keyringScopesOf(FULL_DEVICE_SCOPES))
        assertEquals(Scope.FILES, scopeForItemType(ScopedItemType.FILE))
    }
}
