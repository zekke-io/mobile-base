package zekke.core.users

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UsersTest {
    @Test
    fun usernamesAreNormalisedAndChecked() {
        assertEquals("ana.maria", normalizeUsername("  Ana.Maria "))
        assertTrue(isUsername("ana.maria"))
        for (invalid in listOf("ab", ".ana", "ana-", "ana maria", "a".repeat(65))) assertFalse(isUsername(invalid), invalid)
    }
}
