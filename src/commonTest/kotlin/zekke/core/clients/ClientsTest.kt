package zekke.core.clients

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ClientsTest {
    private val policy = ClientPolicy("android", minSupported = "1.2.0", latest = "1.5.0", deprecatedBelow = "1.4.0", deprecationEnds = "2026-12-01")

    @Test
    fun comparesSemanticVersionsIncludingPrereleases() {
        assertEquals(-1, compareVersions("1.2.3", "1.10.0"))
        assertEquals(-1, compareVersions("1.0.0-alpha", "1.0.0"))
        assertEquals(-1, compareVersions("1.0.0-alpha.2", "1.0.0-alpha.10"))
        assertEquals(1, compareVersions("1.0.0-beta", "1.0.0-alpha.9"))
        assertEquals(0, compareVersions("2.0.0", "2.0.0"))
        assertNull(compareVersions("2.0", "2.0.0"))
    }

    @Test
    fun aVersionIsRequiredDeprecatedAvailableOrCurrent() {
        assertEquals(VersionNotice.Required("1.5.0"), versionNotice(policy, "1.1.9"))
        assertEquals(VersionNotice.Deprecated("1.5.0", "2026-12-01"), versionNotice(policy, "1.3.0"))
        assertEquals(VersionNotice.Available("1.5.0"), versionNotice(policy, "1.4.2"))
        assertEquals(VersionNotice.Current, versionNotice(policy, "1.5.0"))
    }
}
