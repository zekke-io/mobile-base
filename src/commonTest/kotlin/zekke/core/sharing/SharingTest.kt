package zekke.core.sharing

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.addJsonObject
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.encoding.utf8ToBytes
import zekke.core.items.TestVault
import zekke.core.items.data
import zekke.core.items.newItemId
import zekke.core.keyrings.generateScopeKek
import zekke.core.keyrings.generateSharingKeys
import zekke.core.notifications.listNotifications
import zekke.core.notifications.markNotificationsRead
import zekke.core.pairing.MalformedPairingCodeException
import zekke.core.pairing.PairingParties
import zekke.core.pairing.displayFingerprint
import zekke.core.pairing.formatPairingCode
import zekke.core.pairing.normalisePairingCode
import zekke.core.pairing.pairingFingerprint
import zekke.core.pqxdh.RecipientKeys
import zekke.core.pqxdh.RecipientSecrets
import zekke.core.pqxdh.rawX25519Agreement
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import zekke.core.signing.Action
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SharingTest {
    private val alice = "a".repeat(64)
    private val bob = "b".repeat(64)

    @Test
    fun aConnectionKeyOpensOnlyForItsRecipientAndItsTwoParties() {
        val keys = generateSharingKeys(primitives)
        val recipient = RecipientKeys(keys.x25519PublicKey, keys.mlkemPublicKey)
        val secrets = RecipientSecrets(rawX25519Agreement(keys.x25519PrivateKey, primitives), keys.mlkemSecretKey)
        val connectionKey = createConnectionKey(primitives)
        val blob = sealConnectionKey(connectionKey, recipient, alice, bob, primitives)
        assertContentEquals(connectionKey.withBytes { it.copyOf() }, openConnectionKey(blob, secrets, alice, bob, primitives).withBytes { it.copyOf() })
        assertFailsWith<IllegalStateException> { openConnectionKey(blob, secrets, bob, alice, primitives) }
        assertFailsWith<MalformedPartyAddressException> { sealConnectionKey(connectionKey, recipient, "A".repeat(64), bob, primitives) }
        assertFailsWith<MalformedPartyAddressException> { openConnectionKey(blob, secrets, alice, "", primitives) }
    }

    @Test
    fun aWrapUnderAConnectionIsAnIvAndAnAesGcmCiphertextWithAFreshIvEachTime() {
        val key = generateScopeKek(primitives)
        val payload = generateScopeKek(primitives)
        val first = wrapUnderConnection(key, payload, primitives)
        val second = wrapUnderConnection(key, payload, primitives)
        assertEquals(12 + 32 + 16, base64ToBytes(first).size)
        assertFalse(first == second)
        assertContentEquals(payload.withBytes { it.copyOf() }, unwrapUnderConnection(key, first, primitives).withBytes { it.copyOf() })
        assertFailsWith<ConnectionKeyException> { unwrapUnderConnection(generateScopeKek(primitives), first, primitives) }
        assertFailsWith<ConnectionKeyException> { unwrapUnderConnection(key, bytesToBase64(ByteArray(12)), primitives) }
    }

    @Test
    fun theRootFingerprintIsSixGroupsOfTheSpkiDigest() {
        val spki = TestVectors.string("identity_key_p256", "public_key_spki_base64")
        val fingerprint = rootFingerprint(spki, primitives)
        val hex = bytesToHex(primitives.sha2.sha256(base64ToBytes(spki))).uppercase()
        assertEquals((0 until 6).joinToString("-") { hex.substring(it * 4, it * 4 + 4) }, fingerprint)
        assertTrue(Regex("^([0-9A-F]{4}-){5}[0-9A-F]{4}$").matches(fingerprint))
    }

    @Test
    fun theAddressBookKeepsTheFirstPinAndTheLaterName() {
        val book = parseAddressBook("{\"v\":1,\"pins\":{\"$alice\":{\"root_public_key\":\"k1\",\"pinned_at\":\"t\"}},\"nicknames\":{},\"devices\":{}}")
        assertSame(book, pinRoot(alice, "k2").apply(book))
        val named = setNickname("c1", "  Ana ", "2026-10-02T00:00:00.000Z").apply(book)
        assertEquals("Ana", displayName(named.nicknames["c1"]))
        val stored = AddressBook(pins = mapOf(alice to RootPin("stored", "t")), nicknames = mapOf("c1" to NamedEntry("Old", "2026-10-01T00:00:00.000Z")))
        val local = AddressBook(pins = mapOf(alice to RootPin("local", "t"), bob to RootPin("b", "t")), nicknames = mapOf("c1" to NamedEntry("New", "2026-10-03T00:00:00.000Z")))
        val merged = mergeAddressBooks(stored, local)
        assertEquals("stored", merged.pins.getValue(alice).rootPublicKey)
        assertEquals("b", merged.pins.getValue(bob).rootPublicKey)
        assertEquals("New", merged.nicknames.getValue("c1").name)
        assertEquals(merged.pins, parseAddressBook(formatAddressBook(merged)).pins)
        assertFailsWith<AddressBookFormatException> { parseAddressBook("{\"v\":2}") }
        assertFailsWith<AddressBookFormatException> { parseAddressBook("nope") }
        assertNull(displayName(NamedEntry("  ", "t")))
    }

    @Test
    fun theSubkeyDigestIsTheWebAppsLinesJoinedByNewlines() {
        val vault = TestVault()
        val keys = listOf(ConnectionKeyRecord("secrets", 1, "w1"), ConnectionKeyRecord("notes", 2, "w2"))
        assertEquals(bytesToHex(primitives.sha2.sha256(utf8ToBytes("secrets:1:w1\nnotes:2:w2"))), connectionKeysDigest(keys, vault.context))
    }

    @Test
    fun anInvitationAndAShareAreSignedOverWhatTheyCarry() = runTest {
        val vault = TestVault()
        val connectionId = newItemId(primitives)
        vault.server.answer { data(buildJsonObject { it.json.forEach { (k, v) -> if (k !in setOf("challenge", "timestamp", "signature")) put(k, v) }; put("direction", "outbound"); put("username", "ana"); put("user_address", bob); put("status", "pending") }, 201) }
        createConnection(vault.context, " Ana ", "blob", "sealed", 1, 3, connectionId)
        val invite = vault.server.sent.single().json
        assertEquals("ana", invite.getValue("recipient_username").jsonPrimitive.content)
        assertTrue(vault.verifies(invite, Action.CONNECTION_INVITE, listOf("ana", "blob", "1", "3")))

        val itemId = newItemId(primitives)
        vault.server.answer { data(buildJsonObject { put("id", it.json.getValue("id")); put("connection_id", connectionId); put("item_type", "note"); put("item_id", itemId) }, 201) }
        createShare(vault.context, connectionId, zekke.core.scopes.ScopedItemType.NOTE, itemId, "wrapped")
        assertTrue(vault.verifies(vault.server.sent.last().json, Action.SHARE_CREATE, listOf(connectionId, "note", itemId)))
    }

    @Test
    fun aPairingCodeIsReadAsPeopleTypeIt() {
        assertEquals("K7QM9XP2", normalisePairingCode("k7qm-9xp2"))
        assertEquals("10101000", normalisePairingCode("IOL0 1o0o"))
        assertEquals("K7QM-9XP2", formatPairingCode("K7QM9XP2"))
        assertFailsWith<MalformedPairingCodeException> { normalisePairingCode("K7QM9XP") }
        assertFailsWith<MalformedPairingCodeException> { normalisePairingCode("K7QM9XPU") }
        assertEquals("877 160", displayFingerprint("877160"))
    }

    @Test
    fun reproducesThePairingFingerprintVector() {
        val vector = "pairing_fingerprint"
        val mlkem = primitives.mlKem768.keyPairFromSeed(TestVectors.hex("device_keys", "genesis_device", "mlkem_seed_hex")).publicKey
        val parties = PairingParties(
            code = TestVectors.string("device_keys", vector, "code"),
            userAddress = TestVectors.string("seed_and_user_address", "user_address"),
            rootPublicKey = TestVectors.string("identity_key_p256", "public_key_spki_base64"),
            deviceId = TestVectors.string("device_keys", "genesis_device", "device_id"),
            signingPublicKey = TestVectors.string("device_keys", "genesis_device", "signing_public_key_spki"),
            x25519PublicKey = TestVectors.string("device_keys", "genesis_device", "x25519_public_key"),
            mlkemPublicKey = bytesToBase64(mlkem),
        )
        val input = listOf("Cryple-Pairing-v1", parties.code, parties.userAddress, parties.rootPublicKey, parties.deviceId,
            parties.signingPublicKey, parties.x25519PublicKey, parties.mlkemPublicKey).joinToString("|")
        assertEquals(TestVectors.string("device_keys", vector, "input_sha256"), bytesToHex(primitives.sha2.sha256(utf8ToBytes(input))))
        assertEquals(TestVectors.string("device_keys", vector, "fingerprint"), pairingFingerprint(parties, primitives))
    }

    @Test
    fun notificationsKeepUnknownKindsAndMarkReadInBatches() = runTest {
        val vault = TestVault()
        val api = vault.server.api
        vault.server.reply(zekke.core.items.Reply(200, buildJsonObject {
            put("data", buildJsonObject {
                putJsonArray("notifications") {
                    addJsonObject { put("id", newItemId(primitives)); put("kind", "a_future_kind"); put("params", JsonArray(emptyList())); put("created_at", "t") }
                    addJsonObject { put("id", newItemId(primitives)); put("kind", "refunded"); put("params", buildJsonObject { put("plan", "premium_1") }); put("created_at", "t"); put("read_at", "t") }
                }
                put("unread_count", 1)
            })
            put("page", buildJsonObject { put("next_cursor", "c2"); put("has_more", true) })
        }.toString()))
        val page = listNotifications(api)
        assertEquals(listOf(false, true), page.notifications.map { it.isKnown })
        assertEquals(0, page.notifications.first().params.size)
        assertEquals("premium_1", page.notifications.last().params.getValue("plan").jsonPrimitive.content)
        assertEquals("c2", page.nextCursor)
        assertEquals(1, page.unreadCount)

        val ids = (1..250).map { newItemId(primitives) }
        vault.server.reply(data(JsonNull), data(JsonNull))
        markNotificationsRead(api, ids + ids.first())
        assertEquals(listOf(200, 50), vault.server.sent.drop(1).map { it.json.getValue("ids").jsonArray.size })
        assertFailsWith<IllegalArgumentException> { markNotificationsRead(api, listOf("NOT")) }
        assertEquals(3, vault.server.sent.size)
    }
}
