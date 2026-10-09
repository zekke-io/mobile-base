package zekke.core.device

import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.memory.adoptAsSecret
import zekke.core.oprf.deriveDevicePinKeys
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import zekke.core.scopes.FULL_DEVICE_SCOPES
import zekke.core.signing.buildAuthPayload
import zekke.core.signing.signPayload
import zekke.core.signing.verifyPayload
import zekke.core.encoding.spkiBase64ToUncompressedPoint
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceTest {
    private val identity = DeviceIdentity(
        TestVectors.string("seed_and_user_address", "user_address"),
        TestVectors.string("device_keys", "root_wrap", "root_public_key"),
        FULL_DEVICE_SCOPES,
    )

    private fun genesisDevice(): DeviceKeys = deviceKeysFromMaterial(
        TestVectors.string("device_keys", "genesis_device", "device_id"),
        TestVectors.secret("device_keys", "genesis_device", "signing_private_key_hex"),
        TestVectors.secret("device_keys", "genesis_device", "x25519_private_key_hex"),
        TestVectors.secret("device_keys", "genesis_device", "mlkem_seed_hex"),
        primitives,
    )

    private fun wrapKey() = deriveDevicePinKeys(
        TestVectors.secret("pin_oprf", "evaluation", "oprf_output_hex"),
        TestVectors.string("pin_oprf", "pin").toCharArray(),
        TestVectors.hex("pin_oprf", "argon2id", "device_salt_hex"),
        primitives,
    ).wrapKey

    @Test
    fun reproducesTheGenesisDevicePublicKeys() {
        val keys = genesisDevice()
        assertEquals(TestVectors.string("device_keys", "genesis_device", "signing_public_key_spki"), keys.signingPublicKey)
        assertEquals(TestVectors.string("device_keys", "genesis_device", "x25519_public_key"), bytesToBase64(keys.x25519PublicKey))
        assertEquals(TestVectors.string("device_keys", "genesis_device", "mlkem_public_key_sha256"), bytesToHex(primitives.sha2.sha256(keys.mlkemPublicKey)))
    }

    @Test
    fun aGeneratedDeviceHasACanonicalIdAndSignsWithItsDeclaredKey() {
        val keys = generateDeviceKeys(primitives = primitives)
        assertTrue(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").matches(keys.deviceId))
        val payload = buildAuthPayload("c".repeat(64), 1L)
        val signature = signPayload(payload, deviceSigner(keys, primitives))
        assertTrue(verifyPayload(payload, signature, spkiBase64ToUncompressedPoint(deviceDeclaration(keys, FULL_DEVICE_SCOPES).signingPublicKey), primitives))
    }

    @Test
    fun theRecordSealsEveryPrivateKeyAndOpensUnderThePin() {
        val keys = genesisDevice()
        val record = sealDeviceRecord(keys, identity, "00000000-0000-4000-8000-0000000000aa", TestVectors.hex("pin_oprf", "argon2id", "device_salt_hex"), wrapKey(), primitives)
        val opened = openDeviceRecord(record, wrapKey(), primitives)
        assertEquals(TestVectors.string("device_keys", "genesis_device", "signing_private_key_hex"), opened.signingPrivateKey.withBytes { bytesToHex(it) })
        assertEquals(TestVectors.string("device_keys", "genesis_device", "x25519_private_key_hex"), opened.x25519PrivateKey.withBytes { bytesToHex(it) })
        assertEquals(TestVectors.string("device_keys", "genesis_device", "mlkem_seed_hex"), opened.mlkemSeed.withBytes { bytesToHex(it) })
        assertEquals(identity.scopes, recordIdentity(record).scopes)
    }

    @Test
    fun noPrivateKeyAndNoSeedAppearInTheStoredRecord() {
        val keys = genesisDevice()
        val record = sealDeviceRecord(keys, identity, "r", ByteArray(32), wrapKey(), primitives)
        val stored = encodeDeviceRecord(record).decodeToString()
        val privateKeys = listOf(
            TestVectors.hex("device_keys", "genesis_device", "signing_private_key_hex"),
            TestVectors.hex("device_keys", "genesis_device", "x25519_private_key_hex"),
            TestVectors.hex("device_keys", "genesis_device", "mlkem_seed_hex"),
            TestVectors.hex("seed_and_user_address", "seed_hex"),
        )
        for (key in privateKeys) {
            assertTrue(bytesToHex(key) !in stored && bytesToBase64(key) !in stored)
        }
        assertTrue(TestVectors.string("seed_and_user_address", "mnemonic") !in stored)
    }

    @Test
    fun aWrongPinDoesNotOpenTheRecord() {
        val record = sealDeviceRecord(genesisDevice(), identity, "r", ByteArray(32), wrapKey(), primitives)
        assertFailsWith<WrongDevicePinException> { openDeviceRecord(record, ByteArray(32).adoptAsSecret(), primitives) }
    }

    @Test
    fun aRecordWhosePublicKeysDoNotMatchItsMaterialIsRefused() {
        val record = sealDeviceRecord(genesisDevice(), identity, "r", ByteArray(32), wrapKey(), primitives)
        val other = generateDeviceKeys(primitives = primitives)
        val swapped = DeviceRecord(
            record.deviceId, record.registrationId, record.salt, record.sealed, record.userAddress, record.rootPublicKey,
            record.scopes, other.signingPublicKey, record.x25519PublicKey, record.mlkemPublicKey,
        )
        assertFailsWith<DeviceMaterialException> { openDeviceRecord(swapped, wrapKey(), primitives) }
    }

    @Test
    fun theVaultStoresTheEncodedRecordAndDecodesItBack() {
        val vault = MemoryDeviceVault()
        assertNull(loadDeviceRecord(vault))
        val record = sealDeviceRecord(genesisDevice(), identity, "r", ByteArray(32), wrapKey(), primitives)
        saveDeviceRecord(vault, record)
        val loaded = assertNotNull(loadDeviceRecord(vault))
        assertEquals(record.sealed, loaded.sealed)
        assertEquals(record.scopes, loaded.scopes)
        vault.delete()
        assertNull(loadDeviceRecord(vault))
    }

    @Test
    fun aMalformedStoredRecordIsRefused() {
        for (bytes in listOf("not json", "{}", "{\"device_id\":1}").map { it.encodeToByteArray() }) {
            assertFailsWith<DeviceRecordFormatException> { decodeDeviceRecord(bytes) }
        }
    }
}
