package zekke.core.keyrings

import zekke.core.device.deviceSecrets
import zekke.core.device.generateDeviceKeys
import zekke.core.encoding.base64ToBytes
import zekke.core.encoding.bytesToBase64
import zekke.core.encoding.bytesToHex
import zekke.core.pqxdh.PqxdhAuthenticationException
import zekke.core.pqxdh.buildInfo
import zekke.core.primitives.TestVectors
import zekke.core.primitives.primitives
import zekke.core.primitives.toHex
import zekke.core.scopes.Scope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KeyringCryptoTest {
    private val userAddress = TestVectors.string("seed_and_user_address", "user_address")

    @Test
    fun reproducesTheRootWrapOfTheFixedScopeKek() {
        val wrapKey = TestVectors.secret("vault_kek", "vault_kek_hex")
        val wrapped = wrapKekForRootWithIv(wrapKey, TestVectors.secret("device_keys", "root_wrap", "scope_kek_hex"), TestVectors.hex("device_keys", "root_wrap", "iv_hex"), primitives)
        assertEquals(TestVectors.string("device_keys", "root_wrap", "wrapped_base64"), wrapped)
        assertEquals(TestVectors.string("device_keys", "root_wrap", "scope_kek_hex"), openRootWrap(wrapKey, wrapped, primitives).toHex())
    }

    @Test
    fun buildsTheVectorDeviceKeyringInfoString() {
        val context = deviceKeyringContext(userAddress, TestVectors.string("device_keys", "genesis_device", "device_id"))
        assertEquals(TestVectors.string("device_keys", "device_keyring_pqxdh", "info"), buildInfo(context))
    }

    @Test
    fun aDeviceWrapOpensForItsDeviceAndForNoOtherDeviceOfTheAccount() {
        val mine = generateDeviceKeys(primitives = primitives)
        val other = generateDeviceKeys(primitives = primitives)
        val kek = generateScopeKek(primitives)
        val wrapped = wrapKekForDevice(kek, userAddress, DeviceRecipient(mine.deviceId, bytesToBase64(mine.x25519PublicKey), bytesToBase64(mine.mlkemPublicKey)), primitives)
        assertEquals(kek.toHex(), openDeviceWrap(wrapped, userAddress, deviceSecrets(mine, primitives), primitives).toHex())
        assertFailsWith<PqxdhAuthenticationException> { openDeviceWrap(wrapped, userAddress, deviceSecrets(other, primitives), primitives) }
        val impersonated = DeviceSecrets(other.deviceId, deviceSecrets(mine, primitives).x25519, mine.mlkemSecretKey)
        assertFailsWith<PqxdhAuthenticationException> { openDeviceWrap(wrapped, userAddress, impersonated, primitives) }
    }

    @Test
    fun theSharingMaterialRoundTripsAndRebuildsTheSamePublicKeys() {
        val keys = generateSharingKeys(primitives)
        val kek = generateScopeKek(primitives)
        val opened = openSharingMaterial(kek, sealSharingMaterial(kek, keys, primitives), primitives)
        assertEquals(bytesToHex(keys.x25519PublicKey), bytesToHex(opened.x25519PublicKey))
        assertEquals(bytesToHex(keys.mlkemPublicKey), bytesToHex(opened.mlkemPublicKey))
    }

    @Test
    fun rebuildsTheGenesisSharingPublicKeysFromTheVectorMaterial() {
        val keys = sharingKeysFromMaterial(
            TestVectors.secret("device_keys", "genesis_sharing_keys", "x25519_private_key_hex"),
            TestVectors.secret("device_keys", "genesis_sharing_keys", "mlkem_seed_hex"),
            primitives,
        )
        assertEquals(TestVectors.string("device_keys", "genesis_sharing_keys", "x25519_public_key"), bytesToBase64(keys.x25519PublicKey))
        assertEquals(TestVectors.string("device_keys", "genesis_sharing_keys", "mlkem_public_key_sha256"), bytesToHex(primitives.sha2.sha256(keys.mlkemPublicKey)))
    }

    @Test
    fun reproducesTheShareSubkeyOfEveryItemScope() {
        val connectionKey = TestVectors.secret("device_keys", "share_subkeys", "connection_key_hex")
        for (scope in listOf(Scope.SECRETS, Scope.NOTES, Scope.DOCUMENTS, Scope.FILES)) {
            assertEquals(TestVectors.string("device_keys", "share_subkeys", scope.wire), deriveShareSubkey(connectionKey, scope, primitives).toHex(), scope.wire)
        }
    }

    @Test
    fun aWrappedValueThatIsNotAKekIsRefused() {
        val wrapKey = TestVectors.secret("vault_kek", "vault_kek_hex")
        val notAKek = zekke.core.sealed.sealBlob(ByteArray(16), wrapKey, primitives)
        assertFailsWith<KeyringException> { openRootWrap(wrapKey, notAKek, primitives) }
        assertEquals(16 + 29, base64ToBytes(notAKek).size)
    }
}
