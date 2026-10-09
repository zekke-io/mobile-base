# `zekke.core.device` — this phone's own keys

A phone is a device: it generates keys of its own when the account is created or the phone is
added with the phrase, and it never stores the phrase or the seed.

## `DeviceKeys.kt`

| Key               | Size | Use                                                      |
| ----------------- | ---- | -------------------------------------------------------- |
| P-256 signing key | 32   | Sign-in, device actions, chain statements                |
| X25519 key        | 32   | Opening keyring wraps (PQXDH)                            |
| ML-KEM-768 seed   | 64   | Opening keyring wraps (PQXDH); the 2400-byte key is rebuilt from it |

**All three are private keys held as `SecretBytes`, and all three are sealed.** Unlike a browser,
whose signing key is a non-extractable platform key outside the seal, a phone signs nothing until
its PIN has passed the server.

`generateDeviceKeys` draws them (the signing key retried until it is a valid P-256 scalar) with a
random version-4 device id; `deviceKeysFromMaterial` rebuilds them and their public keys from the
raw material. `deviceDeclaration` is what a `device-add` names; `deviceSigner`,
`deviceX25519Agreement` and `deviceSecrets` give `signing`, `pqxdh` and `keyrings` what they need.

## `DeviceRecord.kt` — the record

```
{ device_id, registration_id, salt, sealed,
  user_address, root_public_key, scopes,
  signing_public_key, x25519_public_key, mlkem_public_key }
```

- `sealed` is the sealed-blob envelope of `signing(32) ‖ x25519(32) ‖ mlkem_seed(64)` under the
  PIN's `device-wrap` key (`oprf`). This layout is the phone's own; no other client reads it.
- `salt` is the device's Argon2id salt, which never leaves the phone.
- `root_public_key` is kept so the chain can be verified from the root at every unlock.
- **No seed, no phrase, no root key and no private key is ever in it in the clear**; a test
  checks the encoded record.
- `openDeviceRecord` throws `WrongDevicePinException` when the seal does not open, and refuses the
  record (`DeviceMaterialException`) when the opened material does not rebuild every public key it
  lists.

`encodeDeviceRecord` / `decodeDeviceRecord` turn it into JSON bytes and back, refusing anything
but exactly its ten string fields.

## Where it lives — `DeviceVault`

```kotlin
interface DeviceVault { fun store(record: ByteArray); fun load(): ByteArray?; fun delete() }
```

Each app implements it: it encrypts the encoded record once more under a non-extractable hardware
key (the Android Keystore, the Secure Enclave), keeps it out of every backup, and stores it.
`MemoryDeviceVault` is the same interface in memory, for tests. `saveDeviceRecord` and
`loadDeviceRecord` encode and decode around it.

## Tests

`DeviceTest`: the vector genesis device's public keys from its material; a generated device's id
and signature; the record sealing every private key and opening under the vector PIN key; no
private key, seed or phrase in the stored record; a wrong PIN; a record whose public keys do not
match its material; the vault round trip; malformed stored records.
