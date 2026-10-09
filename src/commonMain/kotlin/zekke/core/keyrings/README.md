# `zekke.core.keyrings` — scope KEKs, wraps and batches

Every keyring scope has generations; each generation is a random 32-byte KEK, wrapped to the root
and to every active device holding the scope. Item DEKs are sealed under the current KEK of their
scope.

## `KeyringCrypto.kt`

| Function                                          | What                                                                                          |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `generateScopeKek`                                | A fresh KEK, as a `SecretBytes`                                                               |
| `wrapKekForRoot` / `openRootWrap`                 | `sealed(root_wrap_key, KEK)`; the root wrap key is the seed's `Cryple-Key-v1\|vault-kek` leaf  |
| `wrapKekForDevice` / `openDeviceWrap`             | PQXDH, usage `device-keyring`, recipient slot `user_address/device_id`, so a wrap for one device never opens for another |
| `generateSharingKeys`, `seal/openSharingMaterial` | A `sharing` generation's X25519 and ML-KEM keys, sealed as `x25519_private(32) ‖ mlkem_seed(64)` under that generation's KEK |
| `deriveShareSubkey`                               | `HKDF-SHA256(connection_key, "Cryple-Share-v1\|<scope>")`                                      |

Every KEK, private key and sub-key is a `SecretBytes`; a value that opens to anything but 32 bytes
is refused with `KeyringException`.

## `Batches.kt`

Each builder signs its events, runs the whole batch through `ChainState.applyBatch`, then wraps
every generation it creates **to the root and to exactly the active devices holding that scope**,
computed from the verified chain, and seals the sharing material. If anything fails, the KEKs it
created are zeroed.

| Builder              | Signed by   | Used for                                                                                       |
| -------------------- | ----------- | ---------------------------------------------------------------------------------------------- |
| `buildGenesis`       | root        | Sign-up: `device-add` (every scope), `sharing-keys` 1, every keyring to 1                       |
| `buildEnrolment`     | root        | Adding a full device with the phrase, optionally removing devices and rotating what they held  |
| `buildDeviceRemoval` | this device | Removing other devices, rotating every keyring they held, new sharing keys if they held `sharing` |
| `buildRotation`      | this device | Rotating named scopes                                                                          |
| `buildSelfRemoval`   | this device | Leaving: a self `device-remove`, which needs no rotation                                        |
| `buildDeviceLink`    | this device | Linking a **limited** device (the extension, a browser): one `device-add` and a wrap of every generation of each scope it is granted |

**Only the phrase makes a full device.** `buildDeviceLink` refuses a scope list containing `admin`
(`GrantsAdminException`) on every account, and a KEK of a scope it does not grant. A full device
joins through `buildEnrolment`, signed by the root, with the account PIN's proof on a Paranoid
account.

**Every rotation needs the root wrap key**, because each new generation is also wrapped to the
root, so the phrase alone can always reopen the keyring. The caller supplies it as a
`RootWrapper`, which holds the root wrap key only for that batch.

## `KeyringsApi.kt` — over HTTP

| Function                                   | Route / purpose                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------------------- |
| `fetchKeyrings`, `loadKeyrings`            | `GET /keyrings`, and every wrap opened with this device's secrets                  |
| `openDeviceKeyrings`, `openRootKeyrings`   | Open a keyrings record with the device's keys or the root wrap key. A missing wrap of a held scope is `MissingGenerationException`, a bug to report |
| `refreshKeyrings`                          | Fetches and adds only the generations the session does not hold yet               |
| `postOwnWraps`                             | `POST /keyrings/wraps`: a new device wrapping existing generations to itself       |
| `fetchChain`, `listDevices`                | `GET /devices/chain`, `GET /devices`                                              |
| `applyDeviceBatch`                         | `POST /devices/batch`                                                             |
| `withCurrentGeneration`                    | Runs a write and, on `409 STALE_KEY_GENERATION`, refreshes the keyrings and runs it **once** more |

The wire forms (`ChainEventWire`, `DeviceBatchWire`, `KeyringsRecord`, …) are converted to and
from the chain's and the builders' types here and nowhere else.

## Tests

`KeyringCryptoTest`: the vector root wrap, the vector `device-keyring` info string, a wrap that
opens for its device only, the sharing material round trip and the genesis sharing keys from the
vector material, every vector share sub-key. The builders are tested with the chain, in
`BatchesTest`.
