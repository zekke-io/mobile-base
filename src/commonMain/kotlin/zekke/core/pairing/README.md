# `zekke.core.pairing` — linking the password extension from the phone

The phone links the Zekke browser extension with a temporary code, as a **limited device** holding
the `passwords` scope and nothing else. The same protocol as the web app's linking.

## Linking

1. `openPairing` gives a code the app shows for five minutes.
2. `getPairing` until it is `claimed`; `claimedDevice` checks the three public keys the extension
   sent.
3. `ownerFingerprint` computes six digits from **this account's** address and root key and the
   claimed keys. The person compares them with the extension's.
4. On a match, `linkClaimedDevice` reads and verifies this account's chain, builds a `device-add`
   granting `passwords` and wrapping **every** `passwords` generation held, applies it, and
   completes the pairing. No rotation, so no recovery phrase.
5. On a mismatch the app cancels (`cancelPairing`) and says why. The same code is never retried.

**A device never links a full device**: `buildDeviceLink` refuses `admin` (see `keyrings`), and only
the phrase makes a full device.

## The fingerprint

`SHA-256("Cryple-Pairing-v1|" + code + "|" + user_address + "|" + root_public_key + "|" + device_id +
"|" + signing_public_key + "|" + x25519_public_key + "|" + mlkem_public_key)`, the first four bytes
big-endian modulo 10⁶, six digits (`displayFingerprint` shows them as `877 160`).

## Codes as people type them

`normalisePairingCode` upper-cases, drops dashes and spaces, reads `I` and `L` as `1` and `O` as
`0`, and refuses anything outside Crockford base32 or not 8 characters long. `formatPairingCode`
writes `XXXX-XXXX`.

`claimPairing` and `claimStatus` are the extension's half, here because the interop suite plays the
extension.

## Tests

`SharingTest` reproduces `device_keys.pairing_fingerprint` from `test-vectors.json` and checks code
reading. The interop suite links a device from the core as the extension would claim it, then signs
in as that device, opens the passwords the phone wrote, and is refused the vault.
