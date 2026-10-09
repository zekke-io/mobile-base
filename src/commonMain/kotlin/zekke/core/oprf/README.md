# `zekke.core.oprf` — both PINs over the OPRF

The client half of the PIN protocol: RFC 9497 base mode, suite `ristretto255-SHA512`, on the
`Ristretto255` primitive, and the keys a PIN derives. **Every PIN guess passes the server**: the
PIN alone derives nothing without the server's evaluation, and the server rations evaluations.

## The OPRF — `Oprf.kt`

| Function                                   | RFC 9497 / RFC 9380                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------- |
| `expandMessageXmd(message, dst, length)`   | RFC 9380 § 5.3.1 with SHA-512                                                                |
| `hashToGroup(input)`                       | `HashToGroup`: the 64 expanded bytes through ristretto255's one-way map, DST `HashToGroup-OPRFV1-\0-ristretto255-SHA512` |
| `hashToScalar(input, dst)`                 | `HashToScalar`: the 64 expanded bytes reduced modulo the group order                         |
| `blindPin(pin)`                            | `Blind` with a fresh random scalar → `BlindedPin` (input, blind, base64 blinded element)     |
| `blindPinWithScalar` / `blindInputWithScalar` | `Blind` with a given scalar, for the fixed-blind vectors                                  |
| `finalizePin(blinded, evaluatedElement)`   | `Finalize`: unblind with the inverted scalar, then SHA-512 over the length-prefixed input, the unblinded element and `"Finalize"` → 64 bytes |

`finalizePin` refuses anything that is not a valid 32-byte ristretto255 encoding, and an
unblinding that lands on the identity, with `MalformedElementException`. It zeroes the blind and the
input whether it succeeds or not, so a `BlindedPin` is used once.

The server's side (`DeriveKeyPair`, `BlindEvaluate`) is not in the library: the tests carry a
`DeriveKeyPair` of their own to reproduce the recorded server keys, and evaluate with
`Ristretto255.scalarMult`.

## The PIN keys — `PinKeys.kt`

```
output   = finalizePin(…)                                              64 bytes
argon    = Argon2id(PIN, salt, m = 65536 KiB, t = 3, p = 1, L = 32)
ikm      = output ‖ argon
leaf(l)  = HKDF-SHA256(ikm, salt = ∅, info = "Cryple-PIN-v1|" ‖ l, L = 32)
```

| Leaf             | Salt                                      | Is                                                                                       |
| ---------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| `device-wrap`    | 32 random bytes kept in the device record | The AES key sealing the device's material                                                |
| `device-confirm` | the same                                  | An Ed25519 seed signing `Cryple-PIN-v1\|device-confirm\|<registration_id>\|<attempt_id>` |
| `account-proof`  | `utf8(user_address)`, 64 bytes            | An Ed25519 seed signing the SHA-256 digest a root action's signature covers              |

| Function                                                  | Purpose                                                          |
| --------------------------------------------------------- | ---------------------------------------------------------------- |
| `deriveDevicePinKeys(output, pin, salt)` / `zeroDevicePinKeys` | `wrapKey`, `confirmSeed`, `confirmPublicKey`                 |
| `signDeviceConfirmation(seed, registrationId, attemptId)` | The confirmation signature, base64                                |
| `deriveAccountProofKey(output, pin, userAddress)` / `zeroAccountProofKey` | `seed`, `publicKey`                               |
| `proofSigner(key)`                                        | A `PinProofSigner` for `signRootAction`                           |
| `stretchPin`, `pinIkm`, `pinLeaf`, `generateDeviceSalt`   | The pieces                                                        |

Both derivations **consume the OPRF output**: it is zeroed with the Argon2id output and the IKM.
The Argon2id parameters are `ARGON2ID_PARAMETERS` and are never lowered: the output would no longer
match what the server registered.

The PIN is a `CharArray` of ASCII digits; its bytes are built for each use and zeroed. The blind,
the PIN input, the OPRF output, the Argon2id output, the IKM and every leaf are
[`SecretBytes`](../memory/README.md).

## Not here

The HTTP routes (register, commit, evaluate, confirm, the account PIN's evaluate, begin, enable and
rotate) and their typed outcomes (`WrongPin`, `RegistrationGone`, `Offline`, `RateLimited`) need
the API client and are not part of this package yet. No evaluation is ever retried automatically:
each one is an attempt.

## Tests

`OprfTest` checks RFC 9380's SHA-512 `expand_message_xmd` vectors, then **RFC 9497's own
ristretto255-SHA512 base-mode vectors first** (`src/commonTest/fixtures/rfc9497-ristretto255-sha512-oprf.json`,
each value checked against RFC 9497 § A.1.1): the server key from its seed, and each vector's
blinded element, evaluation and output. Then every OPRF value of `pin_oprf`: the test server key,
the test blind, the blinded PIN, the evaluation and the output. It also checks a fresh blind per
call and the refusal of malformed elements. `PinKeysTest` reproduces both Argon2id outputs, the
IKM, every leaf, **both Ed25519 signatures byte for byte** (the device confirmation and the PIN
proof), and that the leaves are domain-separated.
