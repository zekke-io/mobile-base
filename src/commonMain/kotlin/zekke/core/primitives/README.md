# `zekke.core.primitives`

The first layer of `mobile-base`: every cryptographic primitive the protocol uses, each behind one interface, so a provider can be
replaced without touching the protocol. **Nothing here is hand-rolled** except the 256-bit addition
modulo P-256's order, which lives in `commonMain` so both platforms run the same code.

`platformPrimitives()` returns the one `Primitives` instance the platform provides. Everything above
this package receives a `Primitives` rather than reaching for a provider, so a test can hand in
another implementation.

## The table

| Interface           | What it does                                                        | Provider on Android and the JVM                  | Provider on iOS                      |
| ------------------- | ------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------ |
| `Sha2`              | SHA-256, SHA-512                                                    | JCA through `cryptography-kotlin`                | CryptoKit through `cryptography-kotlin` |
| `HmacSha512`        | HMAC-SHA512 (SLIP-0010)                                             | JCA                                              | CryptoKit                            |
| `Pbkdf2HmacSha512`  | PBKDF2-HMAC-SHA512 (the BIP39 seed)                                 | JCA                                              | CommonCrypto (CryptoKit has none)    |
| `Hkdf`              | HKDF-SHA512 and HKDF-SHA256                                         | `cryptography-kotlin` over JCA's HMAC            | CryptoKit                            |
| `AesGcm`            | AES-256-GCM with a caller-chosen 12-byte IV and a 16-byte tag       | JCA                                              | CryptoKit                            |
| `EcdsaP256`         | Public point from a raw scalar; sign and verify in IEEE P1363 form  | JCA, plus Bouncy Castle for the public point     | CryptoKit                            |
| `P256Scalar`        | `isValidPrivateKey`, `addModOrder` (SLIP-0010's retry rules)        | `commonMain`, fixed-width limbs                  | the same code                        |
| `X25519`            | Public key, shared secret                                           | libsodium                                        | libsodium                            |
| `MlKem768`          | Key pair from the 64-byte `(d ‖ z)` seed, encapsulate, decapsulate  | mlkem-native                                     | mlkem-native                         |
| `Ed25519`           | Deterministic RFC 8032 signatures from a 32-byte seed               | libsodium                                        | libsodium                            |
| `Ristretto255`      | Point validation, the one-way map, scalar multiplication, inversion, reduction, random scalars | libsodium                     | libsodium                            |
| `Argon2id`          | Argon2id with any salt length                                       | libsodium's Argon2 core                          | libsodium's Argon2 core              |
| `SecureRandom`      | The CSPRNG                                                          | libsodium (`randombytes_buf`)                    | libsodium                            |

The four libsodium/mlkem-native rows reach C through one surface, `native/src/zekke_native.h`: JNI
on Android and the JVM (`ZekkeNativeJni`, in the shared `jniMain` source set), `cinterop` on iOS
(`ZekkeNativeCinterop`). Both platforms therefore run **the same C code** for the primitives that are
hardest to get identical. How that code is built is in the [module README](../../../../../../README.md#the-native-libraries).

## Behaviour every caller relies on

- **An empty HKDF salt means `HashLen` zero bytes**, as RFC 5869 says and every key-tree leaf
  needs. `Hkdf` passes an empty salt to the provider as "no salt", because JCA refuses an empty
  HMAC key. A test checks that an empty salt and 64 zero bytes give the same leaf.
- **`AesGcm.decrypt` returns `null` when the tag does not verify.** It never throws for a wrong
  key or a tampered ciphertext; it throws `IllegalArgumentException` for a key, IV or ciphertext
  of the wrong length, which is a programming error.
- **`EcdsaP256.verify` accepts high-S signatures.** The genesis chain contains two, and the
  server's verifier accepts them; a low-S-only verifier would reject a valid account. It returns
  `false` for a malformed key or signature instead of throwing.
- **`EcdsaP256.sign` hashes once with SHA-256.** Callers pass the message, never a digest.
- **X25519 takes the 32 HKDF bytes as they are** and clamps inside libsodium.
- **`Ristretto255.scalarMult` and `scalarMultBase` throw when the result is the identity**, which
  RFC 9497 requires a client to reject.
- **Argon2id is not reached through `crypto_pwhash`.** libsodium's public API fixes the salt at
  16 bytes, and the PIN vectors use a 32-byte device salt and the 64-character user address. The
  C surface calls `argon2id_hash_raw`, the Argon2 core that `crypto_pwhash` itself wraps, compiled
  from the same pinned libsodium sources. The parameters are never lowered here.
- **Failures inside a provider throw `PrimitiveFailureException`**, naming the operation and
  nothing else: no key, no input, no length.

## Tests

`src/commonTest/kotlin/zekke/core/primitives`, run on every target. Each test names the vector it
reproduces:

| Row            | Reproduced                                                                                           |
| -------------- | ---------------------------------------------------------------------------------------------------- |
| SHA-2, HMAC    | `user_address`, the signed-action digest, FIPS 180 `"abc"`, RFC 4231 test case 2                       |
| PBKDF2         | The BIP39 seed of the all-`abandon` mnemonic                                                          |
| HKDF           | The `x25519`, `mlkem768` and `vault-kek` leaves; the PIN's `device-wrap` leaf; the PQXDH session key   |
| AES-GCM        | `sealed_blob` with its fixed IV; the PQXDH wrap example; a tampered tag                               |
| ECDSA P-256    | The identity public point from its scalar; the three genesis chain signatures (two high-S); a round trip |
| P-256 scalar   | Validity at 0, 1, n − 1, n; additions checked against Python, including a wrap past n                 |
| X25519         | The `x25519_key` leaf (clamping), both genesis devices' keys, the PQXDH ECDH secret from both sides     |
| ML-KEM-768     | `mlkem768_key` from its seed; both genesis seeds by hash; decapsulating the PQXDH ciphertext; a round trip |
| Ed25519        | `device-confirm` and `pin_proof` byte for byte                                                         |
| ristretto255   | RFC 9496 A.1, A.2 (all 29 invalid encodings) and A.3; the test server key evaluating the blinded PIN; inversion |
| Argon2id       | `pin_oprf` device output (32-byte salt) and account output (user address salt)                         |
| CSPRNG         | Sizes; two draws differ                                                                               |

The vectors come from `src/commonTest/fixtures/test-vectors.json`, a byte-for-byte copy of
the canonical Zekke vector file (see the [module README](../../../../../../README.md#the-vector-fixture)). The RFC 9496 values were extracted from the RFC's
text by script, not typed.
