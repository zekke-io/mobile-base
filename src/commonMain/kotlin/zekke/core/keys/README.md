# `zekke.core.keys` — the frozen key tree

Derives every key a Zekke account has from its BIP39 recovery phrase. **A wrong constant here does
not throw, it produces a different account**, so every path, label and length below is part of the
account's identity and is never changed to fix a mismatch.

## The tree

```
BIP39 mnemonic (12 or 24 words)
  │  PBKDF2-HMAC-SHA512(words joined by " ", "mnemonic", 2048, 64 B)  → seed
  │
  ├─ SHA-256(seed)                                                  → user_address (64-char lowercase hex)
  ├─ SLIP-0010 P-256, m/9027'/0'/0'                                  → the root signing key
  ├─ HKDF-SHA512(seed, salt = ∅, info = "Cryple-Key-v1|x25519",    L = 32) → X25519 (derived, not published)
  ├─ HKDF-SHA512(seed, salt = ∅, info = "Cryple-Key-v1|mlkem768",  L = 64) → ML-KEM-768 (derived, not published)
  └─ HKDF-SHA512(seed, salt = ∅, info = "Cryple-Key-v1|vault-kek", L = 32) → the root wrap key
```

The labels keep the product's former name on purpose: they are inputs to every derivation.

The seed is a cold root. It is typed to sign up, to add a device and for account-level actions,
then zeroed; it is never stored. `deriveRootKeys` / `deriveRootKeysFromMnemonic` return exactly
what a root flow needs (`userAddress`, `signing`, `wrapKey`) and `zeroRootKeys` clears them. The
X25519 and ML-KEM leaves stay derived so the vectors keep checking them.

## API

| Function                                                                         | Purpose                                                     |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `deriveKeyTree(words)` / `deriveKeyTreeFromSeed(seed)`                           | The whole tree; the mnemonic's checksum is validated first   |
| `deriveUserAddress`, `deriveIdentityKey`, `deriveX25519Key`, `deriveMlKem768Key`, `deriveVaultKek` | Single leaves                                |
| `deriveRootKeys(seed)` / `deriveRootKeysFromMnemonic(words)` / `zeroRootKeys`    | The root signing key, the root wrap key and the address      |
| `zeroKeyTree(tree)`                                                              | Zeroes every private buffer; not the public keys or the address |
| `isValidMnemonic`, `assertValidMnemonic`, `mnemonicToSeed`, `generateMnemonic`   | BIP39                                                        |
| `deriveMasterNode`, `deriveHardenedChild`, `deriveHardenedPath`                  | SLIP-0010                                                    |

Every function takes a `Primitives`, defaulting to `platformPrimitives()`.

## The phrase is never a `String`

A mnemonic enters and leaves as `List<CharArray>`, one array per word, so the caller can zero it.
Words are looked up by binary search over the sorted wordlist, comparing characters, so no `String`
copy of a word is made. The PBKDF2 password is built as bytes and zeroed after the derivation.

- **Only 12 or 24 words**, each exactly as it appears in the BIP39 English list (lowercase ASCII).
  Normalising what a person typed is the app's job.
- **No passphrase.** Zekke never sets one, so the salt is always `"mnemonic"`; NFKD normalisation,
  which a passphrase would need and Kotlin's common library lacks, is never required.
- **The wordlist ships inside the library** (`Bip39EnglishWordlist.kt`); a test checks its SHA-256
  against the canonical list's, `2f5eed53…24dbda`.

## The traps this package exists to avoid

- **`user_address` hashes the 64 raw seed bytes**, never the mnemonic and never the seed's hex
  string, which gives a valid-looking address for another account. A test asserts both values.
- **SLIP-0010, not BIP32.** The HMAC key is `"Nist256p1 seed"` and the retry rules use **P-256's**
  order, through `P256Scalar`. Every level is hardened; there is no non-hardened code path.
- **X25519 takes the 32 HKDF bytes as they are**; clamping happens inside the primitive.
- **ML-KEM needs 64 bytes**, because FIPS 203 key generation consumes `(d ‖ z)`. `mlkem768.seed`
  is that HKDF output and `mlkem768.secretKey` the 2400-byte expanded key.
- **An empty HKDF salt means 64 zero bytes**, which the primitive guarantees.

## Tests

`KeyTreeTest` reproduces every value of the key tree from the vectors (seed, `user_address`, the
P-256 private key, chain code and public key in every encoding, both encryption key pairs, the
vault KEK), pins each frozen constant against the fixture, checks the hex-string trap, and that
zeroing clears every private buffer. `MnemonicTest` checks the wordlist, the vector mnemonic's
seed, a wrong checksum, unsupported word counts, unknown and uppercase words, and generated
mnemonics of both lengths.
