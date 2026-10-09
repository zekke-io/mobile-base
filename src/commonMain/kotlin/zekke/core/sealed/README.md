# `zekke.core.sealed` — the sealed-blob envelope

The one AES-256-GCM envelope used wherever this library encrypts something **under a key it already
holds**. Encrypting for someone else is [`pqxdh`](../pqxdh/README.md).

```
sealed(key, plaintext) = 0x01 ‖ iv(12) ‖ AES-256-GCM(key, iv, plaintext) ‖ tag(16)
                         base64( … ) for anything that goes in a TEXT column
```

| Function                    | Form                                                       |
| --------------------------- | ---------------------------------------------------------- |
| `sealBytes` / `openBytes`   | The envelope as raw bytes (drive chunks)                    |
| `sealBlob` / `openBlob`     | The same, base64, for text columns                          |
| `sealText` / `openText`     | UTF-8 on top of the base64 form; intermediate bytes zeroed  |

**A fresh random IV on every seal.** `sealBytesWithIv` takes a caller-chosen IV and is `internal`:
only the drive's derived chunk IVs and the tests may use it.

**No AAD.** Each key is single-purpose, so there is no context to bind.

## Rejecting rather than guessing

`openBytes` checks the length before anything else, then the version byte, then decrypts:

| Failure                                          | Exception                            |
| ------------------------------------------------ | ------------------------------------ |
| Shorter than 1 + 12 + 16 bytes, or a bad IV size | `MalformedSealedBlobException`       |
| A version byte other than `0x01`                 | `UnsupportedSealedVersionException`  |
| The tag does not verify under this key           | `SealedBlobAuthenticationException`  |

The version byte is what makes a future change detectable instead of a silent misparse.

## Tests

`SealedTest` reproduces the `sealed_blob` vector in both forms and the root keyring wrap of the
device-keys vectors, checks a fresh IV per seal, and each of the three refusals, plus a text round
trip.
