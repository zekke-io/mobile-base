# `zekke.core.pqxdh` — hybrid wrapping for a recipient

The only way this library encrypts data for someone else: another account (sharing) or another
device of the same account (its keyrings). Breaking a wrapped blob requires breaking **both**
X25519 and ML-KEM-768. Every constant is frozen; changing one needs a new version byte and the
re-wrapping of every stored blob.

## The construction

```
ephemeral   = a fresh X25519 key pair per payload
ecdhSecret  = X25519(ephemeralPrivate, recipientX25519Public)
kemSecret, kemCiphertext = ML-KEM-768.encapsulate(recipientMlKemPublic)

IKM         = 0xFF×32 ‖ ecdhSecret ‖ kemSecret            (the order is normative)
salt        = 0x00×32
info        = "Cryple-PQXDH-v1|" ‖ usage ‖ "|" ‖ senderUserAddress ‖ "|" ‖ recipientUserAddress
sessionKey  = HKDF-SHA256(IKM, salt, info, L = 32)

blob = 0x01 ‖ kemCiphertext(1088) ‖ ephemeralPublic(32) ‖ iv(12) ‖ AES-256-GCM(sessionKey, iv, payload)
```

Base64 on the wire: a 32-byte DEK wraps to 1576 characters.

## API

| Function / type                          | Purpose                                                                    |
| ---------------------------------------- | -------------------------------------------------------------------------- |
| `pqxdhWrap(payload, recipient, context)` | → base64 blob                                                               |
| `pqxdhUnwrap(blob, secrets, context)`    | → payload                                                                   |
| `PqxdhContext(usage, sender, recipient)` | Addresses are the 64-character lowercase hex strings, joined literally      |
| `PqxdhUsage`                             | `ITEM_SHARE` (`item-share`) and `DEVICE_KEYRING` (`device-keyring`) only    |
| `RecipientSecrets(x25519, mlkemSecretKey)` | `x25519` is an `X25519Agreement`, so a device whose key is held elsewhere never hands it over; `rawX25519Agreement` wraps a key held in memory |
| `deriveSessionKey`, `buildInfo`, `parseBlob`, `deviceRecipientSlot` | The pieces, for tests and for callers that check a blob without opening it |

A usage label is never reused for a new purpose: it is what keeps a session key derived for one
purpose from opening a blob made for another.

## Rejecting rather than guessing

`parseBlob` checks the length and the version byte before anything is decrypted:
`MalformedPqxdhBlobException` for a blob shorter than `1 + 1088 + 32 + 12 + 16` bytes,
`UnsupportedPqxdhVersionException` for any version but `0x01`. A tag that does not verify (a
tampered blob, the wrong keys, the wrong context) throws `PqxdhAuthenticationException`.
`ecdhSecret`, `kemSecret`, the session key and the ephemeral private key are zeroed on every path.

## What it does not do

No forward secrecy against the recipient's long-term keys, on purpose: a wrapped blob must stay
openable for years. Recipient key authenticity comes from elsewhere (the verified chain and
contacts' proof paths), not from this package.

## Tests

`PqxdhTest` rebuilds the recorded `info` string and session key, **unwraps the recorded wire blob**
(encapsulation is randomised, so unwrapping is the cross-client test), checks the parsed layout
against the recorded fields, that the session key changes with the usage, either address or the
IKM order, round-trips both usages with a fresh ephemeral key and IV, and each refusal.
