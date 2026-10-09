# `zekke.core.encoding`

Byte-level conversions every other package uses. Nothing here derives a key; it only changes how
bytes another package produced are represented.

## Why one package

The same P-256 public key travels in three encodings, and mixing them up fails silently:

| Encoding                      | Where it is used                              | Size         |
| ----------------------------- | --------------------------------------------- | ------------ |
| SPKI DER, base64              | `public_key` on the wire, **always 124 chars** | 91 bytes     |
| Raw `(X, Y)`                  | The on-chain signer pair                       | 2 × 32 bytes |
| Uncompressed point `0x04‖X‖Y` | Between the two, and what `EcdsaP256` takes    | 65 bytes     |

Every conversion goes through here, so no call site sends a point where an SPKI is expected.

## API

| Function                                                         | Behaviour                                                                                          |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `bytesToHex` / `hexToBytes`                                      | Hex out is **lowercase**: user addresses, event hashes and signed arguments are lowercase. Hex in accepts either case and rejects odd lengths and non-hex characters |
| `bytesToBase64` / `base64ToBytes` / `base64UrlToBytes`           | Standard base64 with padding; the URL-safe decoder accepts missing padding                         |
| `utf8ToBytes` / `bytesToUtf8`                                    | `bytesToUtf8` rejects invalid UTF-8 instead of substituting characters                             |
| `uncompressedPointToSpkiDer` / `spkiDerToUncompressedPoint`      | The SPKI header is a fixed 26-byte prefix; encoding is a concatenation, decoding a length and prefix check. Anything but a 91-byte uncompressed P-256 SPKI is rejected |
| `uncompressedPointToSpkiBase64` / `spkiBase64ToUncompressedPoint` | The same, base64                                                                                   |
| `uncompressedPointToXY` / `xyToUncompressedPoint`                | The on-chain coordinates                                                                           |
| `concatBytes`, `bytesEqual`, `zeroBytes`                         | `bytesEqual` has no early exit on content; `zeroBytes` ignores `null`, so cleanup paths need no checks |

Malformed input throws `IllegalArgumentException`.

## Tests

`EncodingTest`: hex case and rejection, the identity key's SPKI and on-chain coordinates from the
vectors, rejection of a wrong SPKI header, length and leading byte, the wire lengths of both
encryption public keys, and the byte helpers.
