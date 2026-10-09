# `zekke.core.memory` — keys in memory

Every key this library holds is a `SecretBytes`, and `SecretRegistry.zeroAll()` zeroes all of them
at once. That call is what a lock runs: **after it, no key any layer derived, opened or unwrapped
is usable**, and any attempt to use one throws instead of working on zeros.

## `SecretBytes`

A byte array the library owns, with three guarantees a plain `ByteArray` cannot give:

| Guarantee                        | How                                                                                                       |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **A zeroed key cannot be used**  | `withBytes { }` throws `SecretZeroedException` once the secret is zeroed. A zero key never seals a new item, never signs, never decrypts into a misleading error |
| **Zeroing waits for a use in progress** | Each secret has its own lock. `zero()` waits for a `withBytes` block that is running, then clears the bytes; the block finishes with the real key, and the next one fails |
| **The content is never printed** | `toString()` gives the size only: `SecretBytes(32 bytes)`                                                 |

| Function                         | Purpose                                                                                     |
| -------------------------------- | ------------------------------------------------------------------------------------------- |
| `SecretBytes.adopt(bytes)`, `bytes.adoptAsSecret()` | Takes the array itself, without copying it: the caller must not keep using it |
| `withBytes { bytes -> … }`       | The only access to the bytes, for the duration of the block. Inline: no allocation          |
| `copy()`, `copyOfRange(from, to)`| A new, independently registered secret                                                     |
| `zero()`, `close()`              | Clears the bytes and leaves the registry. `SecretBytes` is `AutoCloseable`, so `secret.use { }` zeroes it when the block ends |
| `zeroSecrets(a, b, …)`           | Zeroes several, ignoring `null`                                                              |

**Nothing may keep the array `withBytes` hands out** beyond the block: a copy kept that way escapes
the lock. Copies go through `copy()` or `adoptAsSecret()`, which register them.

## `SecretRegistry`

Every `SecretBytes` is registered when it is created and removed when it is zeroed, so the registry
holds exactly the keys still alive in the process.

- `zeroAll()` zeroes them, repeating until none is left, so a secret created while it runs is
  caught as well. It returns how many it zeroed.
- `liveCount` is the number still alive; zero after `zeroAll()`.

**The registry holds strong references on purpose.** A secret nobody zeroed stays in memory until
the next lock instead of being collected; collection would not have zeroed it, and the lock would
not have reached it. Short-lived secrets are therefore zeroed as soon as they are used, with
`use { }` or in a `finally`, as every function of this library does, so the registry stays small.

## Where `SecretBytes` stops

**The primitives take and return `ByteArray`.** They are the boundary with JCA, Bouncy Castle,
CryptoKit and the C libraries, which only accept arrays. Every layer above them (`keys`, `sealed`,
`pqxdh`, `signing`, `oprf`) takes and returns `SecretBytes` for any key, and opens it with
`withBytes` only for the call into a primitive.

What it cannot reach:

- **Copies the platform libraries make**: JCA's `SecretKeySpec` clones its key, an ECDSA private
  key becomes an immutable `BigInteger`, and the iOS bridge copies into `NSData`. Only the end of
  the process reclaims those.
- **The garbage collector may have moved an array** before it was zeroed, leaving the old copy in
  memory until reused.
- **The recovery phrase and the PIN** are `CharArray`s the app owns and zeroes; the library only
  reads them.

## Platform lock

`PlatformLock` is a reentrant mutex: `ReentrantLock` on the JVM and Android, `NSRecursiveLock` on
iOS. The registry's lock is never held while a secret's lock is taken, so `zeroAll()` cannot
deadlock against a `withBytes` block that creates a new secret.

## Tests

`SecretBytesTest`: a zeroed secret refuses every use, adopting takes the array, closing zeroes,
the content never prints, zeroing leaves the registry, and **`zeroAll()` leaves no key of any layer
usable**: a key tree, root keys, both PIN key sets, a PQXDH-unwrapped DEK and a re-sealed one, and a
signer, after which signing and sealing throw. `SecretBytesConcurrencyTest` (JVM): zeroing waits
for a use in progress, which finishes with the real key.
