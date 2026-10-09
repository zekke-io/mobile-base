# `zekke.core.signing` — challenge and action signatures

Builds the `{challenge, timestamp, signature}` envelope every authenticated request and every
destructive one carries. **Built once, here, never per call site.**

> A device's token authorises reads and additions within its scopes. Destroying data needs a full
> device's signature. Destroying or re-keying the account needs the root, plus the PIN proof on a
> Paranoid account.

## The two payload shapes

```
auth    = <challenge> ":" <timestamp>
action  = <challenge> ":" <timestamp> ":" <action> [":" <arg> …]
```

A signature made in one shape never verifies in the other. The challenge is 32 random bytes as
lowercase hex; the timestamp is the device clock in Unix **seconds**.

## API

| Function / type                                        | Purpose                                                                                 |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| `Signer`                                               | `signBytes(message)` → 64-byte IEEE P1363. Hashes once with SHA-256                       |
| `rawKeySigner(privateKey)`                             | The root, derived from the phrase for one flow                                           |
| `createChallenge()`, `currentTimestamp()`              |                                                                                         |
| `buildAuthPayload`, `buildActionPayload`, `payloadDigest` | The strings above, and their SHA-256                                                  |
| `signPayload`, `verifyPayload`                         | `verifyPayload` accepts high-S signatures and returns `false` for malformed input         |
| `signAuthEnvelope(signer)`                             | Sign-up (root) and sign-in (device)                                                      |
| `signActionEnvelope(action, args, device)`             | Device actions; throws `WrongSignerException` for a root action                          |
| `signRootAction(action, args, root, pinProof?)`        | Root actions; `pinProof` signs `payloadDigest(payload)`, the digest the root signature covers. Throws `PinProofNotAllowedException` on an action that never takes one |
| `Action`, `normalizeActionArgs`                        | The action table as data                                                                 |

The envelope functions take a `clock` so tests can fix the timestamp; nothing else should.

## The action table

`Action` lists the 36 actions with their argument order, signer (`ROOT` or `DEVICE`), whether a PIN
proof applies and whether they are variadic. A test asserts the count.

- **Root actions:** `chain-read`, `device-enrol`, `account-delete`, `second-factor-begin`,
  `enable-second-factor`, `rotate-second-factor`, `pin-evaluate`. A PIN proof goes on all of them
  on a Paranoid account except `enable-second-factor` (no PIN exists yet) and `pin-evaluate`
  (it is how the proof is obtained).
- **Variadic actions** (deletes, purges, re-keys): the ids are **sorted ascending and
  de-duplicated** before signing, and the same list goes on the wire; a single item is the
  one-element case.
- **A re-key batch that names an id twice is refused**, not de-duplicated: two different wraps
  for one id would be two different outcomes.
- `normalizeActionArgs` enforces arity and refuses empty arguments and any containing `:`,
  throwing `InvalidActionArgumentsException`.

## Things that silently break every signature

- **Pre-hashing.** The signer hashes the payload once, as the server does; hashing first signs
  `SHA-256(SHA-256(payload))`. A test checks such a signature fails.
- **Anything but P1363.** `signPayload` checks for 64 bytes.
- **Reusing a challenge.** One fresh challenge per request; a retry needs a new envelope.
- **A wrong clock.** The server accepts ±300 seconds (`FRESHNESS_WINDOW_SECONDS`). The timestamp
  is never adjusted to the server's clock.

## Tests

`SigningTest`: the table's count, uniqueness, root actions and proof rules; the challenge shape;
the recorded `account-delete` payload and digest; signing and verifying against the right key only;
the high-S signatures of the genesis chain; the pre-hash trap; auth versus action separation;
sorting, de-duplication and the re-key refusal; arity, empty and separator checks; signer
refusals; and a PIN proof that verifies over the root's digest.
