# `zekke.core.session` — the keys of an unlocked phone

`SessionKeystore` holds, in memory, what an unlocked phone works with:

- the device's keys (`device`);
- the unwrapped **scope KEKs**, by scope and generation, and the current generation of each;
- the sealed sharing material of each `sharing` generation, opened on first use;
- the account's `user_address` and root public key, this device's id, its scopes and its PIN
  registration id.

**The phrase, the seed and the root keys are never in it.** They exist only inside the flows that
need them, and are zeroed right after.

## API

| Member                                               | Purpose                                                                      |
| ---------------------------------------------------- | ---------------------------------------------------------------------------- |
| `state: StateFlow<SessionState>`                     | `LOCKED`, `UNLOCKING`, `UNLOCKED`, `REMOVED`, for the app to observe          |
| `beginUnlock()`, `unlockFailed()`, `open(keys)`      | An unlock in progress, a failed one, and the keys once opened                 |
| `signer()`, `deviceSecrets()`                        | The device key, for sign-in, actions and statements; its PQXDH secrets        |
| `currentKek(scope)`, `kek(scope, generation)`        | Every write wraps under the current one; a row is read by its `key_generation` |
| `addKeyrings(entries, current)`                      | After a rotation or a keyring refresh; older generations are kept             |
| `sharingKeys(generation)`                            | Opens that generation's sharing material once                                 |
| `holds(scope)`, `requireScope(scope)`, `isFullDevice` |                                                                              |
| `touch()`                                            | The app reports activity, which re-arms the idle timer                        |
| `lock()`, `onLock(listener)`, `markRemoved()`        | See below                                                                     |

- A scope the device does not hold throws `ScopeNotHeldException`.
- A generation of a held scope with no KEK throws `MissingGenerationException`: every generation is
  wrapped to every device holding the scope, so this is a bug to report, not a state to hide.
- Any access while locked throws `SessionLockedException`.

## Locking

**`lock()` runs `SecretRegistry.zeroAll()`**: every key in the process is zeroed, the session's and
any other flow's, and every one of them then refuses to be used. Lock listeners are told once per
lock. The device record stays, so the PIN brings the phone back. `markRemoved()` locks and leaves
the session `REMOVED` for good, for a device the chain no longer lists.

Opening a session over an open one zeroes the previous session's keys, not the whole process, and
not a key the new session reuses.

**The idle timer** locks after `idleTimeout` (15 minutes by default) without activity, when the
keystore is given a `CoroutineScope` to run it in. Every access re-arms it, and so does `touch()`.
What counts as activity, and locking when the app leaves the foreground, are the app's to report.

## Tests

`SessionKeystoreTest`: what it holds, scope and generation refusals, sharing material opened once,
rotations added, a lock that leaves no key in the process and a signer that then refuses, listeners
once per lock, reopening, the removed and unlocking states, and the idle timer on virtual time.
