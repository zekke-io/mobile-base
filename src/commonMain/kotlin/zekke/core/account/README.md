# `zekke.core.account` — the account flows

Every flow an app runs, from the phrase or the PIN to an open session, with the same outcomes and
guarantees as the web app. The phrase is a `List<CharArray>` and the PIN a `CharArray`; the root
and the phrase exist only inside these flows and are zeroed in a `finally`.

`AccountServices(api, session, vault)` bundles what they need: the API client, the session
keystore and the app's `DeviceVault`.

## Creating and entering

| Flow                                   | What it does                                                                                  |
| -------------------------------------- | --------------------------------------------------------------------------------------------- |
| `draftSignUp(words)`                   | Derives the root, generates the device keys and builds the genesis. **The draft survives a failed sign-up**, so a retry sends the same genesis |
| `completeSignUp(services, draft, pin, paranoid)` | Posts the genesis, verifies the chain, registers the device PIN, seals the record into the vault, turns Paranoid on with the same PIN if asked, opens the session |
| `enrolThisDevice(services, words, pin, remove)` | Enters an existing account **as a full device**: checks the account exists, reads the chain with the root (without a PIN proof first, then with one: the mode is never guessed), builds the enrolment (optionally removing devices), wraps every existing generation to itself, registers the PIN, opens the session. On a Paranoid account the PIN typed is the account PIN, and it becomes this phone's PIN too |
| `discardSignUpDraft(draft)`            | Zeroes a draft the user abandoned                                                             |

`TooManyDevicesException` lists the devices so the user can choose which to remove.

## Unlocking

`unlockWithPin(services, pin)` returns an `UnlockOutcome`, never a generic error the UI must guess:

| Outcome                 | Meaning                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `Unlocked(chainProblem)`| Open. A chain that does not verify is reported, not hidden                                    |
| `WrongPin(attemptsRemaining)` | The PIN did not open the record                                                          |
| `Forgotten`             | The registration is gone: too many wrong PINs, **or the phone was removed from another device**. The record is deleted; only the phrase brings the phone back |
| `Removed`               | Signing in was refused, or the chain no longer lists this device                               |
| `Offline`               | Not a PIN error: no attempt was used                                                          |
| `RateLimited(retryAfterSeconds)` | Wait and say so                                                                       |
| `NoDevice`              | The vault holds no record                                                                     |

The session's `state` follows: `UNLOCKING` during the attempt, back to `LOCKED` when it fails,
`REMOVED` for a removed device. Every evaluation is an attempt, and none is retried here.

## Leaving and changing

| Flow                              | What it does                                                                                     |
| --------------------------------- | ------------------------------------------------------------------------------------------------ |
| `renewSignIn(services)`           | Signs in again with the device key before the token expires or after a `401`; a refusal is `DeviceRemovedException` |
| `removeThisDevice(services)`      | A self `device-remove` signed by the open session, then the record and the session go            |
| `forgetThisDevice(services)`      | The same when the session is open; otherwise the record is only deleted locally. **A phone's signing key is sealed under its PIN**, so a phone whose registration is gone cannot sign its own removal; another full device or the phrase removes it |
| `changeDevicePin(services, pin)`  | Registers the new PIN, re-seals the record, and deletes the old registration                     |
| `removeOtherDevices(services, words, ids)` | With the phrase, for the root wrap key: removes the devices and rotates every keyring they held; the session gains the new generations |
| `turnOnParanoid(services, words, pin)` | Turns Paranoid on with this phone's PIN, re-registers this phone's PIN with it, and **removes every other full device**: their PINs would no longer be the account PIN |
| `changeAccountPin(services, words, current, new)` | Rotates the account PIN, re-registers this phone's PIN, and removes every other full device; limited devices are untouched |
| `deleteAccountWithPhrase(services, words, accountPin)` | Root-signed account deletion, with the PIN proof on a Paranoid account |

Only the phrase makes a full device, and a device links limited devices only.

## Tests

`jvmInteropTest`, against a running API: a Standard account signed up, locked, refused a wrong PIN,
unlocked, its sign-in renewed and its PIN changed; a second full device entering with the phrase and
removed by the first with a rotation of every keyring; a Paranoid account refusing the phrase
without its PIN, entered with it, and its PIN change signing out the other full device. Every
account the suite creates is deleted at the end.
