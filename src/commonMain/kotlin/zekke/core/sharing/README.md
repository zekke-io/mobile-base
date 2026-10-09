# `zekke.core.sharing` — sharing between accounts

Connections between two accounts, the items shared through them, trust in the other account's
keys, the address book, and the folders of a friendship. The same protocol as the web app's
sharing, so a share sent from a phone opens in a browser and the reverse.

| File            | What                                                                               |
| --------------- | ---------------------------------------------------------------------------------- |
| `Keys.kt`       | The connection key, its PQXDH wrap, the wrap of a DEK under a connection, the root fingerprint |
| `SharingApi.kt` | The routes and the wire types                                                      |
| `AddressBook.kt`| The sealed address book: root pins, connection nicknames, device names             |
| `Sharing.kt`    | `SharingService`: trust, inviting, accepting, sending, reading, copying, re-establishing, the friendship's folders |

## One connection per pair, both ways

A connection joins two accounts whoever invited, and once accepted carries shares both ways.

- **The connection key** is 32 random bytes, PQXDH-wrapped (usage `item-share`, both parties'
  addresses in the context) to the recipient's current **sharing keys**: `pqxdh_blob`, with
  `recipient_key_generation`. The sender keeps it sealed under its own current `sharing` KEK:
  `sender_wrapped_key`, with `sender_key_generation`. Each side opens only its own copy.
- **A share never uses the connection key directly.** Each side derives one sub-key per item scope,
  `HKDF-SHA256(connection_key, "Cryple-Share-v1|<scope>")`, seals it under that scope's KEK and
  stores it (`PUT /connections/{id}/keys`, signed over a digest of the lines `scope:generation:wrap`).
  A share's DEK is wrapped under the sub-key of its scope with a fresh random IV: `iv(12) ‖ ciphertext ‖ tag`.
- **Opening a share needs only the scope's sub-key.** A device holding `notes` but not `sharing`
  reads the notes shared with its account and nothing else. A side without a sub-key for a scope
  yet derives and stores it when it holds `sharing`.
- **The connection key is never stored in the clear**: it is opened in memory when needed and zeroed.

Party addresses are checked before any key is derived (`MalformedPartyAddressException`): a context
built from a wrong address makes a key nobody can reproduce.

## Trust

The fingerprint two people compare out of band is the root key's (`rootFingerprint`: SHA-256 of the
SPKI, six groups of four hex digits). `SharingService.verifyConnection` resolves the other account's
current username, reads its published sharing keys and the **proof path** that ties them to its root
key in its chain, and returns a `ConnectionTrust`:

| Outcome          | Means                                                                 |
| ---------------- | --------------------------------------------------------------------- |
| `Trusted`        | Same account, the proof verifies, the root key matches the pin        |
| `Unpinned`       | An invitation awaiting this account, not compared yet                 |
| `RootChanged`    | The root key differs from the pin: do not send                        |
| `ProofInvalid`   | The sharing keys do not trace back to the root: do not send           |
| `AccountChanged` | The username now leads to another account                             |
| `Unresolvable`   | The username leads nowhere                                            |

A pin is set the first time an accepted connection is seen and when an invitation is sent, and is
never replaced. **Every send checks first** (`ConnectionNotTrustedException`). A sharing-key
rotation is not an alarm: the proof path covers it. **A lost connection is a new invitation**, never
a repair by resolving a username again, because usernames are released and reused.

## The address book

One sealed blob per account (`GET`/`PUT /sharing/address-book`) holds the root pins by
`user_address`, connection nicknames and device names. A fresh DEK seals each write, wrapped under
the current `sharing` KEK; a `PUT` is on `expected_revision`, signed `address-book-update`, and on
`409` the book is read again and the edit applied again. Every device of the account sees the same
pins.

## `SharingService`

One per unlocked session. It caches published keys, the latest connection rows, the address book and
the friendships' folders, and **a lock forgets all of them**.

| Member | What |
| --- | --- |
| `connections()` | `GET /connections`, remembered |
| `inviteByUsername(username, existing)` | Resolves, checks trust (pinning), wraps a new connection key to the recipient, stores the sub-keys; refuses a second connection with the same person |
| `acceptInvitation(connection)` | Opens the connection key from the PQXDH blob, stores the sub-keys, accepts, pins |
| `shareItemById(connection, type, id)`, `shareItem` | Checks trust, wraps the item's DEK under the sub-key of its scope, `POST /shares` signed `share-create` |
| `describeReceived`, `describeSent`, `describeConnection` | A `ReceivedItem` per share: the name (a secret's from its envelope, a note's first line, a file's from its manifest), the text, the size. **Never throws**: an item that will not open names the step that failed |
| `openSharedText`, `openSharedFile` (streaming), `openSharedFileBytes` | Read what arrived |
| `copySharedItem` | Copies into this account under a **fresh DEK**, so the sender holds no key to the copy |
| `reestablishConnection` | After the other account's rotation, a new connection key and every share and the folders re-wrapped, in one request |
| `loadSharedFolders`, `editSharedFolders`, `resetSharedFolders` | The friendship's folders |

**Re-establishing** runs only for an outbound, accepted connection whose counterparty still resolves
to the same account, still traces to the pinned root, and has published a **newer** sharing
generation than the one the connection was made to. Each share's DEK is opened under the old sub-key
of whichever scope opens it and sealed under the new one. A device removed from the other account
cannot read what is shared from then on; what it could already read, it keeps.

**The folders of a friendship** are the [`folders`](../folders/README.md) manifest under
`SHARED_FOLDER_RULES` (eight levels, no `home`), placements keyed by share id, sealed under a fresh
DEK wrapped by the connection's `sharing` sub-key, written by either side with
`connection-folders-update`. An edit refused by a cached manifest is tried once more on a fresh read,
because the other person makes folders this side has not seen.

**Documents are not opened by the core**: sharing or copying one is `DocumentsNotInCoreException`;
a received document is described without a name.

## What an app must never claim

Re-sharing cannot be prevented, revocation is prospective, and deleting the original breaks the
share.

## Tests

`SharingTest`: a connection key opens only for its recipient and its two parties; a wrap under a
connection; the root fingerprint; the address book's pins and names; the sub-key digest; an
invitation and a share signed over what they carry. The interop suite connects two accounts, shares
a secret, a note and a file and back, copies, files shares into the friendship's folders, and
re-establishes after one side removes a device. `CrossClientSharingTest` is the core's half of an
exchange with the web app: the core shares a secret and a file, the web app opens them and shares a
note back, the core opens it.
