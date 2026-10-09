# `zekke.core.feed` — the replica, the change feed and the outbox

A phone keeps a local copy of the account's items and brings it up to date from `GET /changes`, so
it opens instantly from what it holds and asks the server only for what changed. Writes that need no
signature are queued in an outbox and sent when the network allows.

## What the replica holds — `Replica.kt`

**What the server holds, and nothing else**: each scope's rows exactly as the feed serves them
(ciphertext, wrapped DEKs, generations, ids, sizes, timestamps), the `seq` each row arrived at, the
tombstones' `seq`, and one cursor per scope. **Never plaintext, never a key.** Opening an item
decrypts it in memory with the session's keys.

| Table               | Holds                                                               |
| ------------------- | ------------------------------------------------------------------- |
| `replica_row`       | `(item_type, item_id)` → scope, `seq`, the item as JSON              |
| `replica_tombstone` | `(item_type, item_id)` → the `seq` it was removed at                 |
| `replica_cursor`    | scope → cursor, and whether the scope has been read to its head once |
| `replica_meta`      | the account the replica belongs to                                   |

**A page and its cursor are applied in one transaction.** A row is kept only if its `seq` is above
the one held, so this phone's own write coming back, or a late page, changes nothing. A tombstone
removes the row and is remembered, so an older copy cannot bring it back. Null fields are stored
absent, as every item endpoint omits them.

**The replica belongs to one account.** Opening it for another address empties it first.

**A local schema change is a reset, never a migration.** `replicaSchema` wraps the generated schema:
when its version moves, every table is dropped and created again, and every scope is pulled from
zero. Nothing the server does not already hold is lost.

The app creates the SQLite driver (Android needs a `Context`; iOS and the JVM need a file name) with
`replicaSchema`, and hands it to `Replica(driver, userAddress)`.

## Following the feed — `Feed.kt`

| Member                                  | Purpose                                                                    |
| --------------------------------------- | -------------------------------------------------------------------------- |
| `sync(scope, notify = true)`            | Pulls pages from the cursor until `more` is false; returns whether anything changed (the first sync of a scope always does) |
| `syncAll(scopes)`                       | Each held scope in turn                                                     |
| `changes: SharedFlow<FeedScope>`        | A scope whose content changed in a sync that was not quiet                 |
| `startPolling(scopes)` / `stopPolling()`| Every 30 s, doubling to 120 s while nothing changes, back to 30 s on a change |
| `close()`                               | Stops polling and cancels the feed's work                                  |

- **One pull per scope at a time.** A caller that arrives during a pull waits for it, and then for
  one more pull shared by every caller that arrived meanwhile, so a screen reloading after its own
  write always sees it.
- **`410 RESET`** empties that scope and pulls it from zero, once per sync.
- **Sync runs only while the session is unlocked**, and only for scopes the device holds. Locking
  stops the polling. There are no silent pushes.
- **A failed pull fails the call, not the app**: the feed's coroutines run under their own
  supervisor inside the scope the app gives it.

The feed serves `passwords`, `secrets`, `notes`, `documents` and `files`. `documents` rows carry
their lifecycle only, never their content.

## The outbox — `Outbox.kt`

Writes that need no signature (creating a secret, creating or editing a note, appending a credential
revision, creating a drive folder) are sealed at once and queued **as ciphertext**, each with its
client-generated id, so a replay is a `200`, never a second item. The outbox is a database of its
own: unlike the replica it holds what the server does not have yet, so **it is never wiped by a
schema change**; changing its schema needs a real migration.

| Member                         | Purpose                                                                       |
| ------------------------------ | ----------------------------------------------------------------------------- |
| `enqueue(itemId, scope, method, path, body, keyGeneration)` | `POST` or `PUT` only, and never a body carrying a signature: **a signed action is signed and sent while the user waits** |
| `flush(api)`                   | Sends in order and forgets what was stored. Returns how many were sent, how many wait for a re-wrap, how many were refused, and why it stopped |
| `rewrapStale(rewrap)`          | At the next unlock, re-wraps every entry the server refused as `409 STALE_KEY_GENERATION`, then sends them again |
| `entries()`, `discard(position)` | For the app to show and drop what was refused                                 |

| Answer                         | What happens                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `201` / `200`                  | Sent; the entry goes                                                           |
| `409 STALE_KEY_GENERATION`     | `NEEDS_REWRAP`: it needs the new KEK, so it waits for the next unlock           |
| Any other `4xx`                | `REFUSED`: set aside for the app to show                                       |
| `401`, `429`, `5xx`, no network | Stop; everything stays queued                                                  |

**The outbox may finish after the session locks**, because sending ciphertext needs no key, only the
token. It belongs to one account, like the replica.

## Not here

The views each screen reads come with their domains and are built from `Replica.items(scope, type)`:
the vault split on `deleted_at` (`secrets`), the note tiles newest first (`notes`), each
credential's newest revision and Recently deleted (`credentials`), the tabs and spaces
(`folders`), the drive per folder with its pending uploads (`files`). What each domain queues in the outbox, and the
re-wrap of a queued item, are in [`items`](../items/README.md).

## Tests

`ReplicaTest`, `FeedTest` and `OutboxTest` (JVM, on an in-memory SQLite): the newest copy wins, a
tombstone holds, the cursor moves forward with its page, nulls, resetting one scope, another
account, a schema change wiping; pages, `RESET`, one pull at a time with a shared follow-up, quiet
reads, held scopes and a locked session, the poll's back-off; the outbox's order, re-wrap, offline,
rate limit, refusal, and its refusal of signed actions. The interop suite writes notes from a second
device and reads them here by cursor, forces a `RESET`, replays an outbox entry, and re-wraps one
after a rotation.
