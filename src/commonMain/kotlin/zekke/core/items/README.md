# `zekke.core.items` — what every item domain shares

`secrets`, `notes`, `credentials` and `folders` encrypt the same way and are deleted the same way.
What they share is here, so each domain only says what is different about it.

## The context — `ItemContext`

`ItemContext(api, session, primitives)` is what every domain call takes: the API client with its
token, and the unlocked session holding the scope KEKs and the device key. A domain call made while
the session is locked throws `SessionLockedException`.

## One DEK per item — `ScopeDeks`

Each item has its own random 32-byte DEK (`generateDek`). The item's plaintext is sealed under it,
and the DEK is wrapped under **the scope's current KEK**, with the generation recorded beside it:

```
ciphertext     = sealed(dek, plaintext)
wrapped_dek    = sealed(scope_kek[key_generation], dek)
key_generation = the scope's current generation when the item was written
```

| Member                         | Purpose                                                                       |
| ------------------------------ | ----------------------------------------------------------------------------- |
| `wrap(dek)`                    | Wraps under the current generation; a fresh IV every time                     |
| `unwrap(wrappedDek, generation)` | Picks the KEK by the item's own generation, fetching the keyrings first if the session lacks it, so an item written before a rotation keeps opening |
| `unwrapHeld`                   | The same with no network call                                                 |
| `openText(...)`                | Unwraps, opens the text, zeroes the DEK                                       |
| `openHeldTextOrNull(...)`      | For views: `null` instead of an exception when an item will not open with the keys held, so one bad item never blanks a screen. A lock still throws |
| `refreshForGenerations(...)`   | Fetches the keyrings once if any generation is missing; tolerates being offline |

A DEK wrapped for one scope does not open under another: the KEKs are independent.

Every write runs inside `keyrings.withCurrentGeneration`: on `409 STALE_KEY_GENERATION` the
keyrings are fetched again, the DEK is wrapped under the new generation, and the write runs once
more.

## Ids

`newItemId` mints a canonical lowercase UUID. **Every create carries the caller's id**, so a
retried request is a `200` returning the stored row, never a second item that nobody could tell
apart from the first. `itemIdOrNew` checks an id the caller passes and refuses a non-canonical one,
because the id signed for a delete must be the id the server verifies.

## Signed deletes

`signedBody(context, action, args, fields)` signs a device action and returns the JSON body with
the envelope; every signed `DELETE` carries a JSON body. `canonicalSelection` checks each id,
refuses an empty selection before anything is signed (the server would answer `404`), and sorts and
de-duplicates the ids for a batchable action, because the server rebuilds the signed payload that
way. The same normalised list goes on the wire, so what is sent and what is signed are the same
bytes.

## The outbox

A queued write holds its `wrapped_dek` and `key_generation` in its body. When the server refused it
as `409 STALE_KEY_GENERATION`, `rewrapStaleEntries(context, outbox)` fetches the keyrings, opens
each such DEK under its old generation and wraps it under the current one; the outbox then sends it
again. `rewrapQueuedBody` is that step for one entry.

## Measuring text

`utf8Length` is a budget in bytes; `codePointCount` and `takeCodePoints` count and cut by Unicode
code point, so an emoji is never cut in half. `hashReceivedCiphertext` is the SHA-256 of the
ciphertext **this device received**: `ciphertext_sha256` from the server describes bytes the server
holds, and proves nothing.

## Tests

`ItemsTestSupport.kt` holds a fake API (`FakeServer`) that records every request and answers from
a queue, and `TestVault`, an unlocked session with real device keys and any number of generations
per scope, which also checks a signed body against the device key. The domains' tests use both.
