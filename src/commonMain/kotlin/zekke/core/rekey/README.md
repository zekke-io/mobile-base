# `zekke.core.rekey` — re-wrapping what a rotation left behind

Removing a device rotates every keyring it held: each scope gets a new KEK. Items already stored stay
wrapped under the generation they were written with until something moves them. This package moves
them, in all five scopes that wrap DEKs, documents included, with their folders, the vault's tabs and
the account's preferences.

**Why it matters.** A removed device can no longer fetch anything, but a database leak together with
that device's keys would open every item still wrapped under a generation it knew. Rotating closes
the door; re-wrapping moves the items behind it.

**It is not a re-encryption.** An item's DEK never changes and no ciphertext is touched: a 4 GiB file
moves by sending its new 60-byte wrap. Someone who already holds an item's DEK keeps it.

## The API

| Function | What |
| --- | --- |
| `removeOtherDevicesAndRewrap(services, words, ids)` | The removal with the phrase, then the re-wrap of every scope it rotated |
| `rewrapAfterRotation(context, scopes)` | Each rotated scope this device holds: its items, then its folders, then (for `documents`) the preferences |
| `rewrapStale(context)` | The same for every scope held. Staleness is read from the listings, so it is safe to run at any time: after enrolling with a removal, after turning Paranoid on or changing the account PIN (both remove the other full devices), or at unlock to finish a pass that stopped |
| `rewrapScope(context, scope)` | One scope's items |
| `rewrapFolderNames(context, treeScope)` | The drive's or documents' folder names, the Trash's included |
| `resealPreferences(context)` | The preferences blob, re-sealed **as opaque bytes**: the core never reads what is inside |
| `staleItems`, `listWraps` | The items below the current generation, by id; every wrap of a scope |

## One table, five scopes

| Scope | Listed from | Route | Ids |
| --- | --- | --- | --- |
| `secrets` | the meta listing **and Recently deleted** | `PUT /secrets/keys`, `secret-rekey` | `id` |
| `notes` | the meta listing | `PUT /notes/keys`, `note-rekey` | `id` |
| `documents` | `GET /documents` **and the Trash's keys** | `PUT /documents/keys`, `document-rekey` | `id` |
| `files` | `GET /files` (stored only) **and the Trash's keys** | `PUT /files/keys`, `file-rekey` | `id` |
| `passwords` | `GET /credentials?fields=meta` | `PUT /credentials/keys`, `credential-rekey` | **`revision_id`** |

- **Deleted and trashed rows are moved too**: restoring one later must not bring a rotated-out wrap
  back.
- **Folders follow their scope**: the drive's and documents' folder names (`document-folder-rekey`,
  `file-folder-rekey`); the vault's tabs and the notes' spaces are one manifest each, re-sealed
  (`FolderStore.reseal`). `passwords` has none.
- **The preferences** live under the `documents` keyring; re-sealing them needs no
  understanding of them, which is why a phone that does not show documents still keeps them right.
- **One signature per batch of at most 100**, over the ids sorted ascending, and never one id twice:
  the server refuses such a batch rather than guess which wrap was meant.
- **A file still uploading is skipped**: its upload carries the current generation itself.
- **A scope this device does not hold is skipped**, and left to a device that does.
- **`sharing` is never walked**: a rotation there is `reestablishConnection` on the other side of
  each connection ([`sharing`](../sharing/README.md)).
- **A batch refused as `STALE_KEY_GENERATION`** fetches the keyrings and is wrapped again once.

Nothing is remembered between passes: a pass that stops half way leaves the rest stale, and the next
pass finds them from the listings.

## Tests

`RekeyTest`: only what is below the current generation, in id order; the secrets walk includes
Recently deleted and moves the same DEK under the new generation, signed over the sorted ids;
passwords by revision, in batches of 100; the preferences re-sealed byte for byte. The interop suite
fills an account at generation 1 in every scope (live, deleted and trashed rows, both folder trees
with a trashed folder, both manifests, a document and a trashed one, the preferences), removes a
device from the phone, re-wraps, and finds every row at generation 2, everything still opening, and
nothing left for a second pass.
