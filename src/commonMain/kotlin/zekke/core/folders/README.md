# `zekke.core.folders` — the sealed folder manifest

How the vault's tabs (`secrets`) and the notes' spaces (`notes`) are organised: one sealed blob per
scope, so the server never learns a folder's name, how many there are, or which item sits in which.
The same manifest the web app writes, so a tab made on one client appears on the other.

The drive and documents keep their folders as rows on the server instead: that tree is
[below](#the-tree--drive-and-documents--treekt).

## The manifest — `Manifest.kt`

```
{
  "v": 1,
  "folders": { "<folder id>": { "name", "parent_id", "position", "updated_at", "deleted_at"? } },
  "items":   { "<item id>":   { "folder_id", "updated_at" } }
}
```

`formatFolderManifest` writes it with `parent_id` and `folder_id` as explicit `null`s and whole
positions as integers; `parseFolderManifest` reads it. Timestamps are written as the browser writes
them (`2026-10-09T13:45:07.089Z`, `nowTimestamp`), because the merge compares them as strings.

- **`home` is a real folder** with the fixed id `home`, so two devices that each start an empty
  manifest make the same folder. It can be renamed, never deleted or moved off the root, and an
  item with no live folder resolves to it.
- **A deletion is a tombstone** (`deleted_at`), never a removed key, so a merge cannot bring a
  deleted folder back.
- **Ordering is `position`, then name, then id**, computed here: the server cannot sort what it
  cannot read.

`ManifestScope.rules` is the same for both scopes: depth 1 (a tab is flat) with `home`.

### Validation

The server stores the blob without reading it, so the tree is the client's to check.
`validateFolderManifest` throws `FolderManifestInvalidException` with the problem: `CYCLE`,
`TOO_DEEP`, `UNKNOWN_PARENT`, `DELETED_PARENT`, `MISSING_HOME`, `UNKNOWN_FOLDER`, `MALFORMED`,
`BAD_NAME`, `UNKNOWN_VERSION`. **A cycle would render forever**, so every walk is bounded by the
number of folders and a manifest that fails is reported, never drawn.

### Edits and the merge

An edit is a `FolderEdit`: `createFolder`, `renameFolder`, `moveFolder`, `deleteFolder` (the whole
subtree), `placeItem`, `forgetItems`. It throws `FolderEditException` when it cannot apply, and
returns **the same instance** when it changes nothing, so nothing is written. `createFolder` mints
its id when it is built, so a retry never makes a second folder.

`mergeFolderManifests(stored, local)` keeps, per folder id and per item id, the later `updated_at`
(the stored side wins a tie), then `repairFolderManifest` mends what neither side wrote: a cycle
lifts its most recently moved folder to the root, a live folder under a deleted one is deleted with
it, a subtree carried too deep is lifted, and `home` is put back. A simultaneous rename can lose
one side's word.

## The store — `FolderStore.kt`

`FolderStore(context)` loads, edits and seals one manifest per scope, and keeps them in memory
until the session locks.

| Member                     | Purpose                                                                    |
| -------------------------- | -------------------------------------------------------------------------- |
| `load(scope, fresh)`       | `GET /<scope>/folders`; none stored (`404`) is an empty manifest with `home` |
| `loadFromReplica(scope, replica)` | The same from the replica's `folder_manifest` row, when it is newer than what is held |
| `edit(scope, edit)`        | Applies, merges, seals and `PUT`s on the revision it read. On `409 CONFLICT` it reads again and **applies the same edit** to what the other device stored, so an edit that no longer makes sense fails rather than being merged into something else; on `STALE_KEY_GENERATION` it fetches the keyrings. Four attempts |
| `reset(scope)`             | Replaces a manifest that fails validation with an empty one. Only the user starts it |
| `reseal(scope)`            | Re-seals a manifest stored under an older generation, unchanged, after a rotation |
| `close()`                  | Stops listening to the lock and forgets the manifests                       |

Each write seals the JSON under a fresh DEK wrapped by the scope's current KEK and signs
`folders-update` over `[scope, expected_revision, sha256(ciphertext)]`. Writes on one store are
serialised. Deleting a tab drops only the grouping: the app deletes the tab's items first, with
their own signed batch.

## The tree — drive and documents — `Tree.kt`

Here a folder is a row: the server knows which folder is inside which and where each item sits,
and **never a name**, which is sealed under a fresh DEK wrapped by the scope's KEK.

| Function | What |
| --- | --- |
| `listTreeFolders`, `treeFoldersFromReplica` | Every live folder with its name opened, the tree validated with `TREE_RULES` (depth 8, no `home`) before it is returned |
| `listTreeFolderRecords` | The rows unopened, for a rotation's re-wrap |
| `createTreeFolder`, `renameTreeFolder` | Seal the name; the caller's id |
| `moveTreeFolder` | `null` is the top level |
| `deleteTreeFolder` | `folder-delete` over `[scope, folder_id]`; the server takes the subtree and its items to the Trash |
| `moveItemsToFolder` | Moves items; `null` is the top level |
| `childrenOf`, `pathTo`, `descendantsOf` | Walking the tree for a folder view and a path |
| `canMoveFolder`, `canCreateIn` | The server's depth and cycle rules, so the app never offers a move it would refuse |

The server enforces the tree and the client checks it anyway: a loop from the server is a
`FolderManifestInvalidException`, never an endless screen. Its two refusals,
`FOLDER_TOO_DEEP` and `FOLDER_INTO_ITSELF`, come back as `FolderTreeProblemException`. A folder
whose name will not open keeps its place with `name = null`.

## Tests

`ManifestTest`: the web app's JSON read and written back unchanged; what is not a manifest; every
validation problem; the merge per folder, a deletion kept, a cycle lifted, repairs; edits refused
and edits that change nothing; resolving an item to `home`; timestamps. `FolderStoreTest`: the
first edit on a scope with none, signed on revision 0; a conflict applies the same edit to the
other device's manifest; an edit that changes nothing writes nothing; a looped manifest is
reported; a reseal moves the generation forward unchanged; a lock forgets. The interop suite edits
the tabs from two devices at once and keeps both edits.
