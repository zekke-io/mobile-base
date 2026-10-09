# `zekke.core.trash` — the drive's Trash

Deleted drive files and folders wait in the Trash for the account's `retention_days`
(`GET /users/me`), then the storage worker destroys them. `0` keeps nothing: a delete is final. The
vault and passwords keep their own Recently deleted ([`secrets`](../secrets/README.md),
[`credentials`](../credentials/README.md)).

Documents have a Trash too, and its routes take `TreeScope.DOCUMENTS`, but a document's name is
inside its Yjs state, which the core does not read; listing the documents Trash waits for documents.

| Function            | Route                          | Notes                                              |
| ------------------- | ------------------------------ | -------------------------------------------------- |
| `getFileTrash`      | `GET /files/trash`             | Trashed folders (with `item_count`) and files      |
| `getTrashKeys`      | `GET /<scope>/trash/keys`      | Every trashed row's wrap, for a rotation's re-wrap |
| `restoreFromTrash`  | `POST /<scope>/trash/restore`  | Unsigned                                           |
| `purgeFromTrash`    | `DELETE /<scope>/trash`        | `file-purge` / `document-purge` over the sorted, de-duplicated ids |

## One list, named here

`listFileTrash(context)` turns each row into a `TrashEntry`, newest deletion first:

- **A folder** is one entry for everything deleted with it, named by opening its sealed name.
- **A file** is named, typed and sized from its sealed manifest.
- **A thumbnail never shows as a file**: it travels as a `companion` of its file, so restoring or
  purging the file takes it along.

A row that will not open keeps its place with `name = null`.

`restoreEntries` and `purgeEntries` send each scope's ids, companions included, in one request, and
answer how many rows moved. A restore puts things back where they were, or at the top when their
folder is still in the Trash; one that would pass the quota is refused whole.

## Tests

`TrashTest`: walking the tree and the moves the server would accept; a folder name sealed and the
server's two tree refusals named; a looped tree reported; a thumbnail as a companion, and a purge
signed over sorted ids. The drive interop case deletes, restores and purges a file with its
thumbnail across two devices.
