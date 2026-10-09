# `zekke.core.credentials` — passwords

The password store: the `/credentials` endpoints, the credential payload and the passwords view.
The same contract as the web app and the browser extension.

## An edit is an append

A credential is a series of **revisions**. `writeCredential` always posts a new one: with
`credentialId` it is an edit of that credential, without it a new credential. A `revision_id` is
always sent, so a retry is a `200` and not a second revision. There is no update and there will not
be one: making an edit an addition is what lets a device holding only `passwords` (the extension)
write without any signature, and it is where *Previous passwords* comes from.

The DEK and its wrap are [`items`](../items/README.md)'s, under the `passwords` KEK.
`MAX_CREDENTIAL_PLAINTEXT_BYTES` (24 KiB) is checked before sealing. The server never learns which
site a credential is for: the site is inside the ciphertext.

## The payload

JSON, written by `encodeCredentialPayload` and read by `decodeCredentialPayload`:

```
{ …fields this client does not know…, "site", "username", "password", "note"?, "urls"?, "match"? }
```

- `site`, `username` and `password` are required strings; `note` is a string; `urls` a list of
  strings; `match` is `domain` (the default, never written) or `host`.
- **Fields it does not know are kept** in `extra` and written back on every edit, so an edit here
  never drops what the extension or a later version wrote.
- An empty note and blank URLs are not written. Anything else is
  `MalformedCredentialPayloadException`.

## Calls

| Function              | Endpoint                               | Notes                                          |
| --------------------- | -------------------------------------- | ---------------------------------------------- |
| `writeCredential`     | `POST /credentials`                    | A new revision; `201` created, `200` replayed  |
| `sealCredential`, `queueCredential` | —                        | The same write, sent through the outbox         |
| `listCredentials`     | `GET /credentials`                     | One row per live credential, at its current value |
| `listCredentialsMeta` | `GET /credentials?fields=meta`         | Revision ids and wraps, for a rotation         |
| `getCredential`       | `GET /credentials/{id}`                |                                                |
| `syncCredentials`, `syncAllRevisions` | `GET /credentials/sync` | Every revision above a cursor, tombstones included |
| `listRevisions`       | `GET /credentials/{id}/revisions`      | One credential's history, newest first          |
| `deleteCredential(s)` | `DELETE /credentials/{id}`, `DELETE /credentials` | `credential-delete`: writes a tombstone revision; recoverable |
| `restoreCredential`   | `POST /credentials`                    | Opens the last live revision and writes it again as a new revision of the same credential |
| `pruneCredential`     | `POST /credentials/{id}/prune`         | `credential-prune` over the id **and** `keep_last` |
| `purgeDeletedCredential` | the same                            | `keep_last = 1` on a deleted credential: every revision that sealed a password goes, the tombstones stay |

## The passwords view

`passwordsView(context, replica)` reads every revision the [replica](../feed/README.md) holds:

- `rows`: each credential's **highest-`seq` revision** that is not a tombstone, opened, sorted by
  site then username, ignoring case.
- `deleted`: each credential whose newest revision is a tombstone and that still has a live one
  (`deletedCredentials`), newest deletion first, carrying what `restoreCredential` and
  `purgeDeletedCredential` need.
- `credentialHistory(revisions, id)` is *Previous passwords*: the live revisions, newest first.
- `siteLabel` names a site by its host, without `www.`.

A revision that does not open is a row with `readable = false`.

**A purge done elsewhere does not reach the replica yet.** A prune deletes revisions without a
feed tombstone, so a phone keeps, still encrypted, the revisions another device purged, and lists
the credential under Recently deleted until its replica is reset. The server-side fix is open as a
task of the workspace.

## Tests

`CredentialsTest`: the payload is the web app's and keeps unknown fields; a write is a `POST`
carrying both ids under `passwords` only, a replay is not created, an oversized one is refused; an
edit mints a new revision of the same credential; delete and prune sign exactly what they destroy,
`keep_last` included; Recently deleted, the current revisions and the history; site labels; the
view's order and its deleted list. The interop suite edits, deletes, restores and purges a
credential across two devices.
