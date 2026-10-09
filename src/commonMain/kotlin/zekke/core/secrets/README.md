# `zekke.core.secrets` — the vault

The `/secrets` endpoints, the name-and-value envelope a secret's plaintext is, and the vault view
the app draws. The same contract as the web app's vault, so a secret written on one client opens
on the other.

## A secret

The DEK and its wrap are [`items`](../items/README.md)'s, under the `secrets` KEK. The plaintext is
JSON, `{"name": …, "value": …}` (`encodeSecretPayload`): the wire has no name field, so the name
lives inside the ciphertext. `decodeSecretPayload` refuses anything that is not an object with a
string `name` and a string `value` (`MalformedSecretPayloadException`); other fields are ignored.

**A create is create-or-return, not an update.** Replaying an id returns the stored row with
`created = false`; replaying it with different ciphertext changes nothing. There is no update: to
change a secret, create a new one and delete the old. `MAX_SECRET_PLAINTEXT_BYTES` (700 KiB) is
checked before sealing, because the server answers an oversized body and a malformed one with the
same `400`.

## Calls

| Function             | Endpoint                         | Notes                                                 |
| -------------------- | -------------------------------- | ----------------------------------------------------- |
| `createSecret`       | `POST /secrets`                  | The caller's id; `201` created, `200` already stored  |
| `sealSecret`, `queueSecret` | —                         | Sealed at once, sent through the outbox as ciphertext  |
| `listSecretsMeta`    | `GET /secrets?fields=meta`       | The index without ciphertext                          |
| `listSecrets`, `getSecret` | `GET /secrets`, `GET /secrets/{id}` | A deleted secret is absent from both            |
| `openSecret`         | —                                | Unwrap and open                                       |
| `deleteSecret(s)`    | `DELETE /secrets/{id}`, `DELETE /secrets` | `secret-delete`, signed by this device; moves to Recently deleted |
| `listDeletedSecrets` | `GET /secrets/deleted`           | Recently deleted, with `deleted_at`                    |
| `restoreSecret`      | `POST /secrets/{id}/restore`     | Unsigned, no body                                      |
| `purgeSecrets`       | `DELETE /secrets/deleted`        | `secret-purge`: the only call that destroys            |

**A delete is recoverable and a purge is not.** They are different actions, so a delete signature
can never purge. Both need a full device.

## The vault view

`vaultView(context, replica)` reads the `secrets` rows the [replica](../feed/README.md) holds,
which include deleted ones (the feed serves them with `deleted_at`), and opens each in memory:

| `VaultView` | Holds                                                                   |
| ----------- | ----------------------------------------------------------------------- |
| `rows`      | Every live secret, newest `updated_at` first: name, value, size received |
| `deleted`   | Recently deleted, newest deletion first                                 |

A secret that does not open with the keys held, or whose plaintext is not the envelope, is a row
with `readable = false` and empty fields; the app chooses what such a row may do and what it is
called. The size is measured from the ciphertext received.

## Tests

`SecretsTest`: the envelope is the web app's and refuses anything else; a create sends the current
generation and a DEK that opens under `secrets` only; a replay is not created and an oversized
secret is refused before any request; delete and purge are different signed actions over sorted
ids; a restore is unsigned; the view splits on `deleted_at`, orders newest first and keeps an
unreadable row. The interop suite carries a secret across two devices through Recently deleted,
restore and purge.
