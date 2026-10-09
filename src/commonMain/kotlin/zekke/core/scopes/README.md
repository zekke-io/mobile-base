# `zekke.core.scopes` — what a device may hold

The seven scopes in their canonical order: `admin,passwords,secrets,notes,documents,files,sharing`.
`Scope` carries each one's wire name; every scope but `admin` is a keyring.

| Function / value                                   | Use                                                                                         |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `SCOPES`, `KEYRING_SCOPES`, `ITEM_SCOPES`, `DEK_SCOPES`, `FULL_DEVICE_SCOPES` | The canonical lists                                                    |
| `parseScopeList` / `formatScopeList`               | A list is comma-joined **in canonical order, without duplicates**. Parsing refuses anything else instead of normalising it, because a signature covers the exact string |
| `scopeForItemType`                                 | `secret → secrets`, `note → notes`, `document → documents`, `file → files`                  |
| `isFullDevice`                                     | Holding `admin` is what makes a device full: it may delete, remove devices and rotate       |

A full device joins only with the phrase; one device links others with limited scope lists, never
`admin` (see `keyrings`).

## Tests

`ScopesTest`: the canonical list against the vectors, refused lists, formatting, and `admin`.
