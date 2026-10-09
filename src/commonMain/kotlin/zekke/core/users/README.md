# `zekke.core.users` — the account and usernames

| Function          | Route                              | Notes                                                                      |
| ----------------- | ---------------------------------- | -------------------------------------------------------------------------- |
| `getMe`           | `GET /users/me`                    | The account: address, username, uuid, `paranoid`, the plan                |
| `lookupUsername`  | `GET /users/lookup?address=`       | Public; a `404` means no account uses that phrase                          |
| `updateUsername`  | `PUT /users/username`              | Signed by a full device, `username-update` over the **normalised** name    |
| `resolveUsername` | `GET /users/resolve?username=`     | `null` for no account using that name now, never "this user does not exist" |
| `getPublicKeys`   | `GET /users/{uuid}/public-keys`    | A contact's sharing keys with their proof path, checked by `chain.verifyProofPath` |
| `deleteAccount`   | `DELETE /users`                    | Signed by the root, `account-delete`, with the PIN proof on a Paranoid account |

`normalizeUsername` trims and lowercases; `isUsername` is the format rule.

## Tests

`UsersTest` for the username rules; the routes through the interop suite.
