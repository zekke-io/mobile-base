# `zekke.core.notifications` — notices about the account

The client of `GET /notifications` and `POST /notifications/read`. The server sends a `kind` and
`params`, never text: each app writes the sentence.

| Function | What |
| --- | --- |
| `listNotifications(api, limit, cursor)` | One page, newest first: the notifications, the unread count, and the next cursor when there is one. `params` that is not an object becomes empty |
| `unreadNotificationCount(api)` | Read with `limit = 1` |
| `markNotificationsRead(api, ids)` | De-duplicates, refuses a non-canonical id, sends at most 200 per request |
| `markAllNotificationsRead(api)` | `{ "all": true }` |
| `NOTIFICATION_KINDS`, `isKnownKind` | The kinds this version can word. **A kind outside the list is shown as a generic notice**, never dropped, so an older app survives a newer server |

A notification is about the account, never about what it stores: it needs only the token, no key.
There are no push notifications: the app reads them while it is open.

## Tests

`SharingTest` covers an unknown kind kept, `params` normalised, the cursor, and marking read in
batches of 200 with a non-canonical id refused.
