# `zekke.core.clients` — which app versions are still served

`getClientPolicy(api, platform)` reads `GET /clients/{platform}/policy`; it **fails open**,
returning `null` on any failure. `versionNotice(policy, version)` says what to show:

| Notice       | When                                                            |
| ------------ | --------------------------------------------------------------- |
| `Required`   | Below `min_supported`: the app stops, as a `426` would make it  |
| `Deprecated` | Below `deprecated_below`, with the date support ends            |
| `Available`  | Below `latest`                                                  |
| `Current`    | Otherwise                                                       |

`compareVersions` follows semantic versioning, prereleases included.

## Tests

`ClientsTest`: comparisons with prereleases, and each notice.
