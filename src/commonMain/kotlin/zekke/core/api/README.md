# `zekke.core.api` — the HTTP layer

The one place that talks to the Zekke API: base URL, envelopes, status rules, error codes,
pagination, the token and the client's identity. Nothing above it builds a URL or reads a raw
response. It runs on Ktor: OkHttp on Android and the JVM, Darwin on iOS.

## `ZekkeApi.request`

```kotlin
api.request(method, path, body = jsonObject, token = api.tokens.require(), query = mapOf(...), timeout = 30.seconds)
// → ApiResponse(status, message, data: JsonElement?, page: PageInfo?), then response.decode(Serializer)
```

- **Headers**: `Content-Type` only with a body, `Authorization` only with a token, and
  `Zekke-Client: android/<version>` (or `ios/…`) when the app passed a `ClientIdentity`.
- **No retries, ever.** Every retry of a signed call needs a fresh envelope, so retry policy lives
  with the flows; a test helper retries on rate limits, the library does not.
- **Status by response, never by verb**: `201` created, `200` everything else, `204` with no body.
- **Bodies over 1 MiB** (`MAX_BODY_BYTES`; 8 MiB for documents) throw `RequestTooLargeException`
  before anything is sent.
- **Timeouts never below 2 s** (`MIN_TIMEOUT`); public routes have a 350 ms floor, and timing is
  never a signal.
- **Transport failures** become `NetworkError`; a cancelled coroutine stays cancelled.
- **The server's clock is recorded, never applied.** Each response's `Date` header updates
  `serverClockOffsetSeconds`; `isClockSkewed` turns true past two minutes, so the app can say the
  phone's clock is wrong instead of letting every signature fail as a generic `404`. Signed
  timestamps always use the phone's own clock.
- `wireJson` omits absent optional fields (`explicitNulls = false`) and ignores unknown ones.

## Errors carry no message

`ApiError(code, status, endpoint, allow, retryAfterSeconds)`, with the predicates
`isSessionOver` (`401 UNAUTHORIZED`), `isCredentialFailure` (`401 INVALID_CREDENTIALS`),
`isAuthEndpointRejection` (`404`), `isRateLimited` (with `Retry-After`), `isUpgradeRequired`
(`426`), `isPlanRequired`, `isStaleKeyGeneration`, `isTooManyDevices`, `isInvalidBatch`,
`isQuotaExceeded`, `isObjectTooLarge`, `isUsernameUnavailable` and `isReset`. A router `404` in
plain text is an `ApiError` too. Each app writes its own sentence from the code.

## The rest

| Function / type                              | Purpose                                                                       |
| -------------------------------------------- | ----------------------------------------------------------------------------- |
| `TokenStore`                                 | The JWT, in memory only; `get()` forgets an expired one; `require()` throws `NoSessionTokenException` |
| `decodeJwtClaims`, `isJwtExpired`            | Read `exp`, `device_id`, `user_address` without verifying (the client has no key) |
| `collectPages`                               | Follows `next_cursor` until `has_more` is false; a short page is not the last |
| `isCanonicalUuid`, `canonicalizeUuid`        | The only spelling the API accepts, converted once at the edge                 |
| `ClientIdentity`, `ClientPlatform`           | The `Zekke-Client` header; the version must be semantic                       |
| `parseHttpDate`                              | The `Date` header, for the clock offset                                       |

## Tests

`ZekkeApiTest` on Ktor's mock engine: headers and the client identity, no token no
`Authorization`, `204`, the envelope and page, error codes, the router's plain `404`, both `401`s,
`Retry-After` and `426`, transport failures, the body cap, the clock offset, pagination past a
short page, UUID spellings, the token store's expiry, and semantic versions.
