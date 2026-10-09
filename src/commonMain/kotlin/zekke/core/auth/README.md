# `zekke.core.auth` — signing up, signing in, entering with the phrase

The four authentication routes, each one signed envelope and one request.

| Function             | Route                       | Signed by                                    |
| -------------------- | --------------------------- | -------------------------------------------- |
| `signUpWithGenesis`  | `POST /sign-up`             | The root, over `challenge:timestamp`; the body carries the genesis batch |
| `signInDevice`       | `POST /sign-in`             | The device, over `challenge:timestamp`        |
| `readChainWithRoot`  | `POST /devices/enrol/chain` | The root, `chain-read`, with the PIN proof on a Paranoid account |
| `enrolWithRoot`      | `POST /devices/enrol`       | The root, `device-enrol` over the batch digest, with the PIN proof on a Paranoid account |

Each stores the JWT it receives in the `ZekkeApi`'s `TokenStore`.

**Every `404` from these routes is one `AuthRejectedException`**, carrying the endpoint and a
diagnostic for logs and never for the user: an unknown account, a wrong phrase, a removed device, a
bad signature and a missing or wrong PIN proof are indistinguishable by design, and the app shows
one sentence for all of them.

## Tests

Through the interop suite (`jvmInteropTest`), against a running API.
