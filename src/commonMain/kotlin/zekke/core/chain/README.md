# `zekke.core.chain` — the account event chain

Builds and verifies the signed, hash-chained statements that record an account's devices, scopes,
keyring generations and sharing keys. It is a port, rule for rule, of the server's verifier.
**The client verifies everything the server returns**: its own chain at every unlock, from the
pinned root key, and every contact's proof path.

## Statements

```
statement  = "Cryple-Chain-v1|" user_address "|" seq "|" prev "|" type ["|" field …]
signature  = ECDSA-P256(SHA-256(statement)), IEEE P1363, base64
event_hash = hex(SHA-256(statement "|" signer "|" signature))
```

`buildStatement`, `deviceAddFields`, `formatRotations` / `parseRotations`, `eventHash`,
`signStatement` and `batchDigest` (the hex SHA-256 of the statements joined by `\n`, which
`device-enrol` signs) produce exactly these bytes. `signer` is `root` or the signing device's id.

| Event            | Fields                                                                   |
| ---------------- | ------------------------------------------------------------------------ |
| `device-add`     | device id, signing key (SPKI), X25519 key, ML-KEM key, scope list         |
| `device-remove`  | device id                                                                |
| `device-scopes`  | device id, the narrowed scope list                                       |
| `keyring-rotate` | `scope=generation` pairs in canonical order                              |
| `sharing-keys`   | generation, X25519 key, ML-KEM key                                       |

## `ChainState` — the verifier

`ChainState.replay(userAddress, rootPublicKey, storedEvents)` rebuilds the devices, each keyring's
generation and the announced sharing keys, and **throws `InvalidChainException` on the first rule
broken**: a wrong sequence or head, an unknown version, another account's address, a bad signature,
a removed or non-admin signer, a device granting a scope it lacks, a narrowing that widens, a
rotation that skips a generation, a removal of another device without rotating what it lost, a
sharing rotation without its keys, and a genesis that is not `device-add` (with `admin`),
`sharing-keys` 1, then a rotation of every keyring to 1, all signed by the root. It checks every
stored `event_hash` too, and validates every published key (an ML-KEM key must encapsulate).

`applyBatch(events)` applies a batch this client is about to send, with the server's batch rules;
the builders in `keyrings` run it on everything they build, so a batch the server would refuse is
refused here first.

**Replay without batch boundaries.** A stored chain does not record where a batch ended, so the
batch rules are applied to each run of consecutive events by the same signer. Every batch sits
inside one such run, so an accepted chain always replays, and a removal missing its rotation is
still refused.

The verifier mirrors the server exactly, including what the server still allows: a device-signed
`device-add` granting `admin` replays. Refusing to *build* one is the builders' rule
(`buildDeviceLink`), until the server refuses it too.

## Proof paths

`verifyProofPath(userAddress, rootPublicKey, sharingKeys, proof)` checks what the server publishes
for a contact: the path starts at the root, each step is a `device-add` of an admin device that
signs the next event, every signature and hash verifies, and the last event announces exactly the
published sharing keys. `sharingKeysFromState` gives the current keys of a replayed chain.

**Signatures are verified with high-S accepted**, as the server and the vectors require.

## Tests

`ChainVectorsTest`: every genesis statement rebuilt from its fields, every event hash, the recorded
genesis replayed from the root key and refused under another, the root key the seed derives.
`ChainRulesTest`: each refusal above. `BatchesTest` and `ProofPathTest`: the builders' batches pass
the verifier, and proof paths verify or are refused.
