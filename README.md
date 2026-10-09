# mobile-base

The Kotlin Multiplatform library both Zekke mobile apps share: the cryptographic basis, the
protocol, the API client, the local replica and the item domains. It holds no screen: each app
calls its flows and draws the plaintext view models they return. Android consumes it as a Gradle
module, iOS as an XCFramework.

Its correctness is defined by the Zekke cross-client test vectors, which it reproduces on every
target before any code is built on top of them.

## Targets

| Target                          | Native code                                         | Platform crypto              |
| ------------------------------- | --------------------------------------------------- | ---------------------------- |
| JVM                             | `libzekke_native.so` / `.dylib` for the host, JNI   | JCA and Bouncy Castle        |
| Android (minSdk 28)             | `libzekke_native.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64`, JNI | JCA and Bouncy Castle |
| `iosArm64`, `iosSimulatorArm64` | `libzekke_native.a` per target, cinterop            | CryptoKit, then CommonCrypto |

The JVM target exists for fast tests and interop tests; it ships in no product. The iOS targets
build only on macOS: Kotlin/Native cannot process an Apple cinterop on another host.

## Layout

```
mobile-base/
  settings.gradle.kts         a single-project build
  gradle/libs.versions.toml   every dependency pinned to an exact version
  build.gradle.kts            targets, the native build tasks, the vector fixture tasks
  toolchain/                  a Docker image with the JDK, the Android SDK and the NDK
  .github/workflows/ci.yml    the vectors on the JVM, an Android emulator and the iOS simulator
  consumer-rules.pro          R8 rules an app inherits: the JNI methods, Bouncy Castle's reflective lookup
  native/
    sources.env               the pinned C libraries: version, URL, SHA-256
    fetch.sh                  download both archives and check their SHA-256
    lib.sh                    fetch and verify, configure libsodium, compile mlkem-native and the shim
    build-jvm.sh              host shared library for the JVM tests
    build-android.sh          one libzekke_native.so per ABI, with the NDK
    build-ios.sh              one static library per iOS target, with Xcode (macOS only)
    src/zekke_native.h        the one C surface both platforms call
    src/zekke_native.c        that surface, over libsodium and mlkem-native
    src/zekke_native_jni.c    the JNI shim over it, for Android and the JVM
  src/
    commonMain/…/core         one directory per package, below
    jniMain/…/core            ZekkeNativeJni and the platform lock, shared by the JVM and Android
    jvmMain, androidMain      the JDK provider and Bouncy Castle
    iosMain/…/core            ZekkeNativeCinterop, CryptoKit then CommonCrypto, the platform lock
    nativeInterop/cinterop    zekkeNative.def
    commonMain/sqldelight     the replica's and the outbox's schemas, one database each
    commonTest/…/core         the tests of every package, run on every target
    jvmTest/…/core            tests that need threads
    commonTest/fixtures       test-vectors.json, a copy of the canonical vector file; RFC 9497's vectors
```

Packages are `zekke.core.<module>`, each with its own `README.md`:

| Package                                                        | What it holds                                                         |
| -------------------------------------------------------------- | --------------------------------------------------------------------- |
| [`primitives`](src/commonMain/kotlin/zekke/core/primitives/README.md) | Every cryptographic primitive behind one interface                     |
| [`memory`](src/commonMain/kotlin/zekke/core/memory/README.md)         | `SecretBytes` and the registry a lock zeroes                           |
| [`encoding`](src/commonMain/kotlin/zekke/core/encoding/README.md)     | Hex, base64, UTF-8 and the P-256 public key encodings                  |
| [`keys`](src/commonMain/kotlin/zekke/core/keys/README.md)             | BIP39, SLIP-0010 and the frozen key tree                               |
| [`sealed`](src/commonMain/kotlin/zekke/core/sealed/README.md)         | The AES-256-GCM sealed-blob envelope                                   |
| [`pqxdh`](src/commonMain/kotlin/zekke/core/pqxdh/README.md)           | Hybrid X25519 + ML-KEM-768 wrapping for a recipient                    |
| [`signing`](src/commonMain/kotlin/zekke/core/signing/README.md)       | Challenge and action signatures, and the action table                  |
| [`oprf`](src/commonMain/kotlin/zekke/core/oprf/README.md)             | The RFC 9497 OPRF client and the keys both PINs derive                 |
| [`pin`](src/commonMain/kotlin/zekke/core/pin/README.md)               | The PIN format rules                                                   |
| [`scopes`](src/commonMain/kotlin/zekke/core/scopes/README.md)         | The seven scopes and their canonical lists                             |
| [`chain`](src/commonMain/kotlin/zekke/core/chain/README.md)           | The account event chain: statements, the verifier, proof paths         |
| [`keyrings`](src/commonMain/kotlin/zekke/core/keyrings/README.md)     | Scope KEKs, their wraps, and the batch builders                        |
| [`device`](src/commonMain/kotlin/zekke/core/device/README.md)         | This phone's keys, its sealed record, and the `DeviceVault` each app implements |
| [`session`](src/commonMain/kotlin/zekke/core/session/README.md)       | The keys of an unlocked phone, its state, the lock and the idle timer  |
| [`api`](src/commonMain/kotlin/zekke/core/api/README.md)               | The HTTP layer: requests, errors, the token, pagination, the client identity |
| [`auth`](src/commonMain/kotlin/zekke/core/auth/README.md)             | Signing up, signing in, entering with the phrase                       |
| [`users`](src/commonMain/kotlin/zekke/core/users/README.md)           | The account, usernames, contacts' keys, account deletion               |
| [`clients`](src/commonMain/kotlin/zekke/core/clients/README.md)       | Which app versions are still served                                    |
| [`account`](src/commonMain/kotlin/zekke/core/account/README.md)       | Every account flow, with typed outcomes                                |
| [`feed`](src/commonMain/kotlin/zekke/core/feed/README.md)             | The SQLite replica of ciphertext, the change feed, and the outbox      |
| [`items`](src/commonMain/kotlin/zekke/core/items/README.md)           | What every item domain shares: the per-item DEK, signed deletes, the outbox re-wrap |
| [`secrets`](src/commonMain/kotlin/zekke/core/secrets/README.md)       | The vault: secrets, Recently deleted, restore and purge, the vault view |
| [`notes`](src/commonMain/kotlin/zekke/core/notes/README.md)           | Notes: the note format, the character rule, editing, the note tiles    |
| [`credentials`](src/commonMain/kotlin/zekke/core/credentials/README.md) | Passwords: append-only revisions, Recently deleted, the passwords view |
| [`folders`](src/commonMain/kotlin/zekke/core/folders/README.md)       | The sealed manifest of the vault's tabs and the notes' spaces; the drive's folder tree |
| [`files`](src/commonMain/kotlin/zekke/core/files/README.md)           | The drive: the format, upload with resume, streaming download, thumbnails, the drive view |
| [`trash`](src/commonMain/kotlin/zekke/core/trash/README.md)           | The drive's Trash: listing, restoring, purging                         |
| [`sharing`](src/commonMain/kotlin/zekke/core/sharing/README.md)       | Connections between accounts, shares, trust, the address book, a friendship's folders |
| [`pairing`](src/commonMain/kotlin/zekke/core/pairing/README.md)       | Linking the password extension from the phone with a temporary code    |
| [`notifications`](src/commonMain/kotlin/zekke/core/notifications/README.md) | Notices about the account                                        |
| [`rekey`](src/commonMain/kotlin/zekke/core/rekey/README.md)           | Re-wrapping every scope after a rotation, and re-sealing the preferences |

## Building and testing

This directory is the Gradle root. With a JDK 21, the Android SDK (API 37) and the NDK pinned in
`gradle/libs.versions.toml`:

```sh
./gradlew jvmTest                     # the vectors on the JVM
./gradlew assemble                    # the AAR, with the native code for every ABI
./gradlew connectedAndroidDeviceTest  # the vectors on a connected device or emulator
./gradlew iosSimulatorArm64Test       # the vectors on the iOS simulator (macOS)
./gradlew checkTestVectorsFixture     # the fixture still equals the canonical vector file
./gradlew jvmInteropTest              # the flows, the domains, the drive, sharing and re-keying against a running API (ZEKKE_INTEROP_API)
```

A Linux machine without the Android toolchain can run all but the last two from
[`toolchain`](toolchain/README.md).

**The interop suite** (`src/jvmTest/kotlin/zekke/core/interop`) runs only through
`jvmInteropTest`, never with `jvmTest`. It signs accounts up against the API at
`ZEKKE_INTEROP_API` (default `http://localhost:8080`), so it **writes to that API's database**: every
account it creates is deleted at the end of its test, and an interrupted run can leave one behind.
It waits out the API's rate limits instead of failing on them. The drive cases move their account
to `premium_1` through the API's billing route (`ZEKKE_INTEROP_BILLING_TOKEN`, the local compose's
token by default), upload 1 GiB (`ZEKKE_INTEROP_DRIVE_BYTES`) to the store the API presigns for, and
need that store reachable from the test.

**The cross-client exchanges** (`CrossClientDriveTest`, `CrossClientSharingTest`) run only when
`ZEKKE_CROSSCLIENT_DIR` and `ZEKKE_CROSSCLIENT_STEP` are set. Each is one half of an exchange with
the web app through files in that directory: the core's step writes what it made (and the
recovery phrases of the throwaway accounts), the web app's own code opens it and writes its answer,
and the core's next step checks that answer and deletes the accounts. `core-cleanup` deletes
whatever an interrupted exchange left behind. Run it from a container with
`--network host` when the API listens on the host.

`jvmTest` builds the host library first and hands its path to the tests in the
`zekke.native.library` system property; on Android the library is loaded by name from the APK.

## The native libraries

Two C libraries are built from source rather than taken as Kotlin wrappers. The available
libsodium wrappers are experimental and do not clearly expose ristretto255, and the platform ML-KEM
APIs cannot generate a key pair from a seed on both platforms. Building the same C code for every
target gives Android and iOS one implementation of the primitives that are hardest to get
identical:

| Library      | Version | Used for                                                     |
| ------------ | ------- | ------------------------------------------------------------ |
| libsodium    | 1.0.22  | X25519, Ed25519, ristretto255, Argon2id, the CSPRNG           |
| mlkem-native | 2.0.0   | ML-KEM-768, key generation from the 64-byte seed              |

**Pinning.** `native/sources.env` holds each archive's URL and SHA-256; `lib.sh` downloads into
`build/native/download` and refuses an archive whose hash differs. mlkem-native's archive is
GitHub's tag tarball, and the tag's commit (`MLKEM_NATIVE_COMMIT`) is recorded beside it. Nothing
is downloaded at run time and neither library makes a network call or reads a file.

**One build per target.** libsodium is configured with `--disable-shared --enable-static --with-pic`
for each target and linked statically. mlkem-native is compiled as its single-file
`mlkem_native.c` with ML-KEM-768, the symbol prefix `zekke_mlkem768`, no assembly backend and no
randomised API: the shim draws encapsulation coins from libsodium and zeroes them. The result is
`libzekke_native.so` per Android ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`), a shared library for
the host JVM, and `libzekke_native.a` per iOS target. Android libraries are linked with 16 KB pages,
which Google Play requires of apps targeting Android 15 and later, and export no libsodium symbol.

**The C surface** (`zekke_native.h`) is the only thing either platform calls. Every function returns
`0` on success and `-1` on failure; secret buffers the shim copies are wiped before they are freed.
The Argon2id entry point calls libsodium's internal `argon2id_hash_raw` rather than
`crypto_pwhash`, whose public API only takes 16-byte salts; see the
[primitives README](src/commonMain/kotlin/zekke/core/primitives/README.md#behaviour-every-caller-relies-on).
That header is internal to libsodium, so **a libsodium upgrade must be checked against it**: the
build fails if it moves, and the Argon2id vectors fail if its behaviour changes.

**Changing a version**: update `sources.env` with the new URL and the SHA-256 of an archive you
have verified (libsodium publishes a minisign signature beside each release), delete
`build/native`, and run the vectors on every target. A provider that fails one platform is
replaced, not patched.

## Dependencies

| Dependency                          | Where            | Why                                                                     |
| ----------------------------------- | ---------------- | ----------------------------------------------------------------------- |
| `cryptography-kotlin` 0.6.0         | all              | SHA-2, HMAC, PBKDF2, HKDF, AES-GCM, ECDSA P-256 through the platform    |
| its JDK provider                    | JVM, Android     | JCA                                                                     |
| Bouncy Castle `bcprov-jdk18on` 1.86 | JVM, Android     | The P-256 public point from a raw scalar, which JCA cannot compute       |
| its CryptoKit and Apple providers   | iOS              | CryptoKit first, CommonCrypto for PBKDF2                                 |
| `kotlinx-serialization-json`        | all              | The device record's encoding, and reading the vector fixtures in tests  |
| `kotlinx-coroutines`                | all              | The session's state as a `StateFlow` and its idle timer                  |
| Ktor 3.6.0                          | all              | HTTP: OkHttp on Android and the JVM, Darwin on iOS                       |
| SQLDelight 2.4.0                    | all              | The replica and the outbox: the Android driver, the native driver on iOS, JDBC SQLite on the JVM |

Every version is in `gradle/libs.versions.toml`. Kotlin warnings are errors.

## The vector fixture

`src/commonTest/fixtures/test-vectors.json` is a byte-for-byte copy of the canonical Zekke vector
file, which `checkTestVectorsFixture` expects at `../api-general/docs/crypto/test-vectors.json`.
`web-drive-object.json` was written by the web app's own `lib/files` from a fixed key, so the drive
tests check this core against the other client's bytes. The build embeds every fixture as a Kotlin
string (`generateTestFixturesSource`, which turns each JSON file of `src/commonTest/fixtures` into
one, split across literals the JVM can hold), so every target, the emulator and the simulator
included, reads the
same values without file access. `checkTestVectorsFixture` (part of `check`) fails when the copy
and the canonical file differ; when that file is not present it says so and passes. When the
canonical file changes, copy it again: a value that moved is a protocol
change, and the tests say which.
