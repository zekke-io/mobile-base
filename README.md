# mobile-base

The Kotlin Multiplatform core both Zekke mobile apps share: the cryptographic basis, and in later
milestones the protocol, the API client, the replica and the item domains. **The plan, its rules
and its milestones are in [mobile/kotlin.md](../mobile/kotlin.md)**; this README describes what is built and how
to build it. Android consumes it as a Gradle module, iOS as an XCFramework.

It is the second implementation of the Zekke client protocol, after the web app's TypeScript. The
two never share code. They are bound by `api-general/docs/crypto/test-vectors.json`, which this
module reproduces, and later by interop tests against a live API.

## Where it stands

**Milestone K0: the Gradle project, the targets, CI, the two C libraries built from pinned
sources, and the primitives' interfaces.** K0 is done when every row of the primitives table passes
its vectors on all four targets.

| Target                          | Built | Vectors pass |
| ------------------------------- | ----- | ------------ |
| JVM (Linux x86_64)              | yes   | yes, 41 tests |
| Android 14, x86_64 emulator     | yes   | yes, the same 41 tests |
| Android, arm64 phone            | yes (`arm64-v8a`, `armeabi-v7a` too) | not yet run: needs a phone |
| iOS simulator, iOS arm64        | written, never compiled | not yet run: needs macOS |

The iOS source set (`ZekkeNativeCinterop`, the `cinterop` definition, `native/build-ios.sh`) has
not been compiled: Kotlin/Native cannot process a `cinterop` for Apple targets on a Linux host.
Until the `ios` CI job has run green on macOS, treat that code as unverified.

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
    commonMain/…/primitives   the interfaces, the cryptography-kotlin implementations, P256Scalar
    jniMain/…/primitives      ZekkeNativeJni, shared by the JVM and Android
    jvmMain, androidMain      the JDK provider and Bouncy Castle
    iosMain/…/primitives      ZekkeNativeCinterop, CryptoKit then CommonCrypto
    nativeInterop/cinterop    zekkeNative.def
    commonTest/…/primitives   the vector tests, run on every target
    commonTest/fixtures       test-vectors.json, a copy of api-general's
```

Packages are `zekke.core.<module>`, one per web-app module they port, each with its own
`README.md`. Only [`zekke.core.primitives`](src/commonMain/kotlin/zekke/core/primitives/README.md)
exists so far.

## Building and testing

This directory is the Gradle root. With a JDK 21, the Android SDK (API 36) and the NDK pinned in
`gradle/libs.versions.toml`:

```sh
./gradlew jvmTest                     # the vectors on the JVM
./gradlew assemble                    # the AAR, with the native code for every ABI
./gradlew connectedAndroidDeviceTest  # the vectors on a connected device or emulator
./gradlew iosSimulatorArm64Test       # the vectors on the iOS simulator (macOS)
./gradlew checkTestVectorsFixture     # the fixture still equals api-general's
```

A Linux machine without the Android toolchain can run all but the last two from
[`toolchain`](toolchain/README.md).

`jvmTest` builds the host library first and hands its path to the tests in the
`zekke.native.library` system property; on Android the library is loaded by name from the APK.

## The native libraries

Two C libraries are built from source rather than taken as wrappers, for the reasons in
[kotlin.md § Layer 1](../mobile/kotlin.md#layer-1--primitives):

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
| `kotlinx-serialization-json`        | tests only       | Reading the vector fixture                                               |

Every version is in `gradle/libs.versions.toml`. Kotlin warnings are errors.

## The vector fixture

`src/commonTest/fixtures/test-vectors.json` is a byte-for-byte copy of
`api-general/docs/crypto/test-vectors.json`. The build embeds it as a Kotlin constant
(`generateTestVectorsSource`) so every target, the emulator and the simulator included, reads the
same values without file access. `checkTestVectorsFixture` (part of `check`) fails when the copy
and api-general's file differ; when api-general is not checked out next to `mobile-base/` it says so
and passes. When api-general changes the file, copy it again: a value that moved is a protocol
change, and the tests say which.
