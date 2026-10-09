# Mobile build toolchain

A Docker image with everything the mobile Gradle build needs on Linux: JDK 21, the Android SDK
platform and build tools for API 36, and NDK r28c (`28.2.13676358`), the version
`gradle/libs.versions.toml` pins as `android-ndk`. It exists for machines that have no Android
toolchain installed. CI does not use it; the hosted runners install the same pieces themselves.

It cannot build the iOS targets. Those need Xcode, so they build only on macOS.

## Build the image

```sh
docker build -t zekke-mobile-toolchain mobile-base/toolchain
```

## Run the build in it

From `mobile-base/`, as your own user so the build directory stays yours, with a Gradle home kept
between runs:

```sh
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -e GRADLE_USER_HOME=/gradle-home -v "$HOME/.gradle-zekke-mobile:/gradle-home" \
  -v "$PWD:/workspace" zekke-mobile-toolchain \
  ./gradlew jvmTest assemble
```

The SDK inside the image is made readable by every user (`chmod -R a+rX`) because the build runs
as a non-root user and the NDK's compilers must be executable by it.

## Changing a version

The NDK version appears twice, here (`ANDROID_NDK`) and in `gradle/libs.versions.toml`
(`android-ndk`); they must match, or `buildAndroidNativeLibraries` will not find the NDK.
