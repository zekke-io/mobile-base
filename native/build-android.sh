#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

android_min_sdk="${ANDROID_MIN_SDK:?ANDROID_MIN_SDK must be set}"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -z "$sdk_root" ] || [ -z "${ANDROID_NDK_VERSION:-}" ]; then
    echo "Set ANDROID_NDK_HOME, or ANDROID_HOME and ANDROID_NDK_VERSION." >&2
    exit 1
  fi
  ANDROID_NDK_HOME="$sdk_root/ndk/$ANDROID_NDK_VERSION"
fi
if [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "No NDK at $ANDROID_NDK_HOME: install it with sdkmanager \"ndk;${ANDROID_NDK_VERSION:-<version>}\"." >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) toolchain_host=linux-x86_64 ;;
  Darwin) toolchain_host=darwin-x86_64 ;;
  *) echo "Unsupported host: $(uname -s)" >&2; exit 1 ;;
esac
toolchain_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$toolchain_host/bin"

export AR="$toolchain_bin/llvm-ar"
export RANLIB="$toolchain_bin/llvm-ranlib"
strip_tool="$toolchain_bin/llvm-strip"

fetch_sources

build_abi() {
  local abi="$1" triple="$2"
  local cc="$toolchain_bin/$triple$android_min_sdk-clang"
  local cflags="-O2 -fPIC -fvisibility=hidden"
  local abi_dir="$NATIVE_BUILD_DIR/android/$abi"
  local output_dir="$NATIVE_BUILD_DIR/android/jniLibs/$abi"

  build_libsodium "$abi_dir/libsodium" "$triple" "$cc" "$cflags"
  compile_zekke_native_objects "$abi_dir/objects" "$abi_dir/libsodium" "$cc" "$cflags" "$NATIVE_DIR/src/zekke_native_jni.c"

  mkdir -p "$output_dir"
  "$cc" -shared -o "$output_dir/libzekke_native.so" \
    -Wl,-soname,libzekke_native.so \
    -Wl,--no-undefined \
    -Wl,--exclude-libs,ALL \
    -Wl,-z,max-page-size=16384 \
    "$abi_dir/objects/zekke_native_jni.o" "$abi_dir/objects/zekke_native.o" "$abi_dir/objects/mlkem_native.o" \
    "$abi_dir/libsodium/lib/libsodium.a"
  "$strip_tool" --strip-unneeded "$output_dir/libzekke_native.so"
}

build_abi arm64-v8a aarch64-linux-android
build_abi armeabi-v7a armv7a-linux-androideabi
build_abi x86_64 x86_64-linux-android

echo "$NATIVE_BUILD_DIR/android/jniLibs"
