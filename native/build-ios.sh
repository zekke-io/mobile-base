#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The iOS libraries need Xcode: build them on macOS." >&2
  exit 1
fi

ios_min_version="${IOS_MIN_VERSION:-16.0}"

fetch_sources

build_target() {
  local kotlin_target="$1" sdk="$2" version_flag="$3"
  local cc
  cc="$(xcrun --sdk "$sdk" -f clang)"
  local sysroot
  sysroot="$(xcrun --sdk "$sdk" --show-sdk-path)"
  local cflags="-O2 -arch arm64 -isysroot $sysroot $version_flag=$ios_min_version -fvisibility=hidden"
  local target_dir="$NATIVE_BUILD_DIR/ios/$kotlin_target.work"
  local output_dir="$NATIVE_BUILD_DIR/ios/$kotlin_target"

  AR="$(xcrun --sdk "$sdk" -f ar)" RANLIB="$(xcrun --sdk "$sdk" -f ranlib)" \
    build_libsodium "$target_dir/libsodium" arm-apple-darwin10 "$cc" "$cflags"
  compile_zekke_native_objects "$target_dir/objects" "$target_dir/libsodium" "$cc" "$cflags"

  mkdir -p "$output_dir"
  xcrun libtool -static -o "$output_dir/libzekke_native.a" \
    "$target_dir/objects/zekke_native.o" "$target_dir/objects/mlkem_native.o" \
    "$target_dir/libsodium/lib/libsodium.a"
}

build_target iosArm64 iphoneos -mios-version-min
build_target iosSimulatorArm64 iphonesimulator -mios-simulator-version-min

echo "$NATIVE_BUILD_DIR/ios"
