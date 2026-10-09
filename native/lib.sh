#!/usr/bin/env bash
set -euo pipefail

NATIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_BUILD_DIR="${NATIVE_BUILD_DIR:-$NATIVE_DIR/../build/native}"
DOWNLOAD_DIR="$NATIVE_BUILD_DIR/download"
SOURCE_DIR="$NATIVE_BUILD_DIR/src"

source "$NATIVE_DIR/sources.env"

LIBSODIUM_SOURCE="$SOURCE_DIR/libsodium-$LIBSODIUM_VERSION"
MLKEM_NATIVE_SOURCE="$SOURCE_DIR/mlkem-native-$MLKEM_NATIVE_VERSION"

MLKEM_DEFINES=(
  -DMLK_CONFIG_PARAMETER_SET=768
  -DMLK_CONFIG_NAMESPACE_PREFIX=zekke_mlkem768
  -DMLK_CONFIG_NO_RANDOMIZED_API
)

JNI_INCLUDES=()

PARALLEL_JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

fetch_verified() {
  local url="$1" expected_sha256="$2" archive="$DOWNLOAD_DIR/$3"
  mkdir -p "$DOWNLOAD_DIR"
  if [ ! -f "$archive" ]; then
    curl -fsSL -o "$archive.partial" "$url"
    mv "$archive.partial" "$archive"
  fi
  local actual_sha256
  actual_sha256="$(sha256_of "$archive")"
  if [ "$actual_sha256" != "$expected_sha256" ]; then
    rm -f "$archive"
    echo "SHA-256 mismatch for $url: expected $expected_sha256, got $actual_sha256" >&2
    exit 1
  fi
}

fetch_sources() {
  mkdir -p "$SOURCE_DIR"
  if [ ! -f "$LIBSODIUM_SOURCE/configure" ]; then
    fetch_verified "$LIBSODIUM_URL" "$LIBSODIUM_SHA256" "libsodium-$LIBSODIUM_VERSION.tar.gz"
    tar -xzf "$DOWNLOAD_DIR/libsodium-$LIBSODIUM_VERSION.tar.gz" -C "$SOURCE_DIR"
  fi
  if [ ! -f "$MLKEM_NATIVE_SOURCE/mlkem/mlkem_native.c" ]; then
    fetch_verified "$MLKEM_NATIVE_URL" "$MLKEM_NATIVE_SHA256" "mlkem-native-$MLKEM_NATIVE_VERSION.tar.gz"
    tar -xzf "$DOWNLOAD_DIR/mlkem-native-$MLKEM_NATIVE_VERSION.tar.gz" -C "$SOURCE_DIR"
  fi
}

build_libsodium() {
  local install_dir="$1" host="$2" cc="$3" cflags="$4"
  if [ -f "$install_dir/lib/libsodium.a" ]; then
    return
  fi
  local work_dir="$install_dir.work"
  rm -rf "$work_dir"
  mkdir -p "$work_dir"
  (
    cd "$work_dir"
    local host_argument=()
    if [ -n "$host" ]; then
      host_argument=(--host="$host")
    fi
    CC="$cc" CFLAGS="$cflags" "$LIBSODIUM_SOURCE/configure" \
      ${host_argument[@]+"${host_argument[@]}"} \
      --prefix="$install_dir" \
      --disable-shared \
      --enable-static \
      --with-pic \
      --disable-dependency-tracking \
      --disable-soname-versions \
      >configure.log
    make -j"$PARALLEL_JOBS" install >make.log
  )
  rm -rf "$work_dir"
}

compile_zekke_native_objects() {
  local object_dir="$1" libsodium_dir="$2" cc="$3" cflags="$4"
  shift 4
  local extra_sources=("$@")
  mkdir -p "$object_dir"
  "$cc" $cflags -std=c99 -c "${MLKEM_DEFINES[@]}" \
    -I"$MLKEM_NATIVE_SOURCE/mlkem" \
    "$MLKEM_NATIVE_SOURCE/mlkem/mlkem_native.c" -o "$object_dir/mlkem_native.o"
  "$cc" $cflags -std=c99 -Wall -Wextra -Werror -c "${MLKEM_DEFINES[@]}" \
    -I"$MLKEM_NATIVE_SOURCE/mlkem" \
    -I"$libsodium_dir/include" \
    -I"$LIBSODIUM_SOURCE/src/libsodium/crypto_pwhash/argon2" \
    "$NATIVE_DIR/src/zekke_native.c" -o "$object_dir/zekke_native.o"
  local source
  for source in ${extra_sources[@]+"${extra_sources[@]}"}; do
    "$cc" $cflags -std=c99 -Wall -Wextra -Werror -c \
      -I"$NATIVE_DIR/src" \
      ${JNI_INCLUDES[@]+"${JNI_INCLUDES[@]}"} \
      "$source" -o "$object_dir/$(basename "${source%.c}").o"
  done
}
