#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

if [ -z "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME must point to a JDK: the JNI headers come from it." >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) host_os=linux; library_name=libzekke_native.so; shared_flag=-shared ;;
  Darwin) host_os=darwin; library_name=libzekke_native.dylib; shared_flag=-dynamiclib ;;
  *) echo "Unsupported host: $(uname -s)" >&2; exit 1 ;;
esac

output_dir="$NATIVE_BUILD_DIR/jvm"
libsodium_dir="$output_dir/libsodium"
object_dir="$output_dir/objects"
cc="${CC:-cc}"
cflags="-O2 -fPIC -fvisibility=hidden"

fetch_sources
build_libsodium "$libsodium_dir" "" "$cc" "$cflags"

JNI_INCLUDES=(-I"$JAVA_HOME/include" -I"$JAVA_HOME/include/$host_os")
compile_zekke_native_objects "$object_dir" "$libsodium_dir" "$cc" "$cflags" "$NATIVE_DIR/src/zekke_native_jni.c"

"$cc" $shared_flag -o "$output_dir/$library_name" \
  "$object_dir/zekke_native_jni.o" "$object_dir/zekke_native.o" "$object_dir/mlkem_native.o" \
  "$libsodium_dir/lib/libsodium.a"

echo "$output_dir/$library_name"
