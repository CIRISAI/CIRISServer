#!/usr/bin/env bash
# Build a CIRISServer Android abi3 wheel locally (NDK cross-compile), replicating
# the CI recipe in .github/workflows/build-wheels.yml (the `android` job) so the
# agent team can test the emulator/device fold without waiting for the PyPI
# publish. Builds from the CURRENT working tree — no commit/tag needed.
#
# Usage:
#   tools/build-android-wheel.sh                 # default: x86_64 (the emulator)
#   tools/build-android-wheel.sh arm64-v8a       # a real 64-bit device / arm emulator
#   tools/build-android-wheel.sh armeabi-v7a     # 32-bit device
#
# Prereqs (mostly already present on this box):
#   - Android NDK (set NDK below or export ANDROID_NDK_HOME)
#   - rustup targets: rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi
#   - pip install "maturin>=1.7,<2"
set -euo pipefail
cd "$(dirname "$0")/.."

ABI="${1:-x86_64}"
NDK="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/27.0.12077973}"
API=24

case "$ABI" in
  x86_64)      TARGET=x86_64-linux-android;    CLANG_TRIPLE=x86_64-linux-android${API};    LEGACY=x86_64-linux-android;    PW=64 ;;
  arm64-v8a)   TARGET=aarch64-linux-android;   CLANG_TRIPLE=aarch64-linux-android${API};   LEGACY=aarch64-linux-android;   PW=64 ;;
  armeabi-v7a) TARGET=armv7-linux-androideabi; CLANG_TRIPLE=armv7a-linux-androideabi${API};LEGACY=arm-linux-androideabi;   PW=32 ;;
  *) echo "unknown ABI '$ABI' (want: x86_64 | arm64-v8a | armeabi-v7a)"; exit 2 ;;
esac

TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
[ -x "$TC/bin/${CLANG_TRIPLE}-clang" ] || { echo "NDK clang not found: $TC/bin/${CLANG_TRIPLE}-clang (set ANDROID_NDK_HOME)"; exit 2; }
rustup target list --installed | grep -qx "$TARGET" || { echo "add the rust target: rustup target add $TARGET"; exit 2; }

TMP="$(mktemp -d)"

# 1. PyO3 cross config — abi3, no real libpython at build time.
CFG="$TMP/pyo3-android.config"
{
  echo "implementation=CPython"; echo "version=3.10"; echo "shared=false"
  echo "abi3=true"; echo "lib_name=python3.10"; echo "lib_dir="
  echo "executable="; echo "pointer_width=${PW}"; echo "build_flags="
  echo "suppress_build_script_link_lines=true"
} > "$CFG"
export PYO3_CONFIG_FILE="$CFG"

# 2. libpython3.10 stub so the link resolves (the real one comes from the agent's
#    Python runtime — Chaquopy — at load time on-device).
STUB="$TMP/python-stub"; mkdir -p "$STUB"
echo 'void __pystub(void){}' | \
  "$TC/bin/${CLANG_TRIPLE}-clang" -shared -nostdlib \
    -Wl,-soname,libpython3.10.so -o "$STUB/libpython3.10.so" -x c -

# 3. NDK toolchain env (cc-rs guesses wrong NDK clang names; point everything at
#    the real tools, as cargo-ndk would).
CLANG="$TC/bin/${CLANG_TRIPLE}-clang"
TUS="$(echo "$TARGET" | tr - _)"; TSC="$(echo "$TUS" | tr a-z A-Z)"
export "CC_${TUS}=${CLANG}"  "CXX_${TUS}=${CLANG}++"
export "AR_${TUS}=${TC}/bin/llvm-ar"  "RANLIB_${TUS}=${TC}/bin/llvm-ranlib"
export "CARGO_TARGET_${TSC}_LINKER=${CLANG}"
export ANDROID_NDK_ROOT="$NDK" ANDROID_NDK_HOME="$NDK" ANDROID_API_LEVEL="$API"
# openssl-src (pulled by persist on android) hardcodes legacy NDK tool names r26b+ dropped.
ln -sf "$TC/bin/llvm-ar"     "$TC/bin/${LEGACY}-ar"
ln -sf "$TC/bin/llvm-ranlib" "$TC/bin/${LEGACY}-ranlib"
ln -sf "$CLANG"              "$TC/bin/${LEGACY}-clang"
ln -sf "${CLANG}++"          "$TC/bin/${LEGACY}-clang++"
export PATH="$TC/bin:$PATH"
export RUSTFLAGS="-L ${STUB} -C link-arg=-Wl,--no-as-needed -C link-arg=-lpython3.10"

# 4. Build (no --strip locally — avoids the cached-rebuild 0-byte-.so gotcha; add
#    --strip for a smaller device wheel once you trust the target build is clean).
maturin build --release --out dist-android --target "$TARGET"
echo
echo "Built: dist-android/ (abi=${ABI}, target=${TARGET}, API=${API})"
ls -la dist-android/*android*_${ABI##*-}*.whl 2>/dev/null || ls -la dist-android/*.whl
