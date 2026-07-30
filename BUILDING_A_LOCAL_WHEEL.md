# Building a CIRISServer wheel locally (skip the PyPI wait)

CIRISServer ships as a **PyO3 abi3 wheel** that CIRISAgent `pip install`s. You do
**not** have to wait for the tag→publish→PyPI pipeline to test a change — you can
build the identical wheel from a checkout in a couple of minutes and install it
straight into the agent's venv.

## One-time setup

```bash
pip install "maturin>=1.7,<2"          # the build backend (matches pyproject)
# Optional, only for a PORTABLE manylinux wheel (see "Two flavours" below):
pip install patchelf                    # or: apt-get install -y patchelf
```

That's it — `abi3` means one wheel covers CPython **3.10+**, and the substrate
crates (persist/edge/verify) build from the git tags pinned in `Cargo.lock`, so
there is nothing else to install.

## Build

From a CIRISServer checkout at the commit you want to test:

```bash
maturin build --release --out dist --compatibility linux
```

- `--release` — optimized, the same profile CI ships (a debug wheel also works and
  compiles faster if you just want a functional test: drop `--release`).
- `--compatibility linux` — tags the wheel `linux_x86_64` and **skips the
  manylinux repair**, so you do **not** need `patchelf`. The wheel dynamically
  links `libsqlite3.so.0`, which every real host already has. Perfect for local
  testing on the same machine/emulator family.
- The `extension-module` feature is applied automatically from `pyproject.toml`
  (`[tool.maturin] features = ["extension-module"]`) — don't pass `--features`.

Output, e.g.:

```
📦 Built wheel to dist/ciris_server-0.5.138-cp310-abi3-linux_x86_64.whl
```

First build compiles the whole workspace (~5 min). After that, only your changed
crate recompiles — a re-build is **~40 s**.

### ⚠️ Do NOT combine `--strip` with a cached rebuild

CI uses `--strip`, but on a *cached* local rebuild `--strip` can zero out the
`target/maturin/libciris_server.so` and produce a wheel whose `_native.abi3.so`
is **0 bytes** (imports, then segfaults/blank). For local iteration just omit
`--strip`. If you ever see a suspiciously tiny wheel, that's the tell — verify:

```bash
python3 -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); \
print({i.filename:i.file_size for i in z.infolist() if '_native' in i.filename})" \
dist/ciris_server-*.whl
# expect _native.abi3.so ≈ 100+ MB, NOT 0
```

## Install into the agent

```bash
# Force-replace whatever version is there (same version number won't upgrade otherwise):
pip install --force-reinstall --no-deps dist/ciris_server-*.whl
```

`--no-deps` keeps pip from touching the agent's other pins; `--force-reinstall`
overwrites an already-installed `0.5.x`. Then restart the agent/fold as usual.

### Sanity check before you wire it in

```bash
python -c "import ciris_server; print(ciris_server.__version__); \
print('serve:', hasattr(ciris_server,'serve_with_python_adapter'))"
# → 0.5.138 / serve: True
```

## Two flavours (when to use which)

| Goal | Command | Needs patchelf | Wheel tag |
|---|---|---|---|
| **Local test on this host/emulator** | `maturin build --release --out dist --compatibility linux` | no | `linux_x86_64` |
| **Portable wheel to hand around** (bundles libsqlite3) | `maturin build --release --strip --out dist` | yes | `manylinux_2_39_x86_64` |

The portable one is exactly what CI produces (`maturin build --release --strip
--out dist`). For turnaround testing, the `--compatibility linux` flavour is
faster and dependency-free.

## Other targets

- **aarch64 host**: same command on an arm64 box → `linux_aarch64`.
- **Android** (KMP client): CI cross-compiles with
  `maturin build --release --strip --out dist --target <android-target>` plus the
  Android NDK env (`build-wheels.yml`, the `android` job). Not needed for the
  desktop/emulator fold; use the native `--compatibility linux` build there.

## Why this is safe

The local wheel is byte-for-behaviour identical to the published one — same
`maturin`, same `Cargo.lock` substrate pins, same `pyproject`. The only
difference in the `--compatibility linux` flavour is that it links the host's
`libsqlite3` instead of bundling one, which is invisible to the agent at runtime.

---

# Android wheels (the emulator / mobile fold)

The filmstrip runs on an **`android_24 x86_64`** emulator, so it needs an Android
abi3 wheel — the desktop `--compatibility linux` build won't load there. This is
an NDK cross-compile; a helper script does the whole recipe:

```bash
tools/build-android-wheel.sh                # x86_64  → the emulator (default)
tools/build-android-wheel.sh arm64-v8a      # aarch64 → 64-bit device / arm emu
tools/build-android-wheel.sh armeabi-v7a    # 32-bit device
```

Output: `dist-android/ciris_server-<ver>-cp310-abi3-android_24_x86_64.whl`.

## One-time tooling

Already present on the build box, listed here for a fresh setup:

```bash
# Android NDK (r26b .. r27 all work; the script defaults to
# ~/Android/Sdk/ndk/27.0.12077973 — override with ANDROID_NDK_HOME=/path/to/ndk)
sdkmanager "ndk;27.0.12077973"

# Rust targets
rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi

pip install "maturin>=1.7,<2"
```

## What the script does (and why), in case you build by hand

- **PyO3 cross config** (`PYO3_CONFIG_FILE`) declaring `abi3=true`,
  `lib_name=python3.10`, `shared=false` — so pyo3 cross-compiles abi3 without a
  target-side CPython.
- A **libpython3.10 stub** `.so` to satisfy the link. The *real* `libpython3.10`
  is provided by the agent's on-device Python runtime (Chaquopy) at load time;
  the stub only exists to link, hence `RUSTFLAGS=-C link-arg=-lpython3.10` +
  `--no-as-needed`.
- NDK toolchain env: `CC_/CXX_/AR_/RANLIB_/CARGO_TARGET_*_LINKER` pointed at the
  real NDK clang (cc-rs guesses the wrong names), plus **legacy tool-name
  symlinks** because `openssl-src` (pulled in by persist on Android) hardcodes
  pre-r26b names.
- `maturin build --release --out dist-android --target <triple>`.

First build compiles the substrate for the Android target (~5 min); re-builds of
a changed crate are far faster.

## Install onto the emulator / device

The agent packages the wheel via its KMP client (Chaquopy jniLibs). For a quick
manual swap into a running agent's Python env, push and `pip install` inside the
app's environment, or drop it where the client's Chaquopy picks up
`ciris_server`. (The CI `android` job in `build-wheels.yml` is the source of
truth for the packaging path.)

## Verify (same gotcha as desktop)

```bash
python3 -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); \
print({i.filename:i.file_size for i in z.infolist() if '_native' in i.filename})" \
dist-android/ciris_server-*android_24_x86_64.whl
# expect _native.abi3.so ≈ 115 MB, NOT 0
file <(unzip -p dist-android/*android_24_x86_64.whl ciris_server/_native.abi3.so)
# → ELF 64-bit LSB shared object, x86-64 ... (Android: NEEDED liblog.so/libc.so, not glibc)
```

---

# Winning over PyPI: the `.post` repack (Chaquopy / `--find-links`)

If the local wheel has the **same version** as a wheel already on PyPI (e.g. you
built `0.5.138` locally but `0.5.138` is published), a resolver fed both via
`--find-links` (Chaquopy does this) will often pick the **PyPI** one — and you
silently test the published build, not your local change. Symptom: your new log
lines never appear on-device.

Fix: give the local wheel a **post-release** version so it strictly wins, without
minting a real release. Repack the wheel's `dist-info` (METADATA `Version:` +
the `dist-info` dir name + `RECORD` paths) from `X.Y.Z` → `X.Y.Z.post1`:

```bash
python3 - <<'PY'
import zipfile, os, tempfile
src="dist-android/ciris_server-0.5.138-cp310-abi3-android_24_x86_64.whl"
dst=src.replace("0.5.138","0.5.138.post1")
tmp=tempfile.mkdtemp()
with zipfile.ZipFile(src) as z: z.extractall(tmp)
di=[d for d in os.listdir(tmp) if d.endswith(".dist-info")][0]
meta=os.path.join(tmp,di,"METADATA")
open(meta,"w").write(open(meta).read().replace("Version: 0.5.138","Version: 0.5.138.post1",1))
newdi=di.replace("0.5.138","0.5.138.post1"); os.rename(os.path.join(tmp,di),os.path.join(tmp,newdi))
rec=os.path.join(tmp,newdi,"RECORD"); open(rec,"w").write(open(rec).read().replace(di,newdi))
with zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as z:
    for r,_,fs in os.walk(tmp):
        for f in fs: fp=os.path.join(r,f); z.write(fp,os.path.relpath(fp,tmp))
print("repacked ->",dst)
PY
```

`0.5.138.post1 > 0.5.138` in PEP 440, so `--find-links` picks the local wheel.
(A `.post` repack is a LOCAL test artifact only — it is never a release; the
`_native.abi3.so` is byte-identical, only `dist-info` metadata changed.)
