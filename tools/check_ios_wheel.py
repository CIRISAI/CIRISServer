#!/usr/bin/env python3
"""Verify an iOS wheel's PEP 730 tag against the Mach-O binary inside it.

A wheel filename is a PROMISE about a binary nobody opens. For every other
platform the promise is cheap to check by accident — a manylinux wheel that is
secretly a macOS build fails loudly on the first import, on the machine that
built it. iOS is the one platform where nothing on the build machine, and
nothing in CI, ever loads the artifact: the device that finds out is a phone,
after distribution.

The two ways to get it wrong are both silent and both one character apart:

1. **The sdk is wrong** — a device (`iphoneos`) binary shipped under an
   `iphonesimulator` tag, or the reverse. `pip` installs it happily; the
   simulator then refuses to load a Mach-O whose platform is `iOS` rather than
   `iOSSimulator`, and the CI job that was supposed to prove the app works
   reports a dyld error instead. `file(1)` will not tell you: both slices print
   `Mach-O 64-bit arm64 dynamically linked shared library`, byte-identically.
   The difference lives in a load command.

2. **The minimum version is a lie** — the tag says `ios_13_0`, the binary says
   `LC_BUILD_VERSION minos 14.0`. `pip` reads the TAG to decide the wheel is
   installable, so it installs on iOS 13 and the module fails at load. This is
   not hypothetical here: before this check existed, and with
   `IPHONEOS_DEPLOYMENT_TARGET` unset, our device slice carried a 10.0 floor and
   our simulator slice a 14.0 floor — from the same commit, in the same job.

So: open the wheel, read the load commands, and refuse a tag the binary does not
support.

Usage:
    tools/check_ios_wheel.py dist/ciris_server-*-ios_*.whl [...]
    tools/check_ios_wheel.py --self-test
"""

from __future__ import annotations

import re
import struct
import sys
import zipfile
from pathlib import Path

# Mach-O, 64-bit little-endian. The slices we ship are thin (one arch per
# wheel), so a fat header is a packaging mistake worth naming rather than
# silently walking.
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

CPU_TYPE = {0x0100000C: "arm64", 0x01000007: "x86_64", 0x0000000C: "arm"}

# `arm64` is the PEP 730 spelling; `aarch64` is the same machine under the name
# the Rust target triple uses. Normalising here keeps the gate from failing a
# CORRECT wheel over a synonym — the failure mode that gets a gate deleted.
ARCH_ALIASES = {"aarch64": "arm64", "amd64": "x86_64"}

LC_SYMTAB = 0x02
LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION = 0x32

# `platform` in LC_BUILD_VERSION (mach-o/loader.h).
PLATFORM = {
    1: "macOS",
    2: "iOS",
    3: "tvOS",
    4: "watchOS",
    5: "bridgeOS",
    6: "macCatalyst",
    7: "iOSSimulator",
    8: "tvOSSimulator",
    9: "watchOSSimulator",
    10: "driverKit",
}

# The sdk half of a PEP 730 tag, and the Mach-O platforms that satisfy it.
#
# `iphoneos` accepts LC_VERSION_MIN_IPHONEOS as well as LC_BUILD_VERSION
# platform=iOS: the older load command is what the linker emits for a device
# build with a low deployment target, and it carries the same meaning. There is
# no such legacy spelling for the simulator — a simulator slice ALWAYS carries
# LC_BUILD_VERSION platform=iOSSimulator — which is exactly why the two are not
# interchangeable and why a missing platform record is treated as a device
# build, never as a simulator one.
SDK_PLATFORMS = {
    "iphoneos": {"iOS"},
    "iphonesimulator": {"iOSSimulator"},
}

TAG_RE = re.compile(
    r"^(?P<dist>.+?)-(?P<version>.+?)-(?P<python>[^-]+)-(?P<abi>[^-]+)-"
    r"ios_(?P<major>\d+)_(?P<minor>\d+)_(?P<arch>.+?)_(?P<sdk>iphoneos|iphonesimulator)\.whl$"
)


class WheelProblem(Exception):
    """A wheel whose filename and contents disagree."""


def _version(raw: int) -> tuple[int, int, int]:
    """Mach-O packs a version as xxxx.yy.zz in 32 bits."""
    return (raw >> 16, (raw >> 8) & 0xFF, raw & 0xFF)


def probe_macho(data: bytes) -> dict:
    """Read arch, platform, minimum OS and exported symbols out of a Mach-O."""
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64) or magic in (0xBEBAFECA, 0xBFBAFECA):
        raise WheelProblem(
            "the extension is a FAT (universal) Mach-O. An iOS wheel names ONE "
            "arch and one sdk in its tag, so it must carry a thin slice — a fat "
            "binary means the tag can only be true about half of it."
        )
    if magic != MH_MAGIC_64:
        raise WheelProblem(f"not a 64-bit little-endian Mach-O (magic {magic:#x})")

    _, cputype, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    info: dict = {
        "arch": CPU_TYPE.get(cputype, f"cputype:{cputype:#x}"),
        "platform": None,
        "minos": None,
        "symbols": set(),
        # Scanned once here so the stripped-binary fallback below costs nothing
        # extra and reads the same bytes the loader will.
        "raw_has_pyinit": b"PyInit__native" in data,
    }

    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_BUILD_VERSION:
            plat, minos, _sdk, _n = struct.unpack_from("<IIII", data, off + 8)
            info["platform"] = PLATFORM.get(plat, f"platform:{plat}")
            info["minos"] = _version(minos)
        elif cmd == LC_VERSION_MIN_IPHONEOS and info["platform"] is None:
            ver, _sdk = struct.unpack_from("<II", data, off + 8)
            info["platform"] = "iOS"
            info["minos"] = _version(ver)
        elif cmd == LC_SYMTAB:
            _symoff, _nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
            # The string table, read as a whole and split on NUL. Cheaper and
            # far less error-prone than walking nlist_64 entries, and the only
            # question asked of it is whether a name is present.
            # Empty entries dropped: a STRIPPED binary has an LC_SYMTAB whose
            # string table is zero-length, and `b"".split(b"\x00")` is `[b""]` —
            # a truthy one-element set. Left in, it makes "the table is empty"
            # indistinguishable from "the table exists and lacks the symbol",
            # and the stripped-binary fallback below never runs.
            info["symbols"] = {
                n for n in data[stroff : stroff + strsize].split(b"\x00") if n
            }
        off += cmdsize

    if info["platform"] is None:
        raise WheelProblem(
            "no LC_BUILD_VERSION or LC_VERSION_MIN_IPHONEOS load command — the "
            "binary does not state which platform it targets, so no tag can be "
            "checked against it"
        )
    return info


def check_wheel(path: Path) -> list[str]:
    """Return the notes for a good wheel; raise `WheelProblem` for a bad one."""
    m = TAG_RE.match(path.name)
    if not m:
        raise WheelProblem(
            f"{path.name} is not a PEP 730 iOS wheel filename "
            "(expected …-ios_<major>_<minor>_<arch>_<iphoneos|iphonesimulator>.whl)"
        )
    want_sdk = m["sdk"]
    want_arch = m["arch"]
    want_min = (int(m["major"]), int(m["minor"]))

    with zipfile.ZipFile(path) as zf:
        sos = [n for n in zf.namelist() if n.endswith(".so") or n.endswith(".dylib")]
        if not sos:
            raise WheelProblem(
                "the wheel carries no compiled extension. An iOS wheel whose "
                "whole purpose is the native module is worse empty than absent: "
                "it installs, imports, and fails on the first call."
            )
        if len(sos) > 1:
            raise WheelProblem(f"expected exactly one extension, found {len(sos)}: {sos}")
        member = sos[0]
        info = probe_macho(zf.read(member))

    problems = []
    allowed = SDK_PLATFORMS[want_sdk]
    if info["platform"] not in allowed:
        other = "iphonesimulator" if want_sdk == "iphoneos" else "iphoneos"
        problems.append(
            f"tag says `{want_sdk}` but the binary is platform={info['platform']} "
            f"— this is an `{other}` build under an `{want_sdk}` tag. It will "
            f"install and then fail to load."
        )
    want_arch = ARCH_ALIASES.get(want_arch, want_arch)
    if ARCH_ALIASES.get(info["arch"], info["arch"]) != want_arch:
        problems.append(f"tag says arch `{want_arch}` but the binary is `{info['arch']}`")
    notes = []
    if info["minos"] is not None and info["minos"][:2] > want_min:
        got = ".".join(str(x) for x in info["minos"][:2])
        want = ".".join(str(x) for x in want_min)
        problems.append(
            f"tag claims iOS {want} but the binary's minimum is {got}. pip reads "
            f"the TAG, so this installs on iOS {want} and fails at load. Set "
            f"IPHONEOS_DEPLOYMENT_TARGET={want} for the build, or tag the wheel {got}."
        )
    elif info["minos"] is not None and info["minos"][:2] < want_min:
        # SAFE, and still worth saying. The binary runs everywhere the tag
        # admits, so nothing breaks — but the tag is the narrower promise, and a
        # floor nobody chose is usually a deployment target nobody set. Ours was
        # exactly that: device 10.0, simulator 14.0, same commit, same job.
        got = ".".join(str(x) for x in info["minos"][:2])
        want = ".".join(str(x) for x in want_min)
        notes.append(
            f"    note     binary supports iOS {got}, tag only claims {want} "
            f"(safe; tag is the narrower promise)"
        )
    # `--strip` can leave LC_SYMTAB empty while the module is still perfectly
    # exported through the dyld export trie — so an empty symbol table is not
    # evidence of a missing symbol, and treating it as such would red-flag every
    # stripped wheel we intend to ship. Fall back to the raw image, where the
    # trie stores the name as a string.
    if info["symbols"]:
        exported = b"_PyInit__native" in info["symbols"]
    else:
        exported = info["raw_has_pyinit"]
    if not exported:
        problems.append(
            "the extension does not export PyInit__native — `from ._native import *` "
            "would fail at import"
        )

    if problems:
        raise WheelProblem("; ".join(problems))

    minos = ".".join(str(x) for x in info["minos"][:2])
    return [
        f"{path.name}",
        f"    member   {member}",
        f"    platform {info['platform']}  arch {info['arch']}  minos {minos}",
        *notes,
    ]


def _self_test() -> int:
    """Prove the checker fails on the two mistakes it exists to catch.

    A gate that has only ever been run against good input is a gate nobody has
    tested. These build Mach-O headers by hand — no toolchain, no macOS — so the
    negative cases are exercised on every platform this repo's CI runs on.
    """
    import io
    import tempfile

    def stripped(platform: int, minos: tuple[int, int], with_pyinit: bool = True) -> bytes:
        """LC_SYMTAB present but EMPTY, as `--strip` leaves it; the export name
        (when present) lives in the trailing image the way the export trie does."""
        body = struct.pack("<IiiIIIII", MH_MAGIC_64, 0x0100000C, 0, 6, 2, 48, 0, 0)
        body += struct.pack(
            "<IIIIII", LC_BUILD_VERSION, 24, platform,
            (minos[0] << 16) | (minos[1] << 8), 0, 0,
        )
        body += struct.pack("<IIIIII", LC_SYMTAB, 24, 0, 0, 0, 0)
        return body + (b"\x00__TEXT\x00PyInit__native\x00" if with_pyinit else b"\x00__TEXT\x00")

    def macho(platform: int, minos: tuple[int, int], cputype: int = 0x0100000C,
              with_pyinit: bool = True) -> bytes:
        strtab = b"\x00" + (b"_PyInit__native\x00" if with_pyinit else b"_other\x00")
        # header + LC_BUILD_VERSION(24) + LC_SYMTAB(24), then the string table
        stroff = 32 + 24 + 24
        body = struct.pack("<IiiIIIII", MH_MAGIC_64, cputype, 0, 6, 2, 48, 0, 0)
        body += struct.pack(
            "<IIIIII", LC_BUILD_VERSION, 24, platform,
            (minos[0] << 16) | (minos[1] << 8), 0, 0,
        )
        body += struct.pack("<IIIIII", LC_SYMTAB, 24, 0, 0, stroff, len(strtab))
        assert len(body) == stroff, (len(body), stroff)
        return body + strtab

    def wheel(tmp: Path, name: str, blob: bytes) -> Path:
        p = tmp / name
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("ciris_server/_native.abi3.so", blob)
        p.write_bytes(buf.getvalue())
        return p

    DEVICE, SIM = 2, 7
    cases = [
        ("good device", "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         macho(DEVICE, (13, 0)), None),
        ("good simulator", "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphonesimulator.whl",
         macho(SIM, (13, 0)), None),
        ("device binary under a simulator tag",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphonesimulator.whl",
         macho(DEVICE, (13, 0)), "under an `iphonesimulator` tag"),
        ("simulator binary under a device tag",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         macho(SIM, (13, 0)), "under an `iphoneos` tag"),
        ("minos above the tag",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         macho(DEVICE, (14, 0)), "installs on iOS 13.0 and fails at load"),
        ("minos below the tag is SAFE, not an error",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         macho(DEVICE, (12, 0)), None),
        ("stripped wheel whose symtab is empty but IS exported",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         stripped(DEVICE, (13, 0)), None),
        ("stripped wheel that is genuinely missing the export",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         stripped(DEVICE, (13, 0), with_pyinit=False), "does not export PyInit__native"),
        ("aarch64 spelled in the tag is the same machine as arm64",
         "ciris_server-0.1-cp310-abi3-ios_13_0_aarch64_iphoneos.whl",
         macho(DEVICE, (13, 0)), None),
        ("wrong arch",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         macho(DEVICE, (13, 0), cputype=0x01000007), "arch `arm64` but the binary is `x86_64`"),
        ("no PyInit__native",
         "ciris_server-0.1-cp310-abi3-ios_13_0_arm64_iphoneos.whl",
         macho(DEVICE, (13, 0), with_pyinit=False), "does not export PyInit__native"),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for label, name, blob, expect in cases:
            p = wheel(tmp, name, blob)
            try:
                check_wheel(p)
                got = None
            except WheelProblem as e:
                got = str(e)
            if expect is None and got is not None:
                print(f"  ✗ {label}: expected PASS, got refusal: {got}")
                failures += 1
            elif expect is not None and (got is None or expect not in got):
                print(f"  ✗ {label}: expected a refusal mentioning {expect!r}, got {got!r}")
                failures += 1
            else:
                print(f"  ✓ {label}")
    print("self-test:", "PASS" if not failures else f"{failures} FAILED")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return _self_test()
    paths = [Path(a) for a in argv if not a.startswith("-")]
    if not paths:
        print(__doc__)
        return 2
    rc = 0
    for p in paths:
        try:
            for line in check_wheel(p):
                print(line)
            print("    ✓ tag matches the binary")
        except WheelProblem as e:
            print(f"::error::{p.name}: {e}")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
