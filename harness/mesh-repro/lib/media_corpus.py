"""The file-transfer corpus: one file per type the node supports, at the sizes
that exercise the transfer's boundaries.

    python3 lib/media_corpus.py <outdir>        # writes the files + manifest.json

WHY A CORPUS. The self-files ladder proved one 40-byte `text/plain` file. File
transfer has to be predictable for EVERY type the node accepts and at every
size class the chunk path has: under and over the 1 MiB inline boundary, and a
multi-chunk file. A single small text file exercises none of that.

WHAT "SUPPORTED" MEANS HERE: the types `GET /v1/media/policy` names (tier A,
the tier B convert-at-sender and rasterise-on-node lists, tier C download) plus
`application/zip` and `application/octet-stream`, the honest "I don't know". Each
file carries the leading bytes the write gate sniffs (src/media_gate.rs), so
the gate accepts it as what it says. The rest is deterministic pseudo-random
payload: this is a TRANSFER corpus, not a decoder corpus, and a renderer
fixture would test something else.

DETERMINISTIC. Seeded per file, so a digest mismatch on the second device is a
transfer defect and never a fixture that changed between runs.
"""
from __future__ import annotations

import hashlib
import json
import random
import struct
import sys
from pathlib import Path

KIB = 1024
MIB = 1024 * 1024
#: The drive's inline boundary (`inline_max_bytes` in the media policy).
INLINE = 1 * MIB
#: What the seal adds to an inline blob (measured: 1,048,575 plaintext bytes
#: sealed to 1,048,611). Used ONLY to place fixtures either side of the band
#: CIRISEdge#687 describes; nothing here decides a transfer by it.
SEAL_OVERHEAD = 36

#: Rows that are KNOWN to fail, each naming its upstream issue. Both consumers
#: (tests/drive_crud.rs and the self-files ladder) require these to fail AS
#: DESCRIBED and turn red the moment one passes, so a fixed defect cannot stay
#: marked. Never add a row here to make a run green: add it only with an issue
#: that names the cause.
KNOWN_DEFECTS = {
    "inline_band": "CIRISEdge#687: files::publish picks inline by plaintext size and persist caps "
                   "the sealed size, so 1,048,541-1,048,576 bytes can never publish",
}


def _payload(seed: str, n: int) -> bytes:
    """`n` deterministic bytes. `random.Random(seed).randbytes` is stable across
    CPython versions for a given seed string."""
    if n <= 0:
        return b""
    return random.Random(seed).randbytes(n)


def _box(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + kind + body


def _ftyp(brand: bytes, name: str, size: int) -> bytes:
    head = _box(b"ftyp", brand + b"\x00\x00\x02\x00" + brand + b"isom")
    return head + _box(b"mdat", _payload(name, max(0, size - len(head) - 8)))


def _riff(form: bytes, name: str, size: int) -> bytes:
    body = form + _payload(name, max(0, size - 12))
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _prefixed(prefix: bytes, name: str, size: int, suffix: bytes = b"") -> bytes:
    return prefix + _payload(name, max(0, size - len(prefix) - len(suffix))) + suffix


def _text(name: str, size: int) -> bytes:
    # Several scripts, combining marks and an astral-plane character: a text
    # file that crosses byte-identically, not just an ASCII one.
    line = "CIRIS file transfer · résumé · Ελληνικά · 日本語 · עברית · 🗂️\n".encode()
    out = (line * (size // len(line) + 1))[:size]
    # Never cut a multi-byte sequence: trim back to a character boundary.
    while True:
        try:
            out.decode("utf-8")
            return out
        except UnicodeDecodeError:
            out = out[:-1]


# (name, media_type, filename, builder, size). Sizes are small except the
# boundary rows, which are what the transfer's size classes are about.
def _spec():
    return [
        # ── tier A: rendered inline ────────────────────────────────────────
        ("text", "text/plain", "notes — ünïcode.txt", lambda n, s: _text(n, s), 6 * KIB),
        ("jpeg", "image/jpeg", "photo.jpg",
         lambda n, s: _prefixed(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00", n, s, b"\xff\xd9"), 48 * KIB),
        ("png", "image/png", "screenshot.png",
         lambda n, s: _prefixed(b"\x89PNG\r\n\x1a\n", n, s), 40 * KIB),
        ("webp", "image/webp", "sticker.webp", lambda n, s: _riff(b"WEBPVP8L", n, s), 20 * KIB),
        ("gif", "image/gif", "loop.gif", lambda n, s: _prefixed(b"GIF89a", n, s, b"\x3b"), 30 * KIB),
        ("mp4", "video/mp4", "clip.mp4", lambda n, s: _ftyp(b"isom", n, s), 200 * KIB),
        ("m4a", "audio/mp4", "voice.m4a", lambda n, s: _ftyp(b"M4A ", n, s), 64 * KIB),
        ("mp3", "audio/mpeg", "song.mp3", lambda n, s: _prefixed(b"ID3\x04\x00\x00\x00\x00\x00\x00", n, s), 96 * KIB),
        # ── tier B: converted at the sender / rasterised on the node — the
        #    node still STORES and TRANSFERS what it is given ──────────────────
        ("heic", "image/heic", "IMG_0001.heic", lambda n, s: _ftyp(b"heic", n, s), 60 * KIB),
        ("avif", "image/avif", "art.avif", lambda n, s: _ftyp(b"avif", n, s), 24 * KIB),
        ("mov", "video/quicktime", "clip.mov", lambda n, s: _ftyp(b"qt  ", n, s), 80 * KIB),
        ("webm", "video/webm", "clip.webm", lambda n, s: _prefixed(b"\x1a\x45\xdf\xa3", n, s), 50 * KIB),
        ("ogg", "audio/ogg", "memo.ogg", lambda n, s: _prefixed(b"OggS\x00\x02", n, s), 30 * KIB),
        ("flac", "audio/flac", "track.flac", lambda n, s: _prefixed(b"fLaC", n, s), 70 * KIB),
        ("wav", "audio/wav", "take.wav", lambda n, s: _riff(b"WAVEfmt ", n, s), 44 * KIB),
        ("svg", "image/svg+xml", "diagram.svg",
         lambda n, s: b'<svg xmlns="http://www.w3.org/2000/svg"><!--'
         + _text(n, max(0, s - 60)).replace(b"--", b"- ") + b"--></svg>\n",
         8 * KIB),
        # ── tier C: download ────────────────────────────────────────────────
        ("pdf", "application/pdf", "contract (signed).pdf",
         lambda n, s: _prefixed(b"%PDF-1.7\n", n, s, b"\n%%EOF\n"), 120 * KIB),
        ("glb", "model/gltf-binary", "model.glb", lambda n, s: _prefixed(b"glTF\x02\x00\x00\x00", n, s), 36 * KIB),
        ("usdz", "model/vnd.usdz+zip", "scene.usdz", lambda n, s: _prefixed(b"PK\x03\x04", n, s), 36 * KIB),
        # ── containers and the honest unknown ───────────────────────────────
        ("zip", "application/zip", "archive.zip", lambda n, s: _prefixed(b"PK\x03\x04", n, s), 64 * KIB),
        ("bin", "application/octet-stream", "blob.bin",
         lambda n, s: _prefixed(b"\x00CIRIS-unknown\x00", n, s), 32 * KIB),
        # ── the size classes: either side of the inline boundary, and a file
        #    many chunks long (still under the 64 MiB whole-read cap) ─────────
        ("inline_edge", "video/mp4", "below-the-band.mp4",
         lambda n, s: _ftyp(b"isom", n, s), INLINE - SEAL_OVERHEAD),
        ("inline_band", "video/mp4", "just-under-1MiB.mp4", lambda n, s: _ftyp(b"isom", n, s), INLINE - 1),
        ("inline_over", "video/mp4", "just-over-1MiB.mp4", lambda n, s: _ftyp(b"isom", n, s), INLINE + 1),
        ("large", "video/mp4", "large-24MiB.mp4", lambda n, s: _ftyp(b"isom", n, s), 24 * MIB),
    ]


def generate(outdir: Path) -> list[dict]:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, media_type, filename, build, size in _spec():
        data = build(name, size)
        (outdir / name).write_bytes(data)
        manifest.append({
            "name": name,
            "media_type": media_type,
            "filename": filename,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            **({"known_defect": KNOWN_DEFECTS[name]} if name in KNOWN_DEFECTS else {}),
        })
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False))
    return manifest


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus")
    for row in generate(out):
        mark = f"  KNOWN DEFECT: {row['known_defect'].split(':')[0]}" if "known_defect" in row else ""
        print(f"  {row['name']:<13} {row['media_type']:<26} {row['size']:>10}  {row['sha256'][:16]}{mark}")
