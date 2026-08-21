#!/usr/bin/env bash
# test_logtail.sh — compile and exercise LogTail STANDALONE on the macOS
# toolchain (CIRISServer#473 / #464 codex sweep-5).
#
# ContentView.swift imports SwiftUI + the KMP `shared` module, so the file
# cannot be typechecked without the full app build. The LogTail block is
# Foundation-only BY CONTRACT (its marker comment says so); this script
# extracts it VERBATIM — the same source the app compiles, never a copy that
# can drift — appends a test harness, and runs it with swiftc. The extraction
# failing (markers moved, a non-Foundation import crept in) fails the job.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=iosApp/ContentView.swift
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The block is Foundation-only by contract but carries no import of its own —
# file-scope imports live at the top of ContentView.swift. The harness supplies
# the ONE import the contract permits.
echo "import Foundation" > "$WORK/logtail.swift"
awk '/^\/\/ ── LogTail ─/{f=1} f{print} /^\/\/ ── end LogTail ─/{f=0}' "$SRC" >> "$WORK/logtail.swift"
grep -q "enum LogTail" "$WORK/logtail.swift" || { echo "::error::LogTail block not found in $SRC — markers moved?"; exit 1; }
if grep -E "^import (SwiftUI|shared|UIKit)" "$WORK/logtail.swift"; then
  echo "::error::LogTail grew a non-Foundation dependency — the standalone gate exists to catch exactly this"; exit 1
fi

cat > "$WORK/main.swift" <<'SWIFT'
import Foundation

func fail(_ msg: String) -> Never { print("FAIL: \(msg)"); exit(1) }
let dir = FileManager.default.temporaryDirectory.appendingPathComponent("logtail-test-\(UUID().uuidString)")
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: dir) }

// 1. A LARGE file (well past the byte cap): the tail must be the true last
//    400 lines, every line complete, and the read must be fast (capped).
let big = dir.appendingPathComponent("big.log")
var lines: [String] = []
for i in 0..<400_000 { lines.append("line \(i) — padding padding padding padding padding") }
try! lines.joined(separator: "\n").write(to: big, encoding: .utf8)
let t0 = Date()
guard let tail = LogTail.tail(of: big) else { fail("big file returned nil") }
let elapsed = Date().timeIntervalSince(t0)
let got = tail.split(separator: "\n", omittingEmptySubsequences: false)
guard got.count == 400 else { fail("expected 400 lines, got \(got.count)") }
guard got.last == "line 399999 — padding padding padding padding padding" else { fail("last line wrong: \(got.last ?? "nil")") }
guard got.first == "line 399600 — padding padding padding padding padding" else { fail("first line wrong (partial-line trim broken?): \(got.first ?? "nil")") }
guard elapsed < 2.0 else { fail("capped read took \(elapsed)s — is it reading the whole file?") }

// 2. A file SMALLER than one window and shorter than maxLines: intact.
let small = dir.appendingPathComponent("small.log")
try! "alpha\nbeta\ngamma".write(to: small, encoding: .utf8)
guard LogTail.tail(of: small) == "alpha\nbeta\ngamma" else { fail("small file must come back intact") }

// 3. Empty file and missing file: nil, same verdict as the old !isEmpty guard.
let empty = dir.appendingPathComponent("empty.log")
try! Data().write(to: empty)
guard LogTail.tail(of: empty) == nil else { fail("empty file must be nil") }
guard LogTail.tail(of: dir.appendingPathComponent("missing.log")) == nil else { fail("missing file must be nil") }

// 4. Multibyte content across the window boundary must not crash or corrupt
//    the KEPT lines (the first partial line is dropped by design).
let uni = dir.appendingPathComponent("uni.log")
var ulines: [String] = []
for i in 0..<100_000 { ulines.append("行 \(i) — 🚀 ünïcode päddîng テスト") }
try! ulines.joined(separator: "\n").write(to: uni, encoding: .utf8)
guard let utail = LogTail.tail(of: uni) else { fail("unicode file returned nil") }
let ugot = utail.split(separator: "\n", omittingEmptySubsequences: false)
guard ugot.count == 400, ugot.last == "行 99999 — 🚀 ünïcode päddîng テスト" else { fail("unicode tail wrong: count=\(ugot.count) last=\(ugot.last ?? "nil")") }
guard !utail.unicodeScalars.contains("\u{FFFD}") else { fail("replacement char leaked into KEPT lines — partial-line trim must eat the mangled prefix") }

print("logtail: all 4 cases pass (capped read of 400k-line file in \(String(format: "%.3f", elapsed))s)")
SWIFT

swiftc -O "$WORK/logtail.swift" "$WORK/main.swift" -o "$WORK/logtail_test"
"$WORK/logtail_test"
