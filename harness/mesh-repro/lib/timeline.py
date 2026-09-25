#!/usr/bin/env python3
"""Build one timeline for a harness run from both nodes' own clocks.

Inputs (all in OUT_DIR, written by harness_timeline in the scenario):
  <svc>.log         `docker compose logs -t --no-color <svc>` (ANSI stripped)
  <svc>.started     the container's State.StartedAt (RFC 3339)
  <svc>.db.json     timestamp columns of the tables that carry the trace path
  ladder.txt        the ladder's own `[ladder HH:MM:SS]` samples (optional)

Prints, relative to the AGENT container's start (T0):
  1. milestones: first time / last time / count of each named log event, per node,
     sorted by first appearance, with the gap from the previous milestone;
  2. database: min / max of every timestamp column on the trace path, and the
     agent's trace attestations grouped by cohort_scope (sealed -> promoted);
  3. stage transitions: when each ladder rung first went non-zero;
  4. the phases that took longest, so the next optimization is named, not guessed.

Stdlib only. Nothing here decides pass/fail; it measures.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

OUT = sys.argv[1] if len(sys.argv) > 1 else "."

# (node, label, regex). The label is what the reader sees; the regex is matched
# against the ANSI-stripped message. Missing = never happened in this run, which
# is itself the finding.
MILESTONES = [
    ("agent", "read API bound (:4243)", r"read API up|lens read API listening"),
    ("agent", "split: node key minted", r"Minted and registered a separate node key"),
    ("agent", "signed transport binding published", r"published SIGNED self reticulum transport-tier binding"),
    ("agent", "WARN: transport binding NOT published", r"could not publish SIGNED self transport-destination"),
    ("canonical", "stopped dropping unattributed frames (last drop)", r"item 2 FAILED"),
    ("agent", "first-run claim (owner-binding persisted)", r"first-run ROOT claim|claim-remote: .*persist"),
    ("agent", "owner key record heal (#606)", r"#606\)"),
    ("agent", "actor anchored to owner", r"agent anchored to owner"),
    ("agent", "announce (owner-binding at federation)", r"announce COMPLETE|announce-self:"),
    ("agent", "owner accepts the root", r"trust root ACCEPTED BY THE OWNER"),
    ("agent", "allegiance carried", r"allegiance facts carried|allegiance carry"),
    ("agent", "consent grant authored", r"emitted directed replication-consent grant"),
    ("agent", "consent peers converged", r"converged to [1-9][0-9]* consent peers"),
    ("agent", "send-set resolved", r"send-set resolved"),
    ("agent", "edge: FIRST CONTACT only (no consent seen)", r"narrowed to FIRST CONTACT"),
    ("agent", "Rooted with the canonical", r"rooted_with: a valid root in common"),
    ("agent", "trace sealed", r"terminal outcome: .*sealed_and_persisted"),
    ("agent", "sweep promoted/widened rows", r"consent sweep: [1-9]|[1-9][0-9]* row\(s\) entered the mesh"),
    ("agent", "sweep: rows await their actor", r"await their actor"),
    ("agent", "envelopes served (non-zero)", r"envelopes_served_total\":[1-9]"),
    ("agent", "WARN: withheld", r" WARN .*withh[eo]ld"),
    ("agent", "WARN: refused / rejected", r" WARN .*(refus|reject)"),
    ("canonical", "read API bound (:4243)", r"read API up|lens read API listening"),
    ("canonical", "Rooted with the agent", r"rooted_with: a valid root in common"),
    ("canonical", "edge: FIRST CONTACT only toward the agent", r"narrowed to FIRST CONTACT"),
    ("canonical", "responder served a round", r"responder served an anti-entropy round"),
    ("canonical", "trace rows materialized", r"materializ\w* .*trace|trace_events .*(insert|admit)"),
    ("canonical", "summaries built", r"n_summaries=[1-9]"),
    ("canonical", "capacity score emitted", r"capacity scorer pass complete.*emitted=[1-9]"),
    ("canonical", "WARN: refused / rejected", r" WARN .*(refus|reject)"),
]

TS = re.compile(r"^(?:\S+\s+\|\s+)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s(.*)$")


def parse_ts(s):
    s = str(s).strip()
    if re.fullmatch(r"\d{9,19}(\.\d+)?", s):  # epoch seconds / ms / µs / ns
        v = float(s)
        while v > 1e11:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc)
    s = re.sub(r"^(\d{4}-\d{2}-\d{2}) ", r"\1T", s).replace("Z", "+00:00").replace(" UTC", "+00:00")
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})?$", s)
    if not m:
        return None
    frac = (m.group(2) or ".0")[:7]
    tz = m.group(3) or "+00:00"
    try:
        return datetime.fromisoformat(m.group(1) + frac + tz)
    except ValueError:
        return None


def fmt(dt, t0):
    if dt is None:
        return "—"
    return f"T+{(dt - t0).total_seconds():7.1f}s ({dt.strftime('%H:%M:%S')})"


def read(name):
    p = os.path.join(OUT, name)
    return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""


def main():
    t0 = parse_ts(read("agent.started")) or parse_ts(read("canonical.started"))
    if t0 is None:
        print("  (no container start time — timeline unavailable)")
        return
    starts = {svc: parse_ts(read(f"{svc}.started")) for svc in ("agent", "canonical")}
    print(f"  T0 = agent container start {t0.strftime('%Y-%m-%d %H:%M:%S')}Z; "
          f"canonical started {fmt(starts['canonical'], t0)}")

    # 1. milestones
    lines = {}
    for svc in ("agent", "canonical"):
        out = []
        for raw in read(f"{svc}.log").splitlines():
            m = TS.match(raw)
            if m:
                dt = parse_ts(m.group(1))
                if dt:
                    out.append((dt, m.group(2)))
        lines[svc] = out
    rows = []
    for svc, label, rx in MILESTONES:
        r = re.compile(rx)
        hits = [dt for dt, msg in lines.get(svc, []) if r.search(msg)]
        rows.append((hits[0] if hits else None, hits[-1] if hits else None, len(hits), svc, label))
    seen = sorted([r for r in rows if r[0]], key=lambda r: r[0])
    missing = [r for r in rows if not r[0]]
    print("\n  ── milestones (first seen; gap from the previous milestone) ──")
    prev = None
    for first, last, n, svc, label in seen:
        gap = f"+{(first - prev).total_seconds():6.1f}s" if prev else "        "
        span = f" … last {fmt(last, t0)}" if n > 1 else ""
        print(f"  {fmt(first, t0)}  {gap}  {svc:<9} {label}  ×{n}{span}")
        prev = first
    if missing:
        print("  never seen: " + "; ".join(f"{svc}:{label}" for _, _, _, svc, label in missing))

    # 2. database timestamps
    print("\n  ── database (each node's own row timestamps) ──")
    for svc in ("agent", "canonical"):
        try:
            db = json.loads(read(f"{svc}.db.json") or "{}")
        except json.JSONDecodeError:
            db = {}
        for key, val in db.items():
            if isinstance(val, dict) and "min" in val:
                print(f"  {svc:<9} {key:<55} n={val.get('n', '?'):<5} "
                      f"first {fmt(parse_ts(str(val['min'])) if val['min'] else None, t0)}  "
                      f"last {fmt(parse_ts(str(val['max'])) if val['max'] else None, t0)}")
            else:
                print(f"  {svc:<9} {key:<55} {val}")

    # 3. ladder rung transitions
    ladder = read("ladder.txt")
    first_nonzero = {}
    day = t0.date()
    for raw in ladder.splitlines():
        m = re.search(r"\[ladder (\d{2}:\d{2}:\d{2})\](.*)$", raw)
        if not m:
            continue
        dt = datetime.fromisoformat(f"{day}T{m.group(1)}+00:00")
        for idx, stage, val in re.findall(r"(\d+)\.(\w+)=(-?\d+)", m.group(2)):
            if int(val) > 0 and stage not in first_nonzero:
                first_nonzero[stage] = (int(idx), dt, int(val))
    if first_nonzero:
        print("\n  ── ladder rungs: first sample that read non-zero (15 s sampling) ──")
        for stage, (idx, dt, val) in sorted(first_nonzero.items(), key=lambda kv: kv[1][0]):
            print(f"  {idx:>2}. {stage:<10} {fmt(dt, t0)}  ={val}")

    # 4. the longest gaps between consecutive milestones
    gaps = []
    for (a, _, _, sa, la), (b, _, _, sb, lb) in zip(seen, seen[1:]):
        gaps.append(((b - a).total_seconds(), f"{sa}:{la} → {sb}:{lb}"))
    if gaps:
        print("\n  ── longest phases (where the wall clock went) ──")
        for secs, what in sorted(gaps, reverse=True)[:6]:
            print(f"  {secs:7.1f}s  {what}")


if __name__ == "__main__":
    main()
