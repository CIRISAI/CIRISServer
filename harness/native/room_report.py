"""Read one or more `big_room` run directories and say where the time went.

    python -m harness.native.room_report <run-dir> [<run-dir> ...] [--csv]

Per run: the verdict, each phase's wall time, each seat broken into its
parts (invitation listed, each member's decision seen, seated), each
newcomer's history read with its per-message first-read times, and the
node-log events that explain a slow or failed wait (seat grants, responder
backpressure, closed channels), all on one UTC timeline.

Writes `<run-dir>/timeline.tsv` (every step, wait and node-log event, sorted
by time) and, with `--csv`, `<run-dir>/waits.csv`. Several runs also print a
phase table side by side, so a slow phase is told from a slow run.
"""
from __future__ import annotations

import csv
import json
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ANSI = re.compile(r"\x1b\[[0-9;]*m")
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(\w+)\s+(\S+?):?\s+(.*)$")

#: Node-log lines worth putting on the timeline, by the name the report gives them.
EVENTS: Dict[str, re.Pattern[str]] = {
    "seat_grant": re.compile(r"room seat: members' devices hold this node's room key"),
    "seat_door_failed": re.compile(r"room seat: the seat door failed"),
    "inbox_full": re.compile(r"Responder inbox full while its driver was"),
    "channel_closed": re.compile(r"channel closed before response"),
    "not_granted": re.compile(r"not_granted"),
    "panic": re.compile(r"panicked at"),
}

PHASES = ("booted", "claimed_announced_consented", "owner_keys_held", "contacts_added", "resolved",
          "everyone_reads_everything", "takedown:everywhere", "reversal:everywhere")


def _t(s: str) -> datetime:
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def _lines(p: Path) -> Iterable[str]:
    try:
        with p.open(errors="replace") as f:
            for line in f:
                yield ANSI.sub("", line.rstrip("\n"))
    except FileNotFoundError:
        return


def load(run: Path) -> Dict[str, Any]:
    rep = json.loads((run / "report.json").read_text())
    return rep.get("result") or rep


def node_events(run: Path, start: datetime, end: datetime) -> List[Tuple[datetime, str, str, str]]:
    out: List[Tuple[datetime, str, str, str]] = []
    for node in sorted(p for p in run.iterdir() if p.is_dir()):
        for line in _lines(node / "node.log"):
            for name, pat in EVENTS.items():
                if pat.search(line):
                    m = STAMP.match(line)
                    if not m:
                        break
                    at = _t(m.group(1))
                    if start <= at <= end:
                        out.append((at, node.name, name, m.group(4)[:160]))
                    break
    return out


def report(run: Path, write_csv: bool) -> Dict[str, float]:
    res = load(run)
    steps: List[Dict[str, Any]] = res.get("steps") or []
    waits: List[Dict[str, Any]] = res.get("waits") or []
    vals = res.get("values") or {}
    print(f"== {run.name}: {res.get('verdict')}  people={vals.get('ROOM_N')} contacts="
          f"{vals.get('ROOM_CONTACTS')} limit={vals.get('ROOM_LIMIT')} wall={vals.get('WALL_S')}s"
          f"  first_failure={(res.get('first_failure') or {}).get('step')}")
    if res.get("error"):
        print(f"   error: {str(res['error'])[:300]}")
    phases: Dict[str, float] = {}
    for s in steps:
        if s.get("step") in PHASES and "seconds" in s:
            phases[s["step"]] = float(s["seconds"])
    print("   phases: " + "  ".join(f"{k}={v:.0f}s" for k, v in phases.items()))

    # Each seat, by part.
    seats: Dict[str, List[Dict[str, Any]]] = {}
    for w in waits:
        if w.get("phase") == "seat":
            seats.setdefault(w["who"], []).append(w)
    for s in steps:
        name = str(s.get("step", ""))
        if name.startswith("seated:"):
            who = name.split(":", 1)[1]
            parts = "  ".join(
                f"{w.get('part')}{'@' + w['by'] if w.get('by') else ''}={w['s']:.0f}s"
                for w in seats.get(who, []))
            hist = next((x for x in steps if x.get("step") == f"history:{who}"), {})
            phases[f"seat:{who}"] = float(s.get("seat_s") or 0)
            phases[f"read:{who}"] = float(hist.get("read_s") or 0)
            print(f"   {who:8} seat={s.get('seat_s')}s [{parts}]  read={hist.get('read_s')}s "
                  f"first_reads={hist.get('first_read_s')}")
    slow = sorted((w for w in waits if w.get("phase") in ("contact_add", "contact_resolve")),
                  key=lambda w: -w["s"])[:3]
    if slow:
        print("   slowest contact waits: " + "; ".join(f"{w['what']} {w['s']:.0f}s" for w in slow))
    failed = [w for w in waits if not w.get("ok")]
    for w in failed:
        print(f"   TIMED OUT: {w['what']} after {w['s']:.0f}s ({w['polls']} polls) from {w['start']}")

    # One timeline: steps, waits (at their end) and node-log events.
    stamps = [_t(s["at"]) for s in steps if s.get("at")]
    if stamps:
        start, end = min(stamps) - timedelta(seconds=120), max(stamps) + timedelta(seconds=5)
        rows: List[Tuple[datetime, str, str, str]] = [(_t(s["at"]), "harness", "step", s["step"])
                                                      for s in steps if s.get("at")]
        for w in waits:
            t0 = _t(w["start"])
            rows.append((t0 + timedelta(seconds=w["s"]), "harness", "wait" if w.get("ok") else "TIMEOUT",
                         f"{w['what']} ({w['s']}s)"))
        ev = node_events(run, start, end)
        rows += ev
        rows.sort(key=lambda r: r[0])
        with (run / "timeline.tsv").open("w") as f:
            f.write("at\tsource\tkind\tdetail\n")
            for at, src, kind, detail in rows:
                f.write(f"{at.isoformat(timespec='milliseconds')}\t{src}\t{kind}\t{detail}\n")
        counts: Dict[str, int] = {}
        for _, _, kind, _ in ev:
            counts[kind] = counts.get(kind, 0) + 1
        print("   node events in the run: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                                               or "none") + f"   (timeline: {run / 'timeline.tsv'})")
    if write_csv and waits:
        keys = sorted({k for w in waits for k in w})
        with (run / "waits.csv").open("w", newline="") as f:
            wr = csv.DictWriter(f, fieldnames=keys)
            wr.writeheader()
            wr.writerows(waits)
    return phases


def main(argv: List[str]) -> int:
    write_csv = "--csv" in argv
    runs = [Path(a) for a in argv if not a.startswith("--")]
    if not runs:
        print(__doc__)
        return 2
    table: Dict[str, Dict[str, float]] = {}
    for r in runs:
        try:
            table[r.name] = report(r, write_csv)
        except FileNotFoundError:
            print(f"== {r.name}: no report.json")
    if len(table) > 1:
        keys: List[str] = []
        for ph in table.values():
            keys += [k for k in ph if k not in keys]
        print("\n   phase (s)".ljust(34) + "".join(n[-10:].rjust(11) for n in table) + "     median")
        for k in keys:
            vals = [table[n].get(k) for n in table]
            have = [v for v in vals if v is not None]
            med = statistics.median(have) if have else None
            print(f"   {k:30}" + "".join(("-" if v is None else f"{v:.0f}").rjust(11) for v in vals)
                  + (f"{med:11.0f}" if med is not None else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
