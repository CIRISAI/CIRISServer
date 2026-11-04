"""Upgrading CIRIS while it runs (steward 2026-11-04: "We need to be able to handle
an upgrade while running, either detect an upgrade is happening and shut down, or
handle the upgrade elegantly").

On Windows a running process locks its own files, and pip replaces a package
one file at a time. So ``pip install -U`` over a running CIRIS fails part way
(``WinError 32``) and leaves ``~iris_*`` directories, a new client and server, and
a half-written agent; the next ``pip install -U`` "succeeds" and prints ``Ignoring
invalid distribution ~iris-agent`` for ever. pip's own guidance for this is to stop
what it is replacing first, and to run as ``python -m pip`` so no launcher of the
package is held open. So, in order of how much they can be relied on:

1. **Stop, then upgrade.** :func:`stop_for_upgrade` is the bounded stop an
   ``upgrade`` command calls before it hands over to pip.
2. **Hold nothing in site-packages.** :func:`private_jar` runs the desktop JAR
   from a per-version copy under ``CIRIS_HOME``, so the JVM locks no installed file.
3. **Notice an upgrade started by hand.** :func:`watch` sees pip's rename and
   asks the process to stop. Best effort: pip gives no warning, so by then it has
   already replaced some packages. A safety net, never the fix.
4. **Repair what is left.** :func:`doctor`, runnable from a broken install:

       python -m ciris_server.upgrade            # report
       python -m ciris_server.upgrade --repair   # clean up, print the pip command

A half-installed agent dies at import, before any of its code runs, so this has
to work with nothing else importable: standard library only, and
``ciris_server/__init__.py`` tolerates a broken native library for this one command.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

#: What pip renames a package to while it replaces it: `ciris_server` → `~iris_server`.
TILDE_GLOB = "~iris*"
#: The distributions of a CIRIS install, and the top-level packages each owns.
DISTRIBUTIONS: Dict[str, Tuple[str, ...]] = {
    "ciris_agent": ("ciris_engine", "ciris_adapters", "ciris_sdk"),
    "ciris_server": ("ciris_server",),
    "ciris_client": ("ciris_client",),
}
_VERSION = re.compile(r"(\d+(?:\.\d+)+)")


def site_packages() -> Path:
    """The directory this install lives in."""
    return Path(__file__).resolve().parent.parent


def version_key(name: str) -> Tuple[int, ...]:
    """The numeric version in a file name, for ordering: 0.5.237 beats 0.5.99."""
    found = _VERSION.findall(Path(name).stem)
    if not found:
        return ()
    return tuple(int(p) for p in found[-1].split("."))


def newest_jar(jars: Iterable[Path]) -> Optional[Path]:
    """The newest JAR by VERSION. A plain sort picks the OLDEST of 0.5.99 and
    0.5.100, and a repaired install has both on disk."""
    return max(jars, key=lambda p: (version_key(p.name), p.name), default=None)


def private_jar(jar: Path, home: Path) -> Path:
    """A copy of ``jar`` under ``home`` for the JVM to run, so it holds no file in
    site-packages. One directory per version; older copies are removed when
    nothing has them open. Falls back to ``jar`` if the copy cannot be made: a
    locked upgrade is a better failure than a UI that will not start."""
    dest_dir = Path(home) / "runtime" / "desktop"
    dest = dest_dir / jar.name
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        size = jar.stat().st_size
        if not dest.exists() or dest.stat().st_size != size:
            tmp = dest.with_suffix(f".{os.getpid()}.tmp")
            shutil.copyfile(jar, tmp)
            os.replace(tmp, dest)
        for old in dest_dir.glob("*.jar"):
            if old != dest:
                try:
                    old.unlink()
                except OSError:
                    pass  # An older UI is still running from it.
        return dest
    except OSError as e:
        print(f"ciris_server.upgrade: running the JAR in place ({e})", file=sys.stderr)
        return jar


def dist_versions(site: Path) -> Dict[str, str]:
    """``{distribution: version}`` from the ``.dist-info`` directories present."""
    out: Dict[str, str] = {}
    for d in site.glob("ciris_*.dist-info"):
        name, _, rest = d.name[: -len(".dist-info")].partition("-")
        out[name] = rest
    return out


def upgrade_started(site: Path, baseline: Dict[str, str]) -> Optional[str]:
    """Why an upgrade looks to be under way, or ``None``."""
    tilde = sorted(p.name for p in site.glob(TILDE_GLOB))
    if tilde:
        return f"pip is replacing {', '.join(tilde)}"
    now = dist_versions(site)
    for name, version in baseline.items():
        if now.get(name) != version:
            return f"{name} changed from {version} to {now.get(name, 'nothing')}"
    return None


def watch(
    on_upgrade: Callable[[str], None],
    site: Optional[Path] = None,
    interval_secs: float = 1.0,
) -> threading.Event:
    """Call ``on_upgrade(reason)`` once when an upgrade starts under this process.
    Start it BEFORE entering the node: a daemon thread, so it needs the serve call
    to have released the interpreter lock. Set the returned event to stop watching."""
    site = site or site_packages()
    baseline = dist_versions(site)
    stop = threading.Event()

    def run() -> None:
        while not stop.wait(interval_secs):
            reason = upgrade_started(site, baseline)
            if reason:
                on_upgrade(reason)
                return

    threading.Thread(target=run, name="ciris-upgrade-watch", daemon=True).start()
    return stop


def stop_for_upgrade(deadline_secs: float = 10.0) -> Dict[str, object]:
    """Stop the node in this process inside ``deadline_secs``: finish what is
    running, start nothing new, release the port. The caller exits afterwards.
    Being killed at the deadline loses only unacknowledged work (the node's crash
    tests kill it mid-write; every acknowledged write survives)."""
    import ciris_server

    start = time.monotonic()
    report: Dict[str, object] = {}
    background = getattr(ciris_server, "enter_background", None)
    if background is not None:
        report["background"] = dict(background(deadline_secs * 0.6))
    left = max(0.5, deadline_secs - (time.monotonic() - start))
    report["port_released"] = bool(ciris_server.shutdown_node(left))
    report["elapsed_secs"] = round(time.monotonic() - start, 2)
    return report


@dataclass
class DoctorReport:
    site: str
    tilde: List[str] = field(default_factory=list)
    #: A distribution with packages on disk and no ``.dist-info``, or whose RECORD
    #: names files that are gone.
    half_installed: Dict[str, str] = field(default_factory=dict)
    stale_jars: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    still_locked: List[str] = field(default_factory=list)
    pip_command: Optional[str] = None

    @property
    def healthy(self) -> bool:
        return not (self.tilde or self.half_installed or self.stale_jars or self.still_locked)


def _missing_from_record(site: Path, dist_info: Path) -> int:
    record = dist_info / "RECORD"
    if not record.exists():
        return 0
    missing = 0
    with record.open(newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("..") and not (site / row[0]).exists():
                missing += 1
    return missing


def _examine(site: Path) -> Tuple[Dict[str, str], List[Path]]:
    half: Dict[str, str] = {}
    installed = {d.name.split("-")[0]: d for d in site.glob("ciris_*.dist-info")}
    for dist, packages in DISTRIBUTIONS.items():
        present = [p for p in packages if (site / p).is_dir()]
        info = installed.get(dist)
        if info is None:
            if present:
                half[dist] = f"no .dist-info, but {', '.join(present)} on disk"
            continue
        gone = _missing_from_record(site, info)
        if gone:
            half[dist] = f"{gone} installed file(s) missing"
    stale: List[Path] = []
    groups: Dict[Path, List[Path]] = {}
    for jar in site.glob("ciris_*/**/CIRIS-*.jar"):
        groups.setdefault(jar.parent, []).append(jar)
    for jars in groups.values():
        keep = newest_jar(jars)
        stale.extend(j for j in jars if j != keep)
    return half, stale


def doctor(repair: bool = False, site: Optional[Path] = None) -> DoctorReport:
    """Report what an interrupted upgrade left, and with ``repair`` remove it.
    It never runs pip: that would need nothing of ours running, and only the person
    or an ``upgrade`` command knows that. ``pip_command`` says what finishes the job."""
    site = Path(site) if site else site_packages()
    half, stale = _examine(site)
    tilde = sorted(site.glob(TILDE_GLOB))
    rep = DoctorReport(
        site=str(site),
        tilde=[p.name for p in tilde],
        half_installed=half,
        stale_jars=[str(p) for p in stale],
    )
    if repair:
        for p in [*tilde, *stale]:
            try:
                shutil.rmtree(p) if p.is_dir() else p.unlink()
                rep.removed.append(str(p))
            except OSError:
                rep.still_locked.append(str(p))
    if half:
        names = " ".join(d.replace("_", "-") for d in sorted(half))
        rep.pip_command = f'"{sys.executable}" -m pip install --force-reinstall --no-deps {names}'
    return rep


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m ciris_server.upgrade",
        description="Find and repair what an interrupted CIRIS upgrade left behind.",
    )
    ap.add_argument("--repair", action="store_true", help="remove leftovers and stale JARs")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = doctor(repair=args.repair)
    if args.json:
        print(json.dumps({**asdict(rep), "healthy": rep.healthy}, indent=2))
    else:
        print(f"CIRIS install: {rep.site}")
        for name in rep.tilde:
            print(f"  leftover from an interrupted upgrade: {name}")
        for dist, why in rep.half_installed.items():
            print(f"  half-installed {dist}: {why}")
        for jar in rep.stale_jars:
            print(f"  old desktop JAR: {jar}")
        for path in rep.removed:
            print(f"  removed: {path}")
        for path in rep.still_locked:
            print(f"  STILL LOCKED, stop CIRIS and run this again: {path}")
        if rep.pip_command:
            print(f"Stop CIRIS, then finish the install with:\n  {rep.pip_command}")
        elif rep.healthy:
            print("  healthy")
    return 0 if rep.healthy or rep.removed and not rep.half_installed and not rep.still_locked else 1


if __name__ == "__main__":
    sys.exit(main())
