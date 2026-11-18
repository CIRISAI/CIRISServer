#!/usr/bin/env python3
"""Code <-> model traceability gate for the directory seat.

Model side (tla/DirectorySeat.tla):
  \\* @trace action=<Name> impl=<module>::<fn> | env | plant
  \\* @trace op=<Name>     impl=<module>::<fn>
Code side (src/<module>.rs, guarded modules only):
  /// @tla <Name>              on the fn that implements <Name>
  /// @tla-none: <reason>      on a guarded fn that implements no action (listed in the table, reason required)
  /// @tla-inv <Inv_|Prop_...> on a #[test] that witnesses a model property

Fails (exit 1) when:
  1. a disjunct of Next names an action with no @trace tag;
  2. an impl= target has no fn, or its fn does not name the action back with @tla;
  3. a guarded fn carries neither @tla nor @tla-none (or @tla-none with no reason);
  4. a fn's @tla names an action/op that does not exist, or whose impl= points elsewhere;
  5. two model names claim one fn, or one name is claimed by two fns;
  6. an Inv_/Prop_ of the model is not checked by the main TLC config, or has no @tla-inv test.
Writes TRACE.md (the generated table) next to the crate.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent)
TLA = ROOT / "tla" / "DirectorySeat.tla"
CFG = ROOT / "tla" / "DirectorySeat.cfg"
GUARDED = ["seat", "client"]

errors = []
tla = TLA.read_text()

# ---- model side
tags = {}  # name -> (kind, target)  kind in action|op ; target = rust path | "env" | "plant"
for m in re.finditer(r"\\\* @trace (action|op)=(\w+) (impl=([\w:]+)|env|plant)", tla):
    kind, name, rest, path = m.groups()
    if name in tags:
        errors.append(f"model: {name} tagged twice")
    tags[name] = (kind, path if path else rest)

next_body = re.search(r"^Next ==(.*?)^\s*$", tla, re.S | re.M).group(1)
next_actions = set(re.findall(r"(\w+)\(", next_body))
defined = set(re.findall(r"^(\w+)\([^)]*\) ==", tla, re.M))
for a in sorted((next_actions & defined) - set(tags)):
    errors.append(f"model: action {a} appears in Next with no @trace tag")
for name, (kind, _) in tags.items():
    if kind == "action" and name not in next_actions:
        errors.append(f"model: tagged action {name} is not a disjunct of Next")

props = sorted(set(re.findall(r"^((?:Inv|Prop)_\w+) ==", tla, re.M)))
cfg = CFG.read_text()
for p in props:
    if not re.search(rf"\b{p}\b", cfg):
        errors.append(f"model: {p} is not checked by {CFG.name}")

# ---- code side
fns = {}      # path -> list of @tla names
nones = {}    # path -> reason
inv_tests = {}  # prop -> [test path]
for mod in GUARDED:
    src = (ROOT / "src" / f"{mod}.rs").read_text()
    in_tests = False
    pending, pending_none, pending_inv = [], None, []
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("mod tests"):
            in_tests = True
        if m := re.match(r"///\s*@tla-none:?\s*(.*)", s):
            pending_none = m.group(1).strip()
            continue
        if m := re.match(r"///\s*@tla-inv\s+(\w+)", s):
            pending_inv.append(m.group(1))
            continue
        if m := re.match(r"///\s*@tla\s+(\w+)", s):
            pending.append(m.group(1))
            continue
        if m := re.match(r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)", s):
            path = f"{mod}::{m.group(1)}"
            if in_tests:
                for p in pending_inv:
                    inv_tests.setdefault(p, []).append(path)
                if not pending_inv:
                    errors.append(f"code: test {path} names no model property (@tla-inv)")
            elif pending:
                fns[path] = pending
            elif pending_none is not None:
                if not pending_none:
                    errors.append(f"code: {path} has @tla-none with no reason")
                nones[path] = pending_none
            else:
                errors.append(f"code: guarded fn {path} carries neither @tla nor @tla-none")
            pending, pending_none, pending_inv = [], None, []

# ---- both directions
claimed = {}
for name, (kind, target) in tags.items():
    if target in ("env", "plant"):
        continue
    if target not in fns:
        errors.append(f"trace: {kind} {name} -> {target}: no annotated fn at that path")
    elif name not in fns[target]:
        errors.append(f"trace: {kind} {name} -> {target}, but that fn names {fns[target]}")
for path, names in fns.items():
    if len(names) > 1:
        errors.append(f"trace: {path} claims several model names {names} (one fn, one name)")
    for n in names:
        if n not in tags:
            errors.append(f"trace: {path} names {n}, which the model does not define")
        elif tags[n][1] != path:
            errors.append(f"trace: {path} names {n}, but the model says {n} is {tags[n][1]}")
        if n in claimed:
            errors.append(f"trace: {n} is claimed by {claimed[n]} and {path}")
        claimed[n] = path
for p in props:
    if p not in inv_tests:
        errors.append(f"trace: {p} has no Rust test carrying @tla-inv {p}")
for p in inv_tests:
    if p not in props:
        errors.append(f"trace: a test names {p}, which the model does not define")

# ---- table
rows = ["| Model name | Kind | Rust | Note |", "|---|---|---|---|"]
for name, (kind, target) in sorted(tags.items(), key=lambda kv: (kv[1][0], kv[0])):
    rust = f"`{target}`" if target not in ("env", "plant") else "-"
    note = {"env": "the world (node / adversary); not seat code", "plant": "planted break; must never exist"}.get(target, "")
    rows.append(f"| `{name}` | {kind} | {rust} | {note} |")
for path, why in sorted(nones.items()):
    rows.append(f"| - | none | `{path}` | {why} |")
rows += ["", "| Property | Witnessing tests |", "|---|---|"]
for p in props:
    rows.append(f"| `{p}` | {', '.join(f'`{t}`' for t in inv_tests.get(p, [])) or '**none**'} |")
(ROOT / "TRACE.md").write_text("# Traceability table (generated by scripts/trace_check.py)\n\n" + "\n".join(rows) + "\n")

if errors:
    print("\n".join(f"FAIL {e}" for e in errors))
    print(f"trace_check: {len(errors)} failure(s)")
    sys.exit(1)
print(f"trace_check: ok - {len(tags)} model names, {len(fns)} traced fns, {len(nones)} opted out, "
      f"{len(props)} properties each witnessed")
