#!/bin/bash
# The gate must fail on each planted drift. Copies the crate, plants one break at a time, expects exit 1.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ok=0; bad=0
plant() { # name, file, python-replace-expr
  T="$(mktemp -d)"; cp -r "$HERE/src" "$HERE/tla" "$HERE/scripts" "$T/"
  python3 - "$T/$2" "$3" "$4" <<'EOF'
import sys; p, old, new = sys.argv[1:4]; s = open(p).read()
assert old in s, f"plant anchor not found in {p}: {old!r}"; open(p, "w").write(s.replace(old, new, 1))
EOF
  out="$(python3 "$T/scripts/trace_check.py" "$T" 2>&1)"; rc=$?
  if [ $rc -ne 0 ]; then ok=$((ok+1)); echo "caught: $1 -> $(echo "$out" | grep -m1 FAIL)"; else bad=$((bad+1)); echo "XX missed: $1"; fi
  rm -rf "$T"
}
plant "an action loses its implementation"   src/seat.rs   "    /// @tla Admit
" ""
plant "a guarded fn with no action"           src/seat.rs   "    /// @tla Servable" "    pub fn rebind(&mut self) {}

    /// @tla Servable"
plant "a fn names an action the model lacks"  src/seat.rs   "/// @tla Sync" "/// @tla Gossip"
plant "the model moves an action elsewhere"   tla/DirectorySeat.tla "action=Admit impl=seat::admit_registration" "action=Admit impl=seat::admit"
plant "a new action in Next with no tag"      tla/DirectorySeat.tla "Next ==
" "Evict(s) == UNCHANGED vars

Next ==
    \\/ \\E s \\in Seats : Evict(s)
"
plant "a property no test witnesses"          src/client.rs "/// @tla-inv Inv_RootIsAnchor" "/// @tla-inv Inv_NodeNeverSwapped"
plant "an opt-out with no reason"             src/seat.rs   "/// @tla-none: fixed bytes" "/// @tla-none:
    // fixed bytes"
echo "caught=$ok missed=$bad"; exit $bad
