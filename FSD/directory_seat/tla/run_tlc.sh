#!/bin/bash
# The directory seat under TLC: the main configurations close, and each planted twin fails on its own property.
#   bash tla/run_tlc.sh /path/to/tla2tools.jar [metadir]     (tla2tools 1.7.4, as the constitution's CI pins it)
# Prints one line per run and ok=N bad=M last; exits M.
cd "$(dirname "$0")"
JAR="${1:?tla2tools.jar}"; META="${2:-${RUNNER_TEMP:-/tmp}/dirseat-tlc}"
ok=0; bad=0
tlc(){ java -Xmx1200m -cp "$JAR" tlc2.TLC -workers 2 -metadir "$META/$1" -deadlock -config "$1.cfg" DirectorySeat.tla > "$META.$1.log" 2>&1; }
mkdir -p "$META"
for c in DirectorySeat DirectorySeat_byz; do
  tlc $c
  if grep -q "No error has been found" "$META.$c.log"; then ok=$((ok+1))
    echo "closes: $c $(grep -oE '[0-9]+ distinct states found, 0 states left' "$META.$c.log" | tail -1), depth $(grep -oE 'search is [0-9]+' "$META.$c.log" | grep -oE '[0-9]+')"
  else bad=$((bad+1)); echo "XX does not close: $c"; tail -30 "$META.$c.log"; fi
done
while read -r c prop; do
  tlc $c
  if grep -qE "Invariant $prop is violated|Temporal properties were violated" "$META.$c.log"; then ok=$((ok+1))
    echo "twin fails as it must: $c ($prop) after $(grep -cE '^State [0-9]+:' "$META.$c.log") states in the trace"
  else bad=$((bad+1)); echo "XX twin not caught: $c ($prop)"; tail -20 "$META.$c.log"; fi
done <<'T'
DirectorySeat_firstcome Inv_NoLockout
DirectorySeat_firstcome_live Prop_Registered
DirectorySeat_noderive Inv_NeverSwapped
DirectorySeat_seatauthority Inv_NoAuthority
DirectorySeat_serveowned Inv_OwnedRouteUnserved
DirectorySeat_noanchor Inv_RootIsAnchor
T
[ -n "${KEEP:-}" ] || rm -rf "$META" "$META".*.log
echo "ok=$ok bad=$bad"
exit $bad
