#!/bin/sh
# Remove CIRIS installed by install.sh. Your data (CIRIS_HOME: keys, rooms,
# files) is NOT touched; delete it yourself if you mean to.
set -eu
prefix=${CIRIS_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/ciris}
bindir=${CIRIS_BINDIR:-$HOME/.local/bin}
apps=${XDG_DATA_HOME:-$HOME/.local/share}/applications
units=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now ciris.service 2>/dev/null || true
fi
rm -f "$units/ciris.service" "$apps/ciris.desktop"
# Only our own launcher: never a `ciris` someone else put there.
if [ -f "$bindir/ciris" ] && grep -q 'installers/desktop/linux' "$bindir/ciris"; then
  rm -f "$bindir/ciris"
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload 2>/dev/null || true
fi
[ -f "$prefix/payload.json" ] || { echo "uninstall.sh: $prefix holds no CIRIS payload; leaving it" >&2; exit 1; }
rm -rf "$prefix"
echo "CIRIS removed from $prefix. Your data in CIRIS_HOME is kept."
