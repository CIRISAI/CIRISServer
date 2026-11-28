#!/bin/sh
# CIRIS for Linux, per user (no root): installs the payload beside this script
# into ${CIRIS_PREFIX:-~/.local/share/ciris}, so the agent's in-place upgrade
# (payload.json upgrade_argv, the app's "Upgrade now") can write there.
#
#   ./install.sh                  install or replace
#   ./install.sh --enable-service also start CIRIS headless now and at login
#                                 (systemd --user unit ciris.service)
#
# Rules from the payload contract (CIRISAgent desktop-payload.yml):
#   - start CIRIS with payload.json's launch_argv, never python/bin/ciris-agent
#     (console scripts carry the build machine's interpreter path);
#   - never pass -I or -s (the payload's ciris-no-user-site.pth keeps the user
#     site out on every start);
#   - the unit's main process must BE the interpreter (no forking wrapper):
#     the agent's upgrade checks `systemctl --user show -p MainPID`.
# UNSIGNED for 2.24 (Eric 2026-11-27): there is no signature to check yet.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
prefix=${CIRIS_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/ciris}
bindir=${CIRIS_BINDIR:-$HOME/.local/bin}
apps=${XDG_DATA_HOME:-$HOME/.local/share}/applications
units=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
enable=0
for a in "$@"; do
  case "$a" in
    --enable-service) enable=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "install.sh: unknown option $a" >&2; exit 2 ;;
  esac
done

[ -f "$here/payload/payload.json" ] || { echo "install.sh: no payload/ beside this script" >&2; exit 1; }

# A running CIRIS from this prefix holds files open; stop the unit if it runs.
if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet ciris.service 2>/dev/null; then
  systemctl --user stop ciris.service
fi

mkdir -p "$prefix"
# Replace the interpreter tree whole: files pip added in an in-place upgrade must
# not mix with an older payload's.
rm -rf "$prefix/python" "$prefix/jre"
cp -a "$here/payload/." "$prefix/"
cp "$here/uninstall.sh" "$prefix/uninstall.sh"
chmod +x "$prefix/uninstall.sh"

interp="$prefix/python/bin/python3"
[ -x "$interp" ] || { echo "install.sh: $interp missing after copy" >&2; exit 1; }

# The command: exec the interpreter as launch_argv says (paths relative to the
# prefix, which holds payload.json).
mkdir -p "$bindir"
cat > "$bindir/ciris" <<EOF
#!/bin/sh
# CIRIS launcher (installers/desktop/linux): payload.json launch_argv.
cd "$prefix"
exec "$interp" -m ciris_engine.cli "\$@"
EOF
chmod +x "$bindir/ciris"

desktop=$("$interp" -c "import json;print(json.load(open('$prefix/payload.json')).get('desktop', False))")
if [ "$desktop" = "True" ]; then
  mkdir -p "$apps"
  cat > "$apps/ciris.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=CIRIS
Comment=Your CIRIS node, agent and app
Exec="$bindir/ciris"
Path=$prefix
Terminal=false
Categories=Network;Chat;
EOF
fi

mkdir -p "$units"
cat > "$units/ciris.service" <<EOF
[Unit]
Description=CIRIS (headless: node and agent API)
After=network-online.target

[Service]
Type=exec
WorkingDirectory=$prefix
ExecStart="$interp" -m ciris_engine.cli --adapter api
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload 2>/dev/null || true
  if [ "$enable" = 1 ]; then
    systemctl --user enable --now ciris.service
  fi
fi

version=$("$interp" -c "import json;d=json.load(open('$prefix/payload.json'));print(d['agent_version'], d['server_version'], d['client_version'])")
echo "CIRIS installed in $prefix (agent, server, client: $version)."
echo "Start it with: $bindir/ciris"
[ "$enable" = 1 ] || echo "Headless at login: systemctl --user enable --now ciris.service"
echo "Remove it with: $prefix/uninstall.sh (your data in CIRIS_HOME is kept)"
