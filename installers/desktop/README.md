# CIRIS desktop installers

One installer per OS, for the whole stack: agent, server node and client app.
The agent builds the payload; the server wraps it (Eric, 2026-11-27).
Workflow: `.github/workflows/desktop-installers.yml`.

| Target | Shell | Lands at |
|---|---|---|
| windows-x86_64 | Inno Setup (`windows/ciris.iss`), per user, no administrator | `%LOCALAPPDATA%\Programs\CIRIS` |
| macos-arm64, macos-x86_64 | `CIRIS.app` in a `.dmg` (`macos/build_app.sh`) | `/Applications` or `~/Applications` |
| linux-x86_64, linux-aarch64 (headless) | tarball + `linux/install.sh` | `~/.local/share/ciris`, `~/.local/bin/ciris`, user unit `ciris.service` |

## The payload

`CIRISAgent/.github/workflows/desktop-payload.yml` builds, per target,
`ciris-payload-<ver>-<target>.{tar.zst,payload.json,payload.lock,SHA256SUMS}`:
python-build-standalone CPython 3.12 with ciris-agent, ciris-server and
ciris-client from one hash-locked lock, and a jlinked JRE (`jre/`, desktop only).
`stage.py` checks every file against SHA256SUMS and unpacks the archive into the
prefix. `payload.json` is the install's marker: versions, interpreter,
`launch_argv`, `upgrade_argv` (paths relative to the directory holding it).

## Rules every shell follows

1. **Start CIRIS with `launch_argv`** (`python -m ciris_engine.cli`). Never the
   payload's `ciris-agent` console script: pip wrote the build machine's
   interpreter path into it.
2. **Never pass `-I` or `-s`.** The payload's `ciris-no-user-site.pth` keeps the
   user's own site-packages out; without it an upgrade uninstalled packages from
   `~/.local`.
3. **Replace the interpreter tree whole** on reinstall (`python/`, `jre/`): files
   an in-place upgrade added must not mix with an older payload's.
4. **The prefix is the user's to write**, so "Upgrade now" (`upgrade_argv`) works
   without administrator rights.
5. **The user's data is never touched** by install or uninstall: it lives in
   `CIRIS_HOME`, outside the prefix.
6. **Linux headless runs as the unit's main process:**
   `ExecStart=<interp> -m ciris_engine.cli --adapter api`, `Type=exec`, no
   wrapper that forks. The agent's upgrade checks `systemctl --user show -p
   MainPID` and stops and starts `ciris.service` itself.

## Unsigned (2.24)

The 2.24 installers are unsigned for testing (Eric, 2026-11-27). Windows shows
SmartScreen's "unknown publisher"; macOS needs right-click > Open the first
time. Each shell has a marked `SIGNING` place for the Windows certificate and the
Apple Developer ID (codesign, notarize, staple).

## Retiring the frozen installers

`installers/windows/` (PyInstaller-frozen server) and the agent's
`build-windows-installer` cannot upgrade in place. They retire once this
workflow passes install, upgrade (2.23.2 to next) and uninstall on Windows.
