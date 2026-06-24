# Windows desktop installer (ciris-server)

A double-click installer for the CIRIS Server desktop: the local node (the
compiled Rust extension) + the Compose desktop UI, with no prerequisites.
`pip install -U ciris-server && ciris-server` is the lighter path; this is for
users who'd rather not touch Python.

## What it bundles

| Piece | Source | Lands at |
|-------|--------|----------|
| CPython + Rust node + launcher | PyInstaller `--onedir` of `ciris-server.spec` (after `pip install` of the maturin wheel) | `{app}\` |
| Compose desktop JAR | rides inside the wheel (`ciris_server/desktop_app/CIRIS-*.jar`); collected by the spec | `{app}\_internal\ciris_server\desktop_app\` |
| Trimmed JRE (~30 MB) | `bundle-jre.ps1` (jlink) | `{app}\runtime\` |

`desktop_launcher.find_java()` prefers `{app}\runtime` when frozen, so the
bundled JRE is used; `cli._spawn_headless_node()` re-invokes the frozen exe with
`--headless` for the node child (there is no `python -m` inside a frozen build).

## Files

- `ciris-server-entry.py` — PyInstaller entry (`ciris_server.cli:main`).
- `ciris-server.spec` — one-folder PyInstaller spec.
- `bundle-jre.ps1` — jlink trim of a JDK 17 into a minimal runtime. **Use a
  Win7-capable vendor (Liberica/Zulu) for the Win7 lane** — Temurin dropped Win7.
- `ciris-server-installer.iss` — Inno Setup wrapper. `/DCirisVersion=X.Y.Z`
  required; `/DWin7Tier` + `/DOutputSuffix=-win7` for the Win7 variant.

## Build (locally, on Windows)

```powershell
# 0. build + install the wheel (needs Rust + maturin), with the JAR staged first
cd client; .\gradlew :desktopApp:packageUberJarForCurrentOS
copy desktopApp\build\compose\jars\CIRIS-windows-*.jar ..\python\ciris_server\desktop_app\
cd ..; maturin build --release -o dist-wheel; pip install (Get-ChildItem dist-wheel\*.whl)
# 1. PyInstaller bundle
cd installers\windows; pyinstaller ciris-server.spec --noconfirm; mv dist\ciris-server ..\..\dist\
# 2. trimmed JRE
.\bundle-jre.ps1 -JarPath ..\..\client\desktopApp\build\compose\jars\CIRIS-windows-*.jar -OutputDir ..\..\dist\runtime
# 3. installer
iscc ciris-server-installer.iss /DCirisVersion=0.5.38
```

CI does all of this — see `.github/workflows/client-artifacts.yml`
(`windows-installer` job, Win8.1 floor) and `windows7-installer.yml` (the
experimental, dispatch-only Win7 variant with a patched CPython).

## Windows 7

Win7 SP1 is **unsupported / last-resort**: official CPython gates on Win8.1+, so
the Win7 variant bundles a community-patched interpreter (adang1345/PythonVista)
behind a fail-closed SHA256 check, and the node rides the Tier-3
`x86_64-win7-windows-msvc` build. The node runs at the software-key attestation
tier on Win7 (no TPM 2.0). KB2999226 (Universal CRT) is installed on first run if
absent.
