# PyInstaller spec for ciris-server on Windows (one-folder / --onedir).
#
# Produces dist/ciris-server/ciris-server.exe + its dependencies. One-folder is
# deliberate (one-file unpacks to %TEMP% each run: slow start, AV false
# positives, and it breaks the relative paths the launcher uses to find the
# bundled desktop JAR and the trimmed JRE).
#
# The payload is tiny by Python standards: ciris_server is a thin launcher over
# the compiled Rust extension (ciris_server._native, abi3) and the stdlib —
# there are NO third-party Python deps (the node is all Rust). The desktop JAR
# rides inside the wheel (ciris_server/desktop_app/CIRIS-*.jar) and is collected
# below; the Inno Setup wrapper adds the trimmed JRE.
#
# Build (after `pip install` of the maturin-built ciris-server wheel):
#     cd installers\windows
#     pyinstaller ciris-server.spec --noconfirm

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

block_cipher = None

# The launcher package + the compiled abi3 extension.
hiddenimports = collect_submodules("ciris_server")
hiddenimports += ["ciris_server._native"]

# Grab the compiled _native.<abi3>.pyd and the per-platform desktop JAR that the
# wheel bundles under ciris_server/desktop_app/.
binaries = collect_dynamic_libs("ciris_server")
datas = collect_data_files("ciris_server", includes=["desktop_app/CIRIS-*.jar"])

a = Analysis(
    ["ciris-server-entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Trim heavyweight modules PyInstaller may pull transitively but the thin
    # launcher never uses.
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "scipy",
        "pandas",
        "PIL",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ciris-server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX trips Windows Defender false positives
    console=True,  # the node prints rich startup output; users want to see it
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # TODO: CIRIS .ico once branding is finalized
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ciris-server",
)
