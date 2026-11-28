; CIRIS for Windows: the agent's desktop payload (CIRISAgent desktop-payload.yml)
; in an Inno Setup shell, per user, no administrator. Replaces the frozen
; installers once install, upgrade (2.23.2 -> next) and uninstall pass (Eric
; 2026-11-27); the frozen one cannot upgrade itself in place, this one can: the
; payload's own interpreter runs `ciris_engine.cli upgrade` into this prefix.
;
;   iscc /DPayloadDir=<staged payload> /DCirisVersion=2.24.0 /DServerVersion=0.5.255
;        /DClientVersion=0.5.244 /DOutputDir=<dir> ciris.iss
;
; Rules from the payload contract:
;   - start CIRIS with launch_argv: {app}\python\python.exe -m ciris_engine.cli,
;     never Scripts\ciris-agent.exe (pip wrote the build machine's path into it);
;   - never pass -I or -s (ciris-no-user-site.pth keeps the user site out).

#ifndef PayloadDir
  #error "PayloadDir is required (installers/desktop/stage.py --out)"
#endif
#ifndef CirisVersion
  #error "CirisVersion is required"
#endif
#ifndef ServerVersion
  #define ServerVersion "?"
#endif
#ifndef ClientVersion
  #define ClientVersion "?"
#endif
#ifndef OutputDir
  #define OutputDir "dist"
#endif

[Setup]
; One AppId for every version: a newer installer upgrades the older in place.
AppId={{6B0F7C2E-3C5D-4E1A-9B8F-C1E15CA7D255}
AppName=CIRIS
AppVersion={#CirisVersion}
AppVerName=CIRIS {#CirisVersion} (server {#ServerVersion}, client {#ClientVersion})
AppPublisher=CIRIS L3C
AppPublisherURL=https://ciris.ai
; Per user: the agent's in-place upgrade must be able to write the prefix.
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\CIRIS
DisableDirPage=auto
DefaultGroupName=CIRIS
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=CIRIS-Setup-{#CirisVersion}-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; A running CIRIS holds files in python\: ask Windows to close it first.
CloseApplications=yes
RestartApplications=no
UninstallDisplayName=CIRIS
UninstallDisplayIcon={app}\python\python.exe
; SIGNING: not yet (Eric 2026-11-27, 2.24 installers ship UNSIGNED for testing).
; When the Windows certificate exists, add here:
;   SignTool=cirissign
;   SignedUninstaller=yes
; and define `cirissign` on the iscc command line (/Scirissign=...).

[InstallDelete]
; Replace the interpreter tree whole: files pip added during an in-place
; upgrade must never mix with an older payload's.
Type: filesandordirs; Name: "{app}\python"
Type: filesandordirs; Name: "{app}\jre"

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\CIRIS"; Filename: "{app}\python\python.exe"; Parameters: "-m ciris_engine.cli"; WorkingDir: "{app}"; IconFilename: "{app}\python\python.exe"
Name: "{userdesktop}\CIRIS"; Filename: "{app}\python\python.exe"; Parameters: "-m ciris_engine.cli"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Put CIRIS on the desktop"; Flags: unchecked

[Run]
Filename: "{app}\python\python.exe"; Parameters: "-m ciris_engine.cli"; WorkingDir: "{app}"; Description: "Start CIRIS"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
; Everything under the prefix, including what in-place upgrades wrote. Your
; data (CIRIS_HOME: keys, rooms, files) is elsewhere and is kept.
Type: filesandordirs; Name: "{app}"
