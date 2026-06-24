; Inno Setup script for the Windows ciris-server desktop installer.
;
; Bundles two things into one .exe:
;   1. dist\ciris-server\  — the PyInstaller --onedir bundle: CPython + the
;      compiled Rust node (ciris_server._native) + the launcher. The per-platform
;      Compose desktop JAR rides INSIDE this bundle (the wheel carries it under
;      ciris_server/desktop_app/, and ciris-server.spec collects it), so no
;      separate JAR Files entry is needed.
;   2. dist\runtime\ — a trimmed JRE from bundle-jre.ps1 (~30 MB). find_java()
;      in desktop_launcher.py prefers a frozen-adjacent <app>\runtime, so the
;      desktop "just works" with no system Java.
;
; Per-user install (no admin / UAC). Install location: %LOCALAPPDATA%\CIRISServer.
; bare ciris-server.exe = desktop mode (node + UI).
;
; Build:
;     iscc ciris-server-installer.iss /DCirisVersion=0.5.38
; Output: dist\CIRIS-Server-Setup-{version}-x64.exe

#ifndef CirisVersion
#error "CirisVersion must be defined: iscc ciris-server-installer.iss /DCirisVersion=X.Y.Z"
#endif

#define MyAppName       "CIRIS Server"
#define MyAppPublisher  "CIRIS L3C"
#define MyAppURL        "https://ciris.ai"
#define MyAppExeName    "ciris-server.exe"
#define MyAppId         "{{B4E2D7C1-3A9F-4E68-9C2D-7F1A0B8E5C44}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#CirisVersion}
AppVerName={#MyAppName} {#CirisVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={localappdata}\CIRISServer
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
OutputDir=..\..\dist
; OutputSuffix lets the experimental Win7 lane (windows7-installer.yml) produce
; a distinctly-named artifact via /DOutputSuffix=-win7.
#ifndef OutputSuffix
#define OutputSuffix ""
#endif
OutputBaseFilename=CIRIS-Server-Setup-{#CirisVersion}{#OutputSuffix}-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Two-installer model (mirrors CIRISAgent#875):
;   * MAINLINE = official CPython → Windows 8.1 (6.3) floor.
;   * WIN7 VARIANT (built with /DWin7Tier by windows7-installer.yml, with a
;     Win7-capable patched CPython) lowers the floor to Win7 SP1 (6.1sp1). The
;     Rust node itself is built for the Tier-3 x86_64-win7-windows-msvc target
;     (see ci.yml win7-build-std), so it LoadLibrary's on Win7.
#ifdef Win7Tier
MinVersion=6.1sp1
#else
MinVersion=6.3
#endif
UninstallDisplayName={#MyAppName} {#CirisVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; \
    GroupDescription: "Additional shortcuts:"

[Files]
; PyInstaller --onedir output — the whole ciris-server\ folder (CPython, the
; Rust node, the launcher, and the desktop JAR collected into
; _internal\ciris_server\desktop_app\).
Source: "..\..\dist\ciris-server\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Trimmed JRE (~30 MB). desktop_launcher.find_java() prefers <app>\runtime when
; frozen, so drop it there.
Source: "..\..\dist\runtime\*"; DestDir: "{app}\runtime"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Universal CRT redistributable (KB2999226) — only Windows 7 needs it; in-box on
; Win8.1+. Bundled best-effort (CI fetches into installers\windows\redist\);
; skipifsourcedoesntexist so a missing redist never breaks the build.
Source: "redist\Windows6.1-KB2999226-x64.msu"; DestDir: "{tmp}"; \
    Flags: deleteafterinstall skipifsourcedoesntexist; \
    Check: NeedsUcrtRedist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"; Comment: "Launch CIRIS Server (node + desktop UI)"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Windows 7: install the Universal CRT (KB2999226) before first launch.
Filename: "wusa.exe"; \
    Parameters: """{tmp}\Windows6.1-KB2999226-x64.msu"" /quiet /norestart"; \
    StatusMsg: "Installing Universal C Runtime (Windows 7 prerequisite)..."; \
    Flags: waituntilterminated; Check: NeedsUcrtRedist

Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; The node home (data / keys / config CEG) lives under %USERPROFILE% per the
; node's path resolution — we deliberately do NOT delete it on uninstall. Only
; remove what we installed.
Type: filesandordirs; Name: "{app}\runtime"
Type: filesandordirs; Name: "{app}\_internal"

[Code]
#ifdef Win7Tier
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not WizardSilent() then
    Result := (MsgBox(
      'This is the UNSUPPORTED Windows 7 build of CIRIS Server.' #13#10 #13#10 +
      'It is provided as a last resort for machines that cannot run a newer ' +
      'Windows. If this PC can run Windows 8.1 or later, please install the ' +
      'standard CIRIS Server installer instead.' #13#10 #13#10 +
      'Windows 7 is past end-of-life; the node runs here at the software-key ' +
      'attestation tier (no TPM 2.0). Continue with the Windows 7 build?',
      mbConfirmation, MB_YESNO) = IDYES);
end;
#endif

function IsWindows7(): Boolean;
var
  V: TWindowsVersion;
begin
  GetWindowsVersionEx(V);
  Result := (V.Major = 6) and (V.Minor = 1);
end;

function UcrtPresent(): Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\ucrtbase.dll'));
end;

function NeedsUcrtRedist(): Boolean;
begin
  Result := IsWindows7() and (not UcrtPresent());
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and IsWindows7() and (not WizardSilent()) then
    MsgBox(
      'CIRIS Server is installed.' #13#10 #13#10 +
      'Note for Windows 7: hardware attestation requires TPM 2.0, which ' +
      'Windows 7 predates. The node runs normally here at the software-key ' +
      'attestation tier — the Trust page shows this status in-app.',
      mbInformation, MB_OK);
end;
