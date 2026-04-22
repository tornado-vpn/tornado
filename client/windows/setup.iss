[Setup]
AppName=Tornado VPN Client
AppVersion=1.0.0
AppPublisher=SRI DHARANIVEL A M
DefaultDirName={autopf}\TornadoVPN-client
DefaultGroupName=Tornado VPN
UninstallDisplayIcon={app}\TornadoVPN-client.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.\Output
OutputBaseFilename=TornadoVPN_Windows_Setup
PrivilegesRequired=admin

; Displays the GNU GPL v3 in the installation wizard
LicenseFile=LICENSE.txt

[Files]
; 1. Package the PyInstaller output
Source: "dist\TornadoVPN-client\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; 2. Package the official WireGuard installer into a temporary folder
Source: "wireguard-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

; 3. Explicitly copy your legal documents to the install directory
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "attribution.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Tornado VPN"; Filename: "{app}\TornadoVPN-client.exe"; IconFilename: "{app}\TornadoVPN-client.exe"
Name: "{autodesktop}\Tornado VPN"; Filename: "{app}\TornadoVPN-client.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
; 1. Silently install WireGuard. DO_NOT_LAUNCH=1 tells the installer to skip opening its GUI.
Filename: "{tmp}\wireguard-installer.exe"; Parameters: "/quiet DO_NOT_LAUNCH=1"; StatusMsg: "Installing WireGuard network dependencies..."; Flags: waituntilterminated; Check: WireguardNotInstalled

; 2. Bulletproof Fallback: Forcefully close the WireGuard GUI in the background just in case it still managed to launch.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM wireguard.exe"; Flags: waituntilterminated runhidden; Check: WireguardNotInstalled

; 3. Optionally launch Tornado VPN when the setup wizard finishes
Filename: "{app}\TornadoVPN-client.exe"; Description: "Launch Tornado VPN Client"; Flags: nowait postinstall skipifsilent runascurrentuser


[Code]
function WireguardNotInstalled: Boolean;
var
  IsInstalled: Boolean;
begin
  IsInstalled := False;

  // Method 1: Check if the executable physically exists in Program Files (64-bit or 32-bit)
  if FileExists(ExpandConstant('{pf64}\WireGuard\wireguard.exe')) then
    IsInstalled := True;
  if FileExists(ExpandConstant('{pf32}\WireGuard\wireguard.exe')) then
    IsInstalled := True;

  // Method 2: Check the core WireGuard registry key directly
  if RegKeyExists(HKLM64, 'SOFTWARE\WireGuard') then
    IsInstalled := True;
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\WireGuard') then
    IsInstalled := True;

  // If ANY of the above checks found WireGuard, skip the installation
  Result := not IsInstalled;
end;