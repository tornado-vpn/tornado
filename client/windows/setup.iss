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

; Point directly to the root LICENSE file
LicenseFile=..\..\LICENSE

; Optional: Add an icon to the installer itself
SetupIconFile=..\..\assets\icon.ico

[Files]
; 1. Package the PyInstaller output 
; (This will automatically include the LICENSE and ATTRIBUTIONS.md since PyInstaller put them here)
Source: "dist\TornadoVPN-client\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Tornado VPN"; Filename: "{app}\TornadoVPN-client.exe"; IconFilename: "{app}\TornadoVPN-client.exe"
Name: "{autodesktop}\Tornado VPN"; Filename: "{app}\TornadoVPN-client.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
; Launch Tornado VPN when the setup wizard finishes
Filename: "{app}\TornadoVPN-client.exe"; Description: "Launch Tornado VPN Client"; Flags: nowait postinstall skipifsilent runascurrentuser

[Code]
// Helper function to check for WireGuard
function IsWireGuardInstalled(): Boolean;
begin
  Result := False;
  // Method 1: Check if the executable physically exists in Program Files (64-bit or 32-bit)
  if FileExists(ExpandConstant('{pf64}\WireGuard\wireguard.exe')) then
    Result := True;
  if FileExists(ExpandConstant('{pf32}\WireGuard\wireguard.exe')) then
    Result := True;

  // Method 2: Check the core WireGuard registry key directly
  if RegKeyExists(HKLM64, 'SOFTWARE\WireGuard') then
    Result := True;
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\WireGuard') then
    Result := True;
end;

// InitializeSetup runs before the installer window even appears.
function InitializeSetup(): Boolean;
begin
  Result := True;
  
  if not IsWireGuardInstalled() then
  begin
    // Display a critical message box to the user
    MsgBox('WireGuard for Windows is required to run Tornado VPN but was not found on your system.' + #13#10#13#10 +
           'Please download and install WireGuard from the official website:' + #13#10 +
           'https://www.wireguard.com/install/' + #13#10#13#10 +
           'After installing WireGuard, please run this setup again.', 
           mbCriticalError, MB_OK);
           
    Result := False;
  end;
end;