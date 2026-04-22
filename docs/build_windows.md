# Windows Client Build Guide

This guide builds the Windows desktop client (`client/windows/src/main.py`) and packages it with Inno Setup.

## Prerequisites

1. Python 3.10+ available in PATH
2. Inno Setup installed
3. Official WireGuard installer file present as:
   - `client/windows/wireguard-installer.exe`

## 1. Prepare Build Environment

```cmd
cd client\windows
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller
```

## 2. Build Application Bundle

Use the source entrypoint in `src/main.py`:

```cmd
pyinstaller --noconfirm --onedir --windowed --icon "..\..\assets\icon.ico" ^
  --add-data "..\..\assets\icons\*.svg;." ^
  --add-data "..\..\LICENSE;." ^
  --add-data "..\..\ATTRIBUTIONS.md;." ^
  --name "TornadoVPN-client" src\main.py
```

Expected output:

- `client\windows\dist\TornadoVPN-client\TornadoVPN-client.exe`

## 3. Prepare Installer Inputs

`client/windows/setup.iss` expects:

- `dist\TornadoVPN-client\*`
- `wireguard-installer.exe`
- `LICENSE.txt`
- `attribution.md`

If needed, generate compatibility copies from repo root files:

```cmd
copy ..\..\LICENSE LICENSE.txt
copy ..\..\ATTRIBUTIONS.md attribution.md
```

## 4. Build Installer

1. Open `client/windows/setup.iss` in Inno Setup Compiler.
2. Compile (`Ctrl+F9`) or use CLI compiler.

Expected output:

- `client\windows\Output\TornadoVPN_Windows_Setup.exe`

## 5. Installer Behavior

`setup.iss` performs:

- app install into Program Files
- optional desktop shortcut task
- conditional WireGuard installer execution if WireGuard is not detected
- optional launch of Tornado VPN client after install

## 6. Smoke Test Checklist

1. Install generated setup executable on a clean VM.
2. Confirm app starts and requests elevated privileges when needed.
3. Confirm WireGuard dependency install path works.
4. Confirm login and tunnel lifecycle operations succeed.
5. Confirm uninstall removes app and shortcuts cleanly.

## Build Notes

- The spec file `TornadoVPN-client.spec` is present but currently references `main.py` directly; the maintained build path in this repository uses the explicit CLI command against `src/main.py`.
- Keep legal filenames aligned with installer script expectations (`LICENSE.txt`, `attribution.md`) unless the script is updated.
