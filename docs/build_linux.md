# Linux Client Build Guide

This guide builds and packages the Linux desktop client (`client/linux/src/main.py`) as a Debian package.

## Supported Targets

- Debian and Ubuntu derivatives (amd64)
- Package name: `tornadovpn-client`

## Prerequisites

```bash
sudo apt update
sudo apt install -y build-essential dpkg-dev python3-pip python3-venv python3-pyqt5 wireguard-tools
```

## 1. Build Environment

```bash
cd client/linux
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller
```

## 2. Build Binary With PyInstaller

```bash
pyinstaller --noconfirm --onefile --windowed \
  --name tornadovpn-client \
  --add-data "../../assets/icons/*.svg:." \
  src/main.py
```

Expected output binary:

- `client/linux/dist/tornadovpn-client`

## 3. Package Layout

```bash
mkdir -p tornadovpn-client_1.0.0_amd64/DEBIAN
mkdir -p tornadovpn-client_1.0.0_amd64/usr/bin
mkdir -p tornadovpn-client_1.0.0_amd64/usr/share/applications
mkdir -p tornadovpn-client_1.0.0_amd64/usr/share/icons/hicolor/scalable/apps
mkdir -p tornadovpn-client_1.0.0_amd64/usr/share/doc/tornadovpn-client
```

Copy payload:

```bash
cp dist/tornadovpn-client tornadovpn-client_1.0.0_amd64/usr/bin/
cp ../../assets/icons/tornado_vpn.svg tornadovpn-client_1.0.0_amd64/usr/share/icons/hicolor/scalable/apps/tornadovpn-client.svg
cp -r DEBIAN/* tornadovpn-client_1.0.0_amd64/DEBIAN/
cp ../../LICENSE tornadovpn-client_1.0.0_amd64/usr/share/doc/tornadovpn-client/copyright
cp ATTRIBUTIONS.md tornadovpn-client_1.0.0_amd64/usr/share/doc/tornadovpn-client/
```

If you want a launcher, provide a `.desktop` file and copy it into `usr/share/applications`.

## 4. Permissions and Build

```bash
chmod 755 tornadovpn-client_1.0.0_amd64/DEBIAN/postinst
chmod 755 tornadovpn-client_1.0.0_amd64/DEBIAN/postrm
dpkg-deb --build tornadovpn-client_1.0.0_amd64
```

Expected artifact:

- `tornadovpn-client_1.0.0_amd64.deb`

## 5. Install and Smoke Test

```bash
sudo dpkg -i tornadovpn-client_1.0.0_amd64.deb
which tornadovpn-client
```

Validate post-install script created sudoers drop-in:

```bash
ls -l /etc/sudoers.d/tornadovpn-client
```

## Packaging Notes

- `client/linux/DEBIAN/control` declares runtime dependency on WireGuard tooling.
- `postinst` writes `/etc/sudoers.d/tornadovpn-client` for WireGuard command execution.
- `postrm` removes that sudoers file on package removal/purge.
