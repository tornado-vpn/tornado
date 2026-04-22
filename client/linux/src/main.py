#!/usr/bin/env python3

# Tornado VPN Client
# Copyright (C) 2026 SRI DHARANIVEL A M
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# ═══════════════════════════════════════════════════════════════════════════
# §1  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
import sys
import math
import base64
import time
import subprocess
import os
import json
import socket
import hashlib
import logging
import tempfile
from typing import Optional, Tuple

# ── Logging setup (replaces all print() calls) ───────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tornado_vpn")

# ── Script directory (used for all asset lookups) ────────────────────────
def resource_path(relative_path: str) -> str:
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        # Or, if using --onedir, it runs from the exact compiled folder
        if hasattr(sys, '_MEIPASS'):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else None
            
        if not base_path:
            raise Exception("Not frozen")
            
    except Exception:
        # In development, look up two directories to find the shared assets folder
        # From client/windows/src/main.py -> up to client/windows/ -> up to client/ -> into assets/icons/
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'icons'))

    return os.path.join(base_path, relative_path)

_SCRIPT_DIR = resource_path("")
CUSTOM_LOGO_PATH = resource_path("logo.svg")

# ── Optional keyring for secure token storage ────────────────────────────
try:
    import keyring
    _HAS_KEYRING = True
except ImportError:
    _HAS_KEYRING = False
    log.warning(
        "keyring not installed — session tokens will fall back to a "
        "permission-restricted file. Install with: pip install keyring"
    )

# ── Core dependencies ─────────────────────────────────────────────────────
try:
    import requests
except ImportError:
    log.critical("Missing dependency: pip install requests")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    log.critical("Missing dependency: pip install cryptography")
    sys.exit(1)

# ── PyQt5 ────────────────────────────────────────────────────────────────
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFrame, QSizePolicy,
    QStackedWidget, QGraphicsDropShadowEffect, QSpacerItem,
    QMessageBox, QGridLayout,
)
from PyQt5.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QPropertyAnimation,
    QEasingCurve, QRect, QPoint, QSize, QObject, pyqtProperty,
)
from PyQt5.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QPixmap, QIcon,
    QLinearGradient, QRadialGradient, QPainterPath, QFontDatabase,
)
from PyQt5.QtSvg import QSvgRenderer

import json as _json

# ═══════════════════════════════════════════════════════════════════════════
# §2  EMBEDDED SVG LIBRARY
# ═══════════════════════════════════════════════════════════════════════════

_SVG: dict = {}



_SVG["shield_ok"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
  <path d="M26 4L6 13v13c0 12 8.3 23.2 20 26 11.7-2.8 20-14 20-26V13L26 4z"
        fill="white" fill-opacity="0.95"/>
  <polyline points="17,27 22,32 35,19" fill="none"
            stroke="#27ae60" stroke-width="3.5"
            stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

_SVG["shield_off"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
  <path d="M26 4L6 13v13c0 12 8.3 23.2 20 26 11.7-2.8 20-14 20-26V13L26 4z"
        fill="white" fill-opacity="0.70"/>
  <line x1="18" y1="18" x2="34" y2="34" stroke="#e74c3c" stroke-width="3.5" stroke-linecap="round"/>
  <line x1="34" y1="18" x2="18" y2="34" stroke="#e74c3c" stroke-width="3.5" stroke-linecap="round"/>
</svg>"""

_SVG["user"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
  <circle cx="12" cy="7" r="4"/>
</svg>"""

_SVG["lock"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>"""

_SVG["server"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <rect x="2" y="2" width="20" height="8" rx="2"/>
  <rect x="2" y="14" width="20" height="8" rx="2"/>
  <line x1="6" y1="6" x2="6.01" y2="6"/>
  <line x1="6" y1="18" x2="6.01" y2="18"/>
</svg>"""

_SVG["eye"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
  <circle cx="12" cy="12" r="3"/>
</svg>"""

_SVG["eye_off"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94
            M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19
            m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
  <line x1="1" y1="1" x2="23" y2="23"/>
</svg>"""

_SVG["logout"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
  <polyline points="16 17 21 12 16 7"/>
  <line x1="21" y1="12" x2="9" y2="12"/>
</svg>"""

_SVG["globe"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="10"/>
  <line x1="2" y1="12" x2="22" y2="12"/>
  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10
            a15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
</svg>"""

_SVG["clock"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="10"/>
  <polyline points="12 6 12 12 16 14"/>
</svg>"""

_SVG["activity"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
</svg>"""

_SVG["wifi"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
  <path d="M1.42 9a16 16 0 0 1 21.16 0"/>
  <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
  <line x1="12" y1="20" x2="12.01" y2="20"/>
</svg>"""

_SVG["key"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778
            5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
</svg>"""

_SVG["shield_check"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  <polyline points="9 12 11 14 15 10"/>
</svg>"""

_SVG["node_user"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <circle cx="20" cy="20" r="18" fill="currentColor" fill-opacity="0.12"/>
  <path d="M20 22a6 6 0 1 0 0-12 6 6 0 0 0 0 12z" fill="currentColor"/>
  <path d="M8 34c0-6.627 5.373-10 12-10s12 3.373 12 10" fill="currentColor"/>
</svg>"""

_SVG["node_vpn"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <circle cx="20" cy="20" r="18" fill="currentColor" fill-opacity="0.12"/>
  <path d="M20 6L7 12v10c0 8.284 5.733 16.04 13 18 7.267-1.96 13-9.716 13-18V12L20 6z"
        fill="currentColor"/>
</svg>"""

_SVG["node_tor"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <circle cx="20" cy="20" r="18" fill="currentColor" fill-opacity="0.12"/>
  <circle cx="20" cy="20" r="9" fill="none" stroke="currentColor" stroke-width="2.5"/>
  <circle cx="20" cy="20" r="5" fill="currentColor"/>
  <circle cx="20" cy="8" r="2.5" fill="currentColor"/>
  <circle cx="20" cy="32" r="2.5" fill="currentColor"/>
  <circle cx="8" cy="20" r="2.5" fill="currentColor"/>
  <circle cx="32" cy="20" r="2.5" fill="currentColor"/>
</svg>"""

_SVG["node_web"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <circle cx="20" cy="20" r="18" fill="currentColor" fill-opacity="0.12"/>
  <circle cx="20" cy="20" r="11" fill="none" stroke="currentColor" stroke-width="2.5"/>
  <line x1="9" y1="20" x2="31" y2="20" stroke="currentColor" stroke-width="2"/>
  <path d="M20 9c-3 3-5 6.8-5 11s2 8 5 11" fill="none" stroke="currentColor" stroke-width="2"/>
  <path d="M20 9c3 3 5 6.8 5 11s-2 8-5 11" fill="none" stroke="currentColor" stroke-width="2"/>
</svg>"""

_SVG["download"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
  <polyline points="7 10 12 15 17 10"/>
  <line x1="12" y1="15" x2="12" y2="3"/>
</svg>"""

_SVG["upload"] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
     fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
  <polyline points="17 8 12 3 7 8"/>
  <line x1="12" y1="3" x2="12" y2="15"/>
</svg>"""

# ── SVG Render Helpers ────────────────────────────────────────────────────

def _render_svg(svg_str: str, size: int, color: str = "#555") -> QPixmap:
    svg = svg_str.replace("currentColor", color)
    renderer = QSvgRenderer(bytearray(svg.encode("utf-8")))
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter)
    painter.end()
    return pm


def svg_pixmap(name: str, size: int, color: str = "#555") -> QPixmap:
    return _render_svg(_SVG[name], size, color)


def svg_icon(name: str, size: int = 20, color: str = "#555") -> QIcon:
    return QIcon(svg_pixmap(name, size, color))


# ── Logo Widget ───────────────────────────────────────────────────────────

class LogoWidget(QLabel):
    def __init__(self, size: int = 180, on_dark: bool = True, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("background: transparent; border: none;")
        if CUSTOM_LOGO_PATH and os.path.isfile(CUSTOM_LOGO_PATH):
            pm = QPixmap(CUSTOM_LOGO_PATH).scaled(
                size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
            self.setPixmap(pm)
            self.setFixedSize(size, size)
        else:
            color = "white" if on_dark else "#111111"
            self.setText("◈")
            self.setStyleSheet(
                f"font-size: {size}px; color: {color}; background: transparent; border: none;"
            )
            self.setFixedSize(size + 10, size + 10)


# ═══════════════════════════════════════════════════════════════════════════
# §3  LIGHT THEME DESIGN TOKENS
# ═══════════════════════════════════════════════════════════════════════════

_D = {
    "bg_main":    "#f4f5f7",
    "bg_panel":   "#ffffff",
    "bg_surface": "#ffffff",
    "bg_input":   "#f9f9fa",
    "border":     "#e1e4e8",
    "border_hi":  "#d1d5da",
    "text_pri":   "#111111",
    "text_sec":   "#555555",
    "text_ter":   "#888888",
    "green":      "#219653",
    "green_hi":   "#27ae60",
    "green_dim":  "#e3f5e5",
    "red":        "#eb5757",
    "red_dim":    "#ffebe9",
    "amber":      "#f2c94c",
    "amber_dim":  "#fff8c5",
    "orange":     "#e67e22",
    "blue":       "#2f80ed",
    "tor":        "#9b51e0",
    "tor_hi":     "#bb6bd9",
    "tor_dim":    "#f3e8fd",
}

DEFAULT_PORT = 4605

# ── Keyring constants ─────────────────────────────────────────────────────
_KEYRING_SERVICE = "tornado_vpn"
_KEYRING_ACCOUNT = "session"


# ═══════════════════════════════════════════════════════════════════════════
# §4  WIREGUARD & JWT HELPERS
# ═══════════════════════════════════════════════════════════════════════════

# FIX: Use a secure directory for the WG config to avoid TOCTOU race in /tmp
_WG_DIR  = tempfile.mkdtemp(prefix="tornado_vpn_")
_WG_CONF = os.path.join(_WG_DIR, "tornado_vpn.conf")


def generate_keypair() -> Tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_b  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()


def write_wg_config(private_key: str, vpn_ip: str,
                    server_pubkey: str, server_endpoint: str,
                    dns: str = "1.1.1.1") -> str:
    if ":" not in server_endpoint.split("/")[-1]:
        server_endpoint = f"{server_endpoint}:{DEFAULT_PORT}"
    conf = (
        f"[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {vpn_ip}/32\n"
        f"DNS = {dns}\n\n"
        f"[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {server_endpoint}\n"
        f"PersistentKeepalive = 25\n"
    )
    # FIX: Atomically create the file with strict permissions — no TOCTOU window
    fd = os.open(_WG_CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(conf)
    return _WG_CONF


def _run_wg(cmd: list) -> Tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except Exception as exc:
        return False, str(exc)


def wg_up(path: str)   -> Tuple[bool, str]: return _run_wg(["sudo", "wg-quick", "up",   path])
def wg_down(path: str) -> Tuple[bool, str]: return _run_wg(["sudo", "wg-quick", "down", path])


def extract_jwt_exp(token: str) -> int:
    """Decodes a JWT payload to extract the 'exp' (expiration) timestamp."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("exp", 0)
    except Exception:
        return 0


def format_bytes(b: int) -> str:
    """Converts raw bytes to a human-readable string."""
    val = float(b)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0:
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.2f} PB"


def get_wg_transfer(iface: str = "tornado_vpn") -> Tuple[int, int]:
    """Runs `wg show <iface> transfer` and returns (rx_bytes, tx_bytes)."""
    try:
        r = subprocess.run(
            ["sudo", "wg", "show", iface, "transfer"],
            capture_output=True, text=True, timeout=2,
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split()
            if len(parts) >= 3:
                return int(parts[1]), int(parts[2])
    except Exception:
        pass
    return 0, 0


# ═══════════════════════════════════════════════════════════════════════════
# §5  API CLIENT
# ═══════════════════════════════════════════════════════════════════════════

class TornadoAPI:
    def __init__(self, base_url: str):
        from urllib.parse import urlparse, urlunparse
        url = base_url.strip().rstrip("/")
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        p = urlparse(url)
        host   = p.hostname or ""
        port   = p.port or DEFAULT_PORT
        path   = p.path or ""
        netloc = f"{host}:{port}"
        base_url = urlunparse((p.scheme, netloc, path, "", "", ""))
        self.base_url = base_url.rstrip("/")
        self.host     = host

        self.access_token:  Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.device_id:     Optional[str] = None

        self._s = requests.Session()
        self._s.headers["Content-Type"] = "application/json"

    @property
    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}

    def _fetch_server_pubkey(self) -> bytes:
        r = self._s.get(f"{self.base_url}/auth/pubkey", timeout=5)
        r.raise_for_status()
        return base64.b64decode(r.json()["pubkey"])

    def login(self, username_or_email: str, password: str) -> dict:
        server_pub_bytes = self._fetch_server_pubkey()
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)

        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        shared = eph_priv.exchange(server_pub)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"tornado-vpn-login-v1",
        ).derive(shared)

        plaintext = _json.dumps({
            "username_or_email": username_or_email,
            "password":          password,
        }).encode()

        iv         = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, None)

        body = {
            "ephemeral_pubkey": base64.b64encode(eph_pub_bytes).decode(),
            "iv":               base64.b64encode(iv).decode(),
            "ciphertext":       base64.b64encode(ciphertext).decode(),
        }
        r = self._s.post(f"{self.base_url}/auth/login", json=body, timeout=10)
        r.raise_for_status()

        d = r.json()
        self.access_token  = d["tokens"]["access_token"]
        self.refresh_token = d["tokens"]["refresh_token"]
        self.device_id     = str(d["device_id"])
        return d

    def vpn_initiate(self, public_key: str) -> dict:
        r = self._s.post(
            f"{self.base_url}/vpn/initiate",
            json={"public_key": public_key},
            headers=self._auth,
            timeout=10,
        )
        r.raise_for_status()
        return r.json()

    def heartbeat(self) -> dict:
        r = self._s.post(
            f"{self.base_url}/session/heartbeat",
            headers=self._auth,
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def reauth(self) -> dict:
        r = self._s.post(
            f"{self.base_url}/auth/reauth",
            json={"refresh_token": self.refresh_token},
            timeout=10,
        )
        r.raise_for_status()
        d = r.json()
        self.access_token  = d["tokens"]["access_token"]
        self.refresh_token = d["tokens"]["refresh_token"]
        return d

    def logout(self) -> dict:
        r = self._s.post(
            f"{self.base_url}/auth/logout",
            json={"refresh_token": self.refresh_token},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()


# ═══════════════════════════════════════════════════════════════════════════
# §6  WORKER THREADS
# ═══════════════════════════════════════════════════════════════════════════

class _Worker(QThread):
    success = pyqtSignal(dict)
    failed  = pyqtSignal(str)

    def _safe(self, fn, *args, **kw):
        try:
            self.success.emit(fn(*args, **kw))
        except requests.exceptions.ConnectionError:
            self.failed.emit(
                "Cannot connect to server. Please check the Server IP and try again."
            )
        except requests.exceptions.Timeout:
            self.failed.emit(
                "Connection timed out. The server is taking too long to respond."
            )
        except requests.exceptions.HTTPError as exc:
            try:
                msg = exc.response.json().get("detail", str(exc))
            except Exception:
                msg = f"Server error: {exc.response.status_code}"
            self.failed.emit(str(msg))
        except Exception as exc:
            # FIX: Log the full traceback for debuggability instead of swallowing it
            log.exception(f"Unexpected error in worker thread: {exc}")
            self.failed.emit("An unexpected error occurred. Please try again.")


class LoginWorker(_Worker):
    def __init__(self, api: TornadoAPI, user: str, pw: str):
        super().__init__()
        self._a, self._u, self._p = api, user, pw

    def run(self):
        self._safe(self._a.login, self._u, self._p)


class ReauthWorker(_Worker):
    def __init__(self, api: TornadoAPI):
        super().__init__()
        self._a = api

    def run(self):
        self._safe(self._a.reauth)


class ConnectWorker(_Worker):
    def __init__(self, api: TornadoAPI, pub: str):
        super().__init__()
        self._a, self._pub = api, pub

    def run(self):
        self._safe(self._a.vpn_initiate, self._pub)


class HeartbeatWorker(_Worker):
    def __init__(self, api: TornadoAPI):
        super().__init__()
        self._a = api

    def run(self):
        self._safe(self._a.heartbeat)


class LogoutWorker(_Worker):
    def __init__(self, api: TornadoAPI):
        super().__init__()
        self._a = api

    def run(self):
        self._safe(self._a.logout)


class WgThread(QThread):
    done = pyqtSignal(bool, str)

    def __init__(self, path: str, action: str):
        super().__init__()
        self._path, self._action = path, action

    def run(self):
        fn = wg_up if self._action == "up" else wg_down
        ok, msg = fn(self._path)
        self.done.emit(ok, msg)


# ═══════════════════════════════════════════════════════════════════════════
# §7  SHARED WIDGETS
# ═══════════════════════════════════════════════════════════════════════════

# ── 7a  IconLineEdit ──────────────────────────────────────────────────────

class IconLineEdit(QWidget):
    def __init__(self, placeholder: str, icon_name: str,
                 password: bool = False, parent=None):
        super().__init__(parent)
        self._is_pw  = password
        self._hidden = password
        self.setFixedHeight(46)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        icon_box = QWidget()
        icon_box.setFixedSize(40, 46)
        icon_box.setStyleSheet("""
            QWidget {
                background: #f5f5f5;
                border: 1px solid #d0d0d0;
                border-right: none;
                border-top-left-radius: 10px;
                border-bottom-left-radius: 10px;
            }
        """)
        ib_lay = QHBoxLayout(icon_box)
        ib_lay.setContentsMargins(0, 0, 0, 0)
        self._icon_lbl = QLabel()
        self._icon_lbl.setPixmap(svg_pixmap(icon_name, 18, "#777777"))
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        ib_lay.addWidget(self._icon_lbl)

        self.field = QLineEdit()
        self.field.setPlaceholderText(placeholder)
        self.field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        if password:
            self.field.setEchoMode(QLineEdit.Password)

        right_radius     = "0px"  if password else "10px"
        right_border_base  = "none" if password else "1px solid #d0d0d0"
        right_border_focus = "none" if password else "1px solid #111111"

        self.field.setStyleSheet(f"""
            QLineEdit {{
                border-top: 1px solid #d0d0d0;
                border-bottom: 1px solid #d0d0d0;
                border-left: none;
                border-right: {right_border_base};
                border-top-right-radius: {right_radius};
                border-bottom-right-radius: {right_radius};
                padding: 0 12px;
                font-size: 13px;
                color: #111111;
                background: white;
                selection-background-color: #cccccc;
            }}
            QLineEdit:focus {{
                border-top: 1px solid #111111;
                border-bottom: 1px solid #111111;
                border-left: none;
                border-right: {right_border_focus};
                background: #fafafa;
            }}
        """)

        lay.addWidget(icon_box)
        lay.addWidget(self.field)

        if password:
            self._eye_btn = QPushButton()
            self._eye_btn.setFixedSize(44, 46)
            self._eye_btn.setCursor(Qt.PointingHandCursor)
            self._eye_btn.setIcon(svg_icon("eye", 16, "#777777"))
            self._eye_btn.setStyleSheet("""
                QPushButton {
                    border: 1px solid #d0d0d0;
                    border-left: none;
                    border-top-right-radius: 10px;
                    border-bottom-right-radius: 10px;
                    background: #f5f5f5;
                    padding: 0;
                }
                QPushButton:hover { background: #e8e8e8; }
            """)
            self._eye_btn.clicked.connect(self._toggle)
            lay.addWidget(self._eye_btn)

    def _toggle(self):
        self._hidden = not self._hidden
        self.field.setEchoMode(
            QLineEdit.Password if self._hidden else QLineEdit.Normal
        )
        icon = "eye" if self._hidden else "eye_off"
        self._eye_btn.setIcon(svg_icon(icon, 16, "#777777"))

    def text(self) -> str:
        return self.field.text()

    def setFocus(self):
        self.field.setFocus()


# ── 7b  LoadingDots ───────────────────────────────────────────────────────

class LoadingDots(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(36, 12)
        self._phase = 0.0
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)
        self._t.start(40)

    def _tick(self):
        self._phase = (self._phase + 0.18) % (math.pi * 2)
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        for i in range(3):
            offset = math.sin(self._phase + i * 1.0) * 3
            y = int(self.height() / 2 - offset)
            c = QColor(255, 255, 255, 220)
            p.setBrush(c)
            p.setPen(Qt.NoPen)
            p.drawEllipse(i * 14, y - 4, 8, 8)
        p.end()


# ── 7c  ElapsedTimer ──────────────────────────────────────────────────────

class ElapsedTimer(QObject):
    tick = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._secs = 0
        self._t = QTimer(self)
        self._t.timeout.connect(self._fire)

    def start(self):
        self._secs = 0
        self._t.start(1000)

    def stop(self):
        self._t.stop()
        self._secs = 0

    def _fire(self):
        self._secs += 1
        h = self._secs // 3600
        m = (self._secs % 3600) // 60
        s = self._secs % 60
        self.tick.emit(f"{h:02d}:{m:02d}:{s:02d}")


# ── 7d  SlidingStack ──────────────────────────────────────────────────────

class SlidingStack(QStackedWidget):
    def slide_to(self, index: int, forward: bool = True):
        if index == self.currentIndex():
            return
        out_widget = self.currentWidget()
        self.setCurrentIndex(index)
        in_widget  = self.currentWidget()
        w = self.width()

        for w_ in (out_widget, in_widget):
            w_.setGeometry(0, 0, self.width(), self.height())

        in_start = (QRect( w, 0, self.width(), self.height()) if forward
                    else QRect(-w, 0, self.width(), self.height()))
        out_end  = (QRect(-w, 0, self.width(), self.height()) if forward
                    else QRect( w, 0, self.width(), self.height()))

        in_widget.setGeometry(in_start)
        in_widget.show()
        in_widget.raise_()

        dur  = 340
        ease = QEasingCurve.OutCubic

        anim_out = QPropertyAnimation(out_widget, b"geometry", self)
        anim_out.setDuration(dur)
        anim_out.setEasingCurve(ease)
        anim_out.setStartValue(out_widget.geometry())
        anim_out.setEndValue(out_end)

        anim_in = QPropertyAnimation(in_widget, b"geometry", self)
        anim_in.setDuration(dur)
        anim_in.setEasingCurve(ease)
        anim_in.setStartValue(in_start)
        anim_in.setEndValue(QRect(0, 0, self.width(), self.height()))

        anim_out.start(QPropertyAnimation.DeleteWhenStopped)
        anim_in.start(QPropertyAnimation.DeleteWhenStopped)


# ═══════════════════════════════════════════════════════════════════════════
# §8  DASHBOARD WIDGETS
# ═══════════════════════════════════════════════════════════════════════════

# ── 8a  StatusDot ─────────────────────────────────────────────────────────

class StatusDot(QWidget):
    _COLORS = {
        "disconnected": "#f85149",
        "connecting":   "#d29922",
        "connected":    "#3fb950",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._state = "disconnected"
        self._alpha = 255
        self._dir   = -1
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._pulse)

    def set_state(self, state: str):
        self._state = state
        self._alpha = 255
        if state == "connecting":
            self._timer.start(22)
        else:
            self._timer.stop()
            self._alpha = 255
        self.update()

    def _pulse(self):
        self._alpha += self._dir * 9
        if self._alpha <= 70:  self._dir =  1
        if self._alpha >= 255: self._dir = -1
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        col = QColor(self._COLORS.get(self._state, "#f85149"))
        g = QColor(col); g.setAlpha(25)
        p.setPen(Qt.NoPen); p.setBrush(g)
        p.drawEllipse(0, 0, 16, 16)
        m = QColor(col); m.setAlpha(60)
        p.setBrush(m)
        p.drawEllipse(3, 3, 10, 10)
        c = QColor(col); c.setAlpha(self._alpha)
        p.setBrush(c)
        p.drawEllipse(5, 5, 6, 6)
        p.end()


# ── 8b  DataRow ───────────────────────────────────────────────────────────

class DataRow(QWidget):
    def __init__(self, label: str, value: str = "—", parent=None):
        super().__init__(parent)
        self.setFixedHeight(30)
        self.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        lbl = QLabel(label.upper())
        lbl.setStyleSheet(
            f"color: {_D['text_ter']}; font-size: 10px; font-weight: 700; "
            f"letter-spacing: 1px; background: transparent;"
        )

        self._val = QLabel(value)
        self._val.setStyleSheet(
            f"color: {_D['text_sec']}; font-size: 12px; "
            f"font-weight: 500; background: transparent;"
        )
        self._val.setAlignment(Qt.AlignRight)

        lay.addWidget(lbl)
        lay.addStretch()
        lay.addWidget(self._val)

    def set_value(self, v: str):
        self._val.setText(v)

    def highlight(self, on: bool):
        color = _D["text_pri"] if on else _D["text_sec"]
        self._val.setStyleSheet(
            f"color: {color}; font-size: 12px; "
            f"font-weight: {'700' if on else '500'}; background: transparent;"
        )


# ── 8c  Session Statistics — 2×3 Card Grid ───────────────────────────────

class StatCard(QFrame):
    def __init__(self, icon: str, label: str, value: str = "—", parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumHeight(76)
        self.setObjectName("StatCard")
        self.setStyleSheet(f"""
            QFrame#StatCard {{
                background-color: {_D['bg_panel']};
                border-radius: 10px;
                border: 1px solid {_D['border']};
            }}
        """)

        sh = QGraphicsDropShadowEffect(self)
        sh.setBlurRadius(12)
        sh.setOffset(0, 3)
        sh.setColor(QColor(0, 0, 0, 18))
        self.setGraphicsEffect(sh)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(8)

        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        hdr.setContentsMargins(0, 0, 0, 0)

        ic = QLabel()
        ic.setPixmap(svg_pixmap(icon, 16, _D["text_sec"]))
        ic.setAlignment(Qt.AlignCenter)
        ic.setFixedSize(26, 26)
        ic.setStyleSheet(f"""
            background: {_D['bg_input']};
            border-radius: 6px;
            border: 1px solid {_D['border']};
        """)

        lbl_w = QLabel(label.upper())
        lbl_w.setStyleSheet(f"""
            font-size: 10px; font-weight: 700;
            color: {_D['text_ter']}; letter-spacing: 1px;
            background: transparent; border: none;
        """)

        hdr.addWidget(ic, alignment=Qt.AlignVCenter)
        hdr.addWidget(lbl_w, alignment=Qt.AlignVCenter)
        hdr.addStretch()
        root.addLayout(hdr)

        self._val_lbl = QLabel(value)
        self._val_lbl.setStyleSheet(f"""
            font-size: 15px; font-weight: 800;
            color: {_D['text_pri']}; background: transparent;
            border: none; letter-spacing: -0.4px;
        """)
        self._val_lbl.setWordWrap(False)
        self._val_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        root.addWidget(self._val_lbl)
        root.addStretch()

    def set_value(self, v: str):
        self._val_lbl.setText(v)

    def highlight(self, on: bool):
        col    = _D["text_pri"] if on else _D["text_sec"]
        weight = "800" if on else "600"
        self._val_lbl.setStyleSheet(f"""
            font-size: 15px; font-weight: {weight};
            color: {col}; background: transparent;
            border: none; letter-spacing: -0.4px;
        """)


class SessionStatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.setMinimumHeight(260)
        self.setStyleSheet("background: transparent;")

        grid = QGridLayout(self)
        grid.setContentsMargins(4, 4, 4, 4)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        self.c_ip     = StatCard("globe",    "VPN TUNNEL IP")
        self.c_server = StatCard("server",   "Server")
        self.c_time   = StatCard("clock",    "Duration",  "00:00:00")
        self.c_proto  = StatCard("key",      "Protocol",  "WireGuard®")
        self.c_down   = StatCard("download", "Data Rx",   "0 B")
        self.c_up     = StatCard("upload",   "Data Tx",   "0 B")

        grid.addWidget(self.c_ip,     0, 0)
        grid.addWidget(self.c_server, 0, 1)
        grid.addWidget(self.c_time,   1, 0)
        grid.addWidget(self.c_proto,  1, 1)
        grid.addWidget(self.c_down,   2, 0)
        grid.addWidget(self.c_up,     2, 1)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)


# ── 8d  TorToggle ─────────────────────────────────────────────────────────

class ToggleSwitch(QWidget):
    toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(48, 26)
        self.setCursor(Qt.PointingHandCursor)
        self._on  = False
        self._pos = 3.0
        self._anim = QPropertyAnimation(self, b"pos_val", self)
        self._anim.setDuration(200)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    @pyqtProperty(float)
    def pos_val(self):
        return self._pos

    @pos_val.setter
    def pos_val(self, v):
        self._pos = v
        self.update()

    def set_on(self, on: bool):
        self._on = on
        self._anim.setEndValue(23.0 if on else 3.0)
        self._anim.start()

    def mouseReleaseEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            self.set_on(not self._on)
            self.toggled.emit(self._on)

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        bg_col = QColor(_D["tor"]) if self._on else QColor(_D["border_hi"])
        p.setPen(Qt.NoPen)
        p.setBrush(bg_col)
        p.drawRoundedRect(0, 0, self.width(), self.height(), 13, 13)
        p.setBrush(Qt.white)
        p.drawEllipse(int(self._pos), 3, 20, 20)
        p.end()


class TorToggle(QWidget):
    toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._on = False
        self.setFixedHeight(68)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._build()

    def _build(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        self._icon_lbl = QLabel()
        self._icon_lbl.setFixedSize(36, 36)
        icon_lay = QHBoxLayout(self._icon_lbl)
        icon_lay.setContentsMargins(0, 0, 0, 0)
        self._inner_ic = QLabel()
        self._inner_ic.setAlignment(Qt.AlignCenter)
        icon_lay.addWidget(self._inner_ic)

        lay.addWidget(self._icon_lbl, alignment=Qt.AlignVCenter)

        col = QVBoxLayout()
        col.setSpacing(2)
        col.setAlignment(Qt.AlignVCenter)
        self._label = QLabel("Tor over VPN")
        self._label.setStyleSheet(
            f"font-size: 13px; color: {_D['text_pri']}; font-weight: 700;"
            f"background: transparent; border: none;"
        )
        self._sublabel = QLabel("Onion-routed privacy")
        self._sublabel.setWordWrap(True)
        self._sublabel.setStyleSheet(
            f"font-size: 11px; color: {_D['text_sec']}; background: transparent; border: none;"
        )
        col.addWidget(self._label)
        col.addWidget(self._sublabel)
        lay.addLayout(col)
        lay.addStretch()

        self._switch = ToggleSwitch()
        self._switch.toggled.connect(self._toggle)
        lay.addWidget(self._switch, alignment=Qt.AlignVCenter)
        self._apply_style()

    def _toggle(self, state: bool):
        self._on = state
        self._apply_style()
        self.toggled.emit(self._on)

    def _apply_style(self):
        """
        FIX: Removed hardcoded QSvgRenderer("tor_server.svg") that silently
        produced a blank icon when the file was missing.  Now tries the file
        relative to _SCRIPT_DIR first, then falls back to the embedded SVG.
        """
        sz    = 18
        color = _D["tor"] if self._on else _D["text_ter"]

        svg_path = resource_path("tor_server.svg")
        if os.path.isfile(svg_path):
            pm = QPixmap(sz, sz)
            pm.fill(Qt.transparent)
            painter = QPainter(pm)
            painter.setRenderHint(QPainter.Antialiasing)
            if not self._on:
                painter.setOpacity(0.4)
            renderer = QSvgRenderer(svg_path)
            renderer.render(painter)
            painter.end()
        else:
            # Embedded fallback — always available
            base_pm = svg_pixmap("node_tor", sz, color)
            if not self._on:
                pm = QPixmap(base_pm.size())
                pm.fill(Qt.transparent)
                p = QPainter(pm)
                p.setOpacity(0.4)
                p.drawPixmap(0, 0, base_pm)
                p.end()
            else:
                pm = base_pm

        self._inner_ic.setPixmap(pm)

        if self._on:
            self._icon_lbl.setStyleSheet(
                f"background: {_D['tor_dim']}; border-radius: 8px;"
            )
            self._label.setStyleSheet(
                f"font-size: 13px; color: {_D['text_pri']}; font-weight: 700;"
                f"background: transparent; border: none;"
            )
        else:
            self._icon_lbl.setStyleSheet(
                f"background: {_D['bg_input']}; border-radius: 8px;"
                f"border: 1px solid {_D['border']};"
            )
            self._label.setStyleSheet(
                f"font-size: 13px; color: {_D['text_sec']}; font-weight: 700;"
                f"background: transparent; border: none;"
            )

    def is_on(self) -> bool:
        return self._on


# ── 8e  TopologyView ──────────────────────────────────────────────────────

class _TopoNode(QWidget):
    NODE_SIZE  = 80
    ICON_SIZE  = 44
    SMALL_SIZE = 60
    SMALL_ICON = 32

    def __init__(self, image_path: str, label: str, small: bool = False, parent=None):
        super().__init__(parent)
        self.setFixedWidth(100)
        self._image_path = image_path
        self._label_text = label
        self._small      = small
        self._pm_cache: dict = {}

        sz  = self.SMALL_SIZE if small else self.NODE_SIZE
        icz = self.SMALL_ICON if small else self.ICON_SIZE

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(6)
        lay.setContentsMargins(0, 0, 0, 0)

        self.circle = QFrame()
        self.circle.setFixedSize(sz, sz)
        self._r = sz // 2

        sh = QGraphicsDropShadowEffect(self.circle)
        sh.setBlurRadius(18)
        sh.setOffset(0, 3)
        sh.setColor(QColor(0, 0, 0, 60))
        self.circle.setGraphicsEffect(sh)
        self._apply_border("#e1e4e8", "#ffffff")

        cl = QVBoxLayout(self.circle)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setAlignment(Qt.AlignCenter)

        self._icon_lbl = QLabel()
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        self._icon_lbl.setStyleSheet("background: transparent; border: none;")
        self._load_icon(icz, opacity=0.35)
        cl.addWidget(self._icon_lbl)

        self._text_container = QWidget()
        tl = QVBoxLayout(self._text_container)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(0)

        self._lbl_w = QLabel(label)
        self._lbl_w.setAlignment(Qt.AlignCenter)
        self._lbl_w.setMinimumWidth(80)
        self._lbl_w.setFixedHeight(18)

        self._ip_lbl = QLabel("—")
        self._ip_lbl.setAlignment(Qt.AlignCenter)
        self._ip_lbl.setMinimumWidth(80)
        self._ip_lbl.setFixedHeight(18)
        self._ip_lbl.setStyleSheet(
            f"font-size: 9px; color: {_D['text_sec']}; background: white; "
            f"border: 1px solid {_D['border']}; border-top: none; border-radius: 0px;"
        )

        tl.addWidget(self._lbl_w)
        tl.addWidget(self._ip_lbl)

        lay.addWidget(self.circle, alignment=Qt.AlignCenter)
        lay.addWidget(self._text_container, alignment=Qt.AlignCenter)

        self._blink_timer: Optional[QTimer] = None
        self._blink_on = True

    def _apply_border(self, border_color: str, bg_color: str):
        r = self._r
        self.circle.setStyleSheet(f"""
            QFrame {{
                border: 3px solid {border_color};
                border-radius: {r}px;
                background: {bg_color};
            }}
        """)

    def _load_icon(self, icz: int, opacity: float = 1.0):
        key = (self._image_path, icz, opacity)
        if key not in self._pm_cache:
            # FIX: Path resolution already used __file__ here — preserved and correct
            path = resource_path(self._image_path)
            if not os.path.exists(path):
                path = self._image_path

            pm = QPixmap(icz, icz)
            pm.fill(Qt.transparent)
            painter = QPainter(pm)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setOpacity(opacity)
            if self._image_path.endswith(".svg"):
                rnd = QSvgRenderer(path)
                rnd.render(painter)
            else:
                src = QPixmap(path).scaled(
                    icz, icz, Qt.KeepAspectRatio, Qt.SmoothTransformation
                )
                painter.drawPixmap(
                    (icz - src.width()) // 2,
                    (icz - src.height()) // 2, src,
                )
            painter.end()
            self._pm_cache[key] = pm
        self._icon_lbl.setPixmap(self._pm_cache[key])

    def _stop_blink(self):
        if self._blink_timer and self._blink_timer.isActive():
            self._blink_timer.stop()
        self._blink_timer = None

    def set_ip(self, ip: str):
        self._ip_lbl.setText(ip)

    def set_state(self, state: str):
        self._stop_blink()
        icz = self.SMALL_ICON if self._small else self.ICON_SIZE

        base_lbl_style = (
            f"font-size: 9px; font-weight: 800; letter-spacing: 1px; "
            f"background: white; border: 1px solid {_D['border']};"
        )

        if state == "idle":
            self._apply_border(_D["border"], "#ffffff")
            self._load_icon(icz, opacity=0.35)
            self._lbl_w.setStyleSheet(base_lbl_style + f" color: {_D['text_ter']};")

        elif state == "success":
            self._apply_border(_D["green_hi"], "#f0fff4")
            self._load_icon(icz, opacity=1.0)
            self._lbl_w.setStyleSheet(base_lbl_style + f" color: {_D['green_hi']};")

        elif state == "vpn_success":
            self._apply_border(_D["orange"], "#ffffff")
            self._load_icon(icz, opacity=1.0)
            self._lbl_w.setStyleSheet(base_lbl_style + f" color: {_D['orange']};")

        elif state == "error":
            self._apply_border(_D["red"], "#fff5f5")
            self._load_icon(icz, opacity=1.0)
            self._lbl_w.setStyleSheet(base_lbl_style + f" color: {_D['red']};")

        elif state in ("blinking_yellow", "blinking_orange"):
            color_on  = "#f2c94c" if state == "blinking_yellow" else "#e67e22"
            color_off = _D["border"]
            self._load_icon(icz, opacity=1.0)
            self._lbl_w.setStyleSheet(base_lbl_style + f" color: {color_on};")
            self._blink_timer = QTimer(self)
            self._blink_on = True

            def _toggle():
                clr = color_on if self._blink_on else color_off
                self._apply_border(clr, "#ffffff")
                self._blink_on = not self._blink_on

            self._blink_timer.timeout.connect(_toggle)
            self._blink_timer.start(400)
            _toggle()

        elif state == "tor_success":
            self._apply_border(_D["tor_hi"], "#faf0ff")
            self._load_icon(icz, opacity=1.0)
            self._lbl_w.setStyleSheet(base_lbl_style + f" color: {_D['tor_hi']};")


class TopologyView(QWidget):
    _KEYS = ("vpn", "tor", "web")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(200)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self._connected   = False
        self._tor_enabled = False

        self._line_color    = {k: QColor(_D["border"]) for k in self._KEYS}
        self._line_progress = {k: 0.0                  for k in self._KEYS}

        self._dot_phases  = [0.0, 0.34, 0.67]
        self._sweep_phase = 0.0
        self._anim_timer  = QTimer(self)
        self._anim_timer.timeout.connect(self._anim_step)
        self._anim_timer.start(16)

        self._animating  = False
        self._anim_key   = ""
        self._anim_cb    = None
        self._line_timer = QTimer(self)
        self._line_timer.timeout.connect(self._line_step)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(40, 10, 40, 10)
        lay.setSpacing(0)

        self.n_pc  = _TopoNode("client.svg",      "YOU",         parent=self)
        self.n_vpn = _TopoNode("tornado_vpn.svg", "TORNADO VPN", parent=self)
        self.n_tor = _TopoNode("tor_server.svg",  "TOR",         parent=self)
        self.n_web = _TopoNode("internet.svg",    "INTERNET",    parent=self)

        self._spacer_1 = QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self._spacer_2 = QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self._spacer_3 = QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)

        lay.addWidget(self.n_pc)
        lay.addSpacerItem(self._spacer_1)
        lay.addWidget(self.n_vpn)
        lay.addSpacerItem(self._spacer_2)
        lay.addWidget(self.n_tor)
        lay.addSpacerItem(self._spacer_3)
        lay.addWidget(self.n_web)

        self._update_visibility()

    def _update_visibility(self):
        self.n_tor.setVisible(self._tor_enabled)
        if self._tor_enabled:
            self._spacer_2.changeSize(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)
        else:
            self._spacer_2.changeSize(0, 0, QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.layout().invalidate()
        self.update()

    def set_ips(self, ips: dict):
        self.n_pc.set_ip( ips.get("user", "—"))
        self.n_vpn.set_ip(ips.get("vpn",  "—"))
        self.n_tor.set_ip(ips.get("tor",  "—"))
        self.n_web.set_ip(ips.get("web",  "—"))

    def set_connected(self, connected: bool):
        self._connected = connected
        self.update()

    def set_tor_enabled(self, enabled: bool):
        self._tor_enabled = enabled
        self._update_visibility()
        self.update()

    def animate_line(self, key: str, color: str, on_complete=None):
        if self._animating and self._anim_key != key:
            self._line_progress[self._anim_key] = 1.0
        self._animating = True
        self._anim_key  = key
        self._anim_cb   = on_complete
        self._line_color[key] = QColor(color)
        if self._line_progress[key] >= 1.0:
            self._line_progress[key] = 0.0
        self._line_timer.start(20)

    def set_node_state(self, node_name: str, state: str):
        node = {
            "pc":  self.n_pc, "vpn": self.n_vpn,
            "tor": self.n_tor, "web": self.n_web,
        }.get(node_name)
        if node:
            node.set_state(state)

    def reset_all(self):
        self._connected = False
        self._animating = False
        self._line_timer.stop()
        for k in self._KEYS:
            self._line_color[k]    = QColor(_D["border"])
            self._line_progress[k] = 0.0
        for node in (self.n_pc, self.n_vpn, self.n_tor, self.n_web):
            node.set_state("idle")
            node.set_ip("—")
        self.update()

    def _line_step(self):
        k = self._anim_key
        self._line_progress[k] = min(1.0, self._line_progress[k] + 0.045)
        self.update()
        if self._line_progress[k] >= 1.0:
            self._line_timer.stop()
            self._animating = False
            if self._anim_cb:
                cb, self._anim_cb = self._anim_cb, None
                cb()

    def _anim_step(self):
        if self._connected:
            self._dot_phases  = [(p + 0.009) % 1.0 for p in self._dot_phases]
            self._sweep_phase = (self._sweep_phase + 0.004) % 1.0
        self.update()

    def _center(self, node: _TopoNode) -> QPoint:
        c = node.circle
        return QPoint(
            node.x() + c.x() + c.width()  // 2,
            node.y() + c.y() + c.height() // 2,
        )

    def _r(self, node: _TopoNode) -> int:
        return node.circle.width() // 2

    def _draw_line(self, p: QPainter, a: "_TopoNode", b: "_TopoNode",
                   key: str, is_tor: bool = False):
        pt_a, pt_b = self._center(a), self._center(b)
        r_a, r_b   = self._r(a), self._r(b)

        dx   = pt_b.x() - pt_a.x()
        dy   = pt_b.y() - pt_a.y()
        dist = math.hypot(dx, dy) or 1
        ux, uy = dx / dist, dy / dist

        sx = int(pt_a.x() + ux * r_a); sy = int(pt_a.y() + uy * r_a)
        ex = int(pt_b.x() - ux * r_b); ey = int(pt_b.y() - uy * r_b)

        progress = self._line_progress[key]
        color    = QColor(_D["tor"]) if is_tor else self._line_color[key]

        if progress <= 0:
            pen = QPen(QColor(_D["border"]), 2, Qt.DashLine)
            pen.setDashPattern([5, 4])
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawLine(sx, sy, ex, ey)
            return

        ax = int(sx + (ex - sx) * progress)
        ay = int(sy + (ey - sy) * progress)

        if self._connected and progress >= 1.0:
            for gw, ga in ((16, 10), (10, 28), (5, 60)):
                gc = QColor(color); gc.setAlpha(ga)
                p.setPen(QPen(gc, gw, Qt.SolidLine, Qt.RoundCap))
                p.drawLine(sx, sy, ex, ey)

            seg_off = int(hashlib.md5(key.encode()).hexdigest(), 16) % 100 * 0.01
            t_sw = (self._sweep_phase + seg_off * 0.6) % 1.0
            spx = int(sx + (ex - sx) * t_sw)
            spy = int(sy + (ey - sy) * t_sw)
            sw  = 55
            bright      = (QColor(230, 210, 255, 200) if is_tor
                           else QColor(255, 255, 255, 200))
            transparent = QColor(color); transparent.setAlpha(0)
            grad = QLinearGradient(
                spx - ux * sw, spy - uy * sw,
                spx + ux * sw, spy + uy * sw,
            )
            grad.setColorAt(0.0, transparent)
            grad.setColorAt(0.5, bright)
            grad.setColorAt(1.0, transparent)
            p.save()
            clip = QPainterPath()
            clip.addRect(
                min(sx, ex) - 8, min(sy, ey) - 8,
                abs(ex - sx) + 16, abs(ey - sy) + 16,
            )
            p.setClipPath(clip)
            p.setPen(QPen(QBrush(grad), 6, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(sx, sy, ex, ey)
            p.restore()

        pen = QPen(color, 3, Qt.SolidLine)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawLine(sx, sy, ax, ay)

        if self._connected and progress >= 1.0:
            dot_r   = 4
            dot_col = QColor("#e9d5ff") if is_tor else QColor("#ffffff")
            for j, base in enumerate(self._dot_phases):
                t   = (base + j * 0.33) % 1.0
                dpx = int(sx + (ex - sx) * t)
                dpy = int(sy + (ey - sy) * t)
                for hr, ha in ((dot_r + 5, 18), (dot_r + 2, 40)):
                    hc = QColor(color); hc.setAlpha(ha)
                    p.setPen(Qt.NoPen); p.setBrush(hc)
                    p.drawEllipse(QPoint(dpx, dpy), hr, hr)
                p.setBrush(dot_col)
                p.setPen(Qt.NoPen)
                p.drawEllipse(QPoint(dpx, dpy), dot_r, dot_r)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        if self._tor_enabled:
            self._draw_line(p, self.n_pc,  self.n_vpn, "vpn")
            self._draw_line(p, self.n_vpn, self.n_tor, "tor", is_tor=True)
            self._draw_line(p, self.n_tor, self.n_web, "web", is_tor=True)
        else:
            self._draw_line(p, self.n_pc,  self.n_vpn, "vpn")
            self._draw_line(p, self.n_vpn, self.n_web, "web")
        p.end()


# ═══════════════════════════════════════════════════════════════════════════
# §9  LOGIN PAGE
# ═══════════════════════════════════════════════════════════════════════════

class LoginPage(QWidget):
    do_login = pyqtSignal(str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._busy = False
        self._build()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        brand = QWidget()
        brand.setFixedWidth(290)
        brand.setStyleSheet("background: #f9f9fa;")

        bl = QVBoxLayout(brand)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setAlignment(Qt.AlignCenter)
        bl.setSpacing(0)

        logo = LogoWidget(size=150, on_dark=False)
        logo.setAlignment(Qt.AlignCenter)

        title = QLabel("TORNADO VPN")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "color: black; font-size: 21px; font-weight: 900;"
            "letter-spacing: 3px; margin-top: 10px; background: transparent;"
        )
        tagline = QLabel("Fast  ·  Secure  ·  Private")
        tagline.setAlignment(Qt.AlignCenter)
        tagline.setStyleSheet(
            "color: rgba(0,0,0,0.50); font-size: 12px; background: transparent;"
        )

        div = QFrame()
        div.setFixedSize(40, 1)
        div.setStyleSheet("background: rgba(0,0,0,0.15); border: none;")

        features = QWidget()
        features.setStyleSheet("background: transparent;")
        fl = QVBoxLayout(features)
        fl.setContentsMargins(35, 26, 35, 0)
        fl.setSpacing(10)
        for icon_name, text in [
            ("wifi", "WireGuard® protocol"),
            ("key",  "End-to-end encryption"),
        ]:
            row = QWidget()
            row.setStyleSheet(
                "background: #fcfcfc; border-radius: 8px; border: 1px solid #f0f0f0;"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(12, 8, 12, 8)
            rl.setSpacing(10)
            ic = QLabel()
            ic.setPixmap(svg_pixmap(icon_name, 16, "black"))
            ic.setFixedSize(20, 20)
            ic.setAlignment(Qt.AlignCenter)
            tx = QLabel(text)
            tx.setStyleSheet(
                "color: #444444; font-size: 12px; background: transparent; border: none;"
            )
            rl.addWidget(ic); rl.addWidget(tx); rl.addStretch()
            fl.addWidget(row)

        port_badge = QLabel(f"Port {DEFAULT_PORT}")
        port_badge.setAlignment(Qt.AlignCenter)
        port_badge.setStyleSheet(
            "color: rgba(0,0,0,0.30); font-size: 11px; "
            "background: transparent; margin-top: 18px; letter-spacing: 1px;"
        )

        bl.addStretch()
        bl.addWidget(logo, alignment=Qt.AlignHCenter)
        bl.addSpacing(8)
        bl.addWidget(title); bl.addWidget(tagline)
        bl.addSpacing(20)
        bl.addWidget(div, alignment=Qt.AlignCenter)
        bl.addWidget(features)
        bl.addWidget(port_badge)
        bl.addStretch()

        form_wrap = QWidget()
        form_wrap.setStyleSheet("background: #ffffff;")
        fw = QVBoxLayout(form_wrap)
        fw.setContentsMargins(140, 0, 140, 0)
        fw.setAlignment(Qt.AlignVCenter)
        fw.setSpacing(0)
        fw.addStretch()

        greet = QLabel("Welcome back")
        greet.setStyleSheet(
            "font-size: 28px; font-weight: 800; color: #111111; letter-spacing: -0.5px;"
        )
        sub = QLabel("Sign in to continue your secure connection")
        sub.setStyleSheet("font-size: 13px; color: #888888; margin-top: 6px;")

        fw.addWidget(greet); fw.addWidget(sub)
        fw.addSpacing(34)

        self._srv  = IconLineEdit(f"Server IP  (192.179.232.10:{DEFAULT_PORT})", "server")
        self._user = IconLineEdit("Username or e-mail", "user")
        self._pass = IconLineEdit("Password", "lock", password=True)

        fw.addWidget(self._srv);  fw.addSpacing(13)
        fw.addWidget(self._user); fw.addSpacing(13)
        fw.addWidget(self._pass); fw.addSpacing(22)

        self._err = QLabel()
        self._err.setWordWrap(True)
        self._err.setStyleSheet("""
            color: #cc0000; background: #fff0f0;
            border: 1px solid #ffbbbb; border-radius: 8px;
            padding: 9px 14px; font-size: 12px;
        """)
        self._err.hide()
        fw.addWidget(self._err); fw.addSpacing(4)

        self._btn = QPushButton("Sign In")
        btn_shadow = QGraphicsDropShadowEffect(self._btn)
        btn_shadow.setBlurRadius(20)
        btn_shadow.setOffset(0, 4)
        btn_shadow.setColor(QColor(0, 0, 0, 30))
        self._btn.setGraphicsEffect(btn_shadow)
        self._btn.setFixedHeight(50)
        self._btn.setCursor(Qt.PointingHandCursor)
        self._btn.setStyleSheet("""
            QPushButton {
                background: #111111; color: white; border-radius: 12px;
                font-size: 15px; font-weight: 700; letter-spacing: 0.5px;
            }
            QPushButton:hover   { background: #333333; }
            QPushButton:pressed { background: #000000; }
            QPushButton:disabled { background: #cccccc; color: #f0f0f0; }
        """)
        self._btn.clicked.connect(self._submit)
        fw.addWidget(self._btn)

        # FIX: Parent dots to the button so they're always clipped correctly
        self._dots = LoadingDots(self._btn)
        self._dots.hide()

        fw.addStretch()

        root.addWidget(brand)

        main_divider = QFrame()
        main_divider.setFrameShape(QFrame.VLine)
        main_divider.setFixedWidth(1)
        main_divider.setStyleSheet("background: rgba(0, 0, 0, 0.08); border: none;")
        root.addWidget(main_divider)
        root.addWidget(form_wrap)

    def _submit(self):
        srv  = self._srv.text().strip()
        user = self._user.text().strip()
        pw   = self._pass.text()
        if not srv or not user or not pw:
            self._show_err("Please fill in all fields.")
            return
        self._err.hide()
        self._set_busy(True)
        self.do_login.emit(srv, user, pw)

    def _set_busy(self, busy: bool):
        self._busy = busy
        self._btn.setEnabled(not busy)
        self._btn.setText("" if busy else "Sign In")
        if busy:
            # FIX: Position dots only when the button has a valid geometry
            self._dots.move(
                self._btn.width()  // 2 - 18,
                self._btn.height() // 2 - 6,
            )
        self._dots.setVisible(busy)

    def _show_err(self, msg: str):
        self._set_busy(False)
        self._err.setText(msg)
        self._err.show()

    def show_error(self, msg: str):
        self._show_err(msg)

    def reset(self):
        self._set_busy(False)
        self._err.hide()


# ═══════════════════════════════════════════════════════════════════════════
# §10  DASHBOARD PAGE
# ═══════════════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    do_connect    = pyqtSignal()
    do_disconnect = pyqtSignal()
    do_logout     = pyqtSignal()
    tor_toggled   = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._conn_state = "disconnected"
        self.setStyleSheet(f"background: {_D['bg_main']};")
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._build_topbar(root)

        content = QWidget()
        content.setStyleSheet(f"background: {_D['bg_main']};")
        cl = QHBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)

        self._build_left(cl)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setFixedWidth(1)
        sep.setStyleSheet(f"background: {_D['border']}; border: none; max-width: 1px;")
        cl.addWidget(sep)

        self._build_right(cl)

        root.addWidget(content)

        self._elapsed = ElapsedTimer(self)
        self._elapsed.tick.connect(self._dr_duration.set_value)
        self._elapsed.tick.connect(self._stats_panel.c_time.set_value)
        self._elapsed._t.timeout.connect(self._update_network_stats)

    def _build_topbar(self, parent_layout):
        bar = QWidget()
        bar.setFixedHeight(56)
        bar.setStyleSheet(f"""
            QWidget {{
                background: {_D['bg_panel']};
                border-bottom: 1px solid {_D['border']};
            }}
        """)
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(24, 0, 24, 0)
        bl.setSpacing(0)

        chip = LogoWidget(size=50, on_dark=False)

        brand_lbl = QLabel("TORNADO VPN CLIENT")
        brand_lbl.setStyleSheet(
            f"font-size: 13px; font-weight: 900; color: {_D['text_pri']}; "
            f"letter-spacing: 2.5px; background: transparent;"
        )

        self._server_badge = QLabel("● Not connected")
        self._server_badge.setStyleSheet(
            f"font-size: 11px; color: {_D['red']}; "
            f"background: transparent; font-weight: 600;"
        )

        bl.addWidget(chip); bl.addSpacing(4)
        bl.addWidget(brand_lbl); bl.addSpacing(15)

        tb_sep = QFrame()
        tb_sep.setFrameShape(QFrame.VLine)
        tb_sep.setFixedWidth(1)
        tb_sep.setFixedHeight(20)
        tb_sep.setStyleSheet(f"background: {_D['border']}; border: none;")
        bl.addWidget(tb_sep); bl.addSpacing(16)
        bl.addWidget(self._server_badge)
        bl.addStretch()

        self._user_lbl = QLabel("—")
        self._user_lbl.setStyleSheet(
            f"font-size: 12px; color: {_D['text_sec']}; background: transparent;"
        )
        bl.addWidget(self._user_lbl); bl.addSpacing(14)

        logout_btn = QPushButton()
        logout_btn.setIcon(svg_icon("logout", 14, _D["text_sec"]))
        logout_btn.setFixedSize(30, 30)
        logout_btn.setCursor(Qt.PointingHandCursor)
        logout_btn.setToolTip("Sign out")
        logout_btn.setStyleSheet(f"""
            QPushButton {{
                background: {_D['bg_surface']};
                border-radius: 8px;
                border: 1px solid {_D['border']};
            }}
            QPushButton:hover {{
                background: {_D['bg_input']};
                border-color: {_D['border_hi']};
            }}
        """)
        logout_btn.clicked.connect(self.do_logout)
        bl.addWidget(logout_btn)

        parent_layout.addWidget(bar)

    def set_dns(self, dns: str):
        self._dr_dns.set_value(dns)

    def _update_network_stats(self):
        if self._conn_state == "connected":
            rx, tx = get_wg_transfer("tornado_vpn")
            self._stats_panel.c_down.set_value(format_bytes(rx))
            self._stats_panel.c_up.set_value(format_bytes(tx))

    def _build_left(self, parent_layout):
        panel = QWidget()
        panel.setFixedWidth(295)
        panel.setStyleSheet(f"background: {_D['bg_main']};")

        pl = QVBoxLayout(panel)
        pl.setContentsMargins(22, 26, 22, 24)
        pl.setSpacing(0)

        sec1 = QLabel("CONNECTION STATUS")
        sec1.setStyleSheet(
            f"font-size: 9px; font-weight: 800; color: {_D['text_ter']}; "
            f"letter-spacing: 1.8px; background: transparent;"
        )
        pl.addWidget(sec1)
        pl.addSpacing(14)

        status_row = QWidget()
        status_row.setFixedHeight(22)
        status_row.setStyleSheet("background: transparent;")
        sr_lay = QHBoxLayout(status_row)
        sr_lay.setContentsMargins(0, 0, 0, 0)
        sr_lay.setSpacing(8)

        self._dot = StatusDot()
        self._status_lbl = QLabel("NOT PROTECTED")
        self._status_lbl.setStyleSheet(
            f"font-size: 11px; font-weight: 800; color: {_D['red']}; "
            f"letter-spacing: 0.6px; background: transparent;"
        )
        sr_lay.addWidget(self._dot, alignment=Qt.AlignVCenter)
        sr_lay.addWidget(self._status_lbl, alignment=Qt.AlignVCenter)
        sr_lay.addStretch()
        pl.addWidget(status_row)
        pl.addSpacing(5)

        self._sub_lbl = QLabel("Your traffic is exposed")
        self._sub_lbl.setStyleSheet(
            f"font-size: 11px; color: {_D['text_ter']}; background: transparent;"
        )
        self._sub_lbl.setWordWrap(True)
        pl.addWidget(self._sub_lbl)
        pl.addSpacing(20)

        pl.addWidget(self._hr())
        pl.addSpacing(16)

        self._dr_server   = DataRow("Server")
        self._dr_ip       = DataRow("VPN TUNNEL IP")
        self._dr_dns      = DataRow("DNS Server")
        self._dr_duration = DataRow("Duration", "00:00:00")

        for row in (self._dr_server, self._dr_ip, self._dr_dns, self._dr_duration):
            pl.addWidget(row)

        pl.addSpacing(16)
        pl.addWidget(self._hr())
        pl.addStretch(1)

        self._action_btn = QPushButton("Connect")
        self._action_btn.setFixedHeight(50)
        self._action_btn.setCursor(Qt.PointingHandCursor)
        btn_shadow = QGraphicsDropShadowEffect(self._action_btn)
        btn_shadow.setBlurRadius(20)
        btn_shadow.setOffset(0, 4)
        btn_shadow.setColor(QColor(255, 153, 0, 70))
        self._action_btn.setGraphicsEffect(btn_shadow)
        self._action_btn.setStyleSheet(self._btn_connect_style())
        self._action_btn.clicked.connect(self._on_action)
        pl.addWidget(self._action_btn)
        pl.addSpacing(12)

        tor_card = QWidget()
        tor_card.setStyleSheet(f"""
            QWidget {{
                background: {_D['bg_panel']};
                border-radius: 10px;
                border: 1px solid {_D['border']};
            }}
        """)
        tc_lay = QHBoxLayout(tor_card)
        tc_lay.setContentsMargins(12, 10, 12, 10)

        self._tor_toggle = TorToggle()
        self._tor_toggle.toggled.connect(self._on_tor_toggled)
        tc_lay.addWidget(self._tor_toggle)
        pl.addWidget(tor_card)
        pl.addStretch(1)

        wg_card = QWidget()
        wg_card.setStyleSheet(f"""
            QWidget {{
                background: {_D['bg_surface']};
                border-radius: 8px;
                border: 1px solid {_D['border']};
            }}
        """)
        wg_lay = QHBoxLayout(wg_card)
        wg_lay.setContentsMargins(12, 8, 12, 8)
        wg_lay.setSpacing(8)

        wg_ic = QLabel()
        wg_ic.setPixmap(svg_pixmap("key", 13, _D["text_ter"]))
        wg_ic.setFixedSize(15, 15)
        wg_ic.setAlignment(Qt.AlignCenter)
        wg_ic.setStyleSheet("background: transparent; border: none;")

        wg_txt = QLabel("Secured by WireGuard®")
        wg_txt.setStyleSheet(
            f"font-size: 10px; color: {_D['text_ter']}; background: transparent; border: none;"
        )
        wg_lay.addWidget(wg_ic); wg_lay.addWidget(wg_txt); wg_lay.addStretch()
        pl.addWidget(wg_card)

        parent_layout.addWidget(panel)

    def _build_right(self, parent_layout):
        panel = QWidget()
        panel.setStyleSheet(f"background: {_D['bg_main']};")
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(22, 26, 22, 24)
        pl.setSpacing(0)

        topo_hdr = QLabel("NETWORK PATH")
        topo_hdr.setStyleSheet(
            f"font-size: 9px; font-weight: 800; color: {_D['text_ter']}; "
            f"letter-spacing: 1.8px; background: transparent;"
        )
        pl.addWidget(topo_hdr)
        pl.addSpacing(10)

        topo_card = QWidget()
        topo_card.setStyleSheet(f"""
            QWidget {{
                background: {_D['bg_panel']};
                border-radius: 14px;
                border: 1px solid {_D['border']};
            }}
        """)
        tc_shadow = QGraphicsDropShadowEffect()
        tc_shadow.setBlurRadius(20)
        tc_shadow.setOffset(0, 4)
        tc_shadow.setColor(QColor(0, 0, 0, 80))
        topo_card.setGraphicsEffect(tc_shadow)

        tc_lay = QVBoxLayout(topo_card)
        tc_lay.setContentsMargins(12, 12, 12, 12)

        self._topology = TopologyView()
        tc_lay.addWidget(self._topology)
        pl.addWidget(topo_card)
        pl.addSpacing(20)

        stats_hdr_row = QHBoxLayout()
        stats_hdr_row.setContentsMargins(0, 0, 0, 0)
        stats_hdr_row.setSpacing(8)

        stats_hdr = QLabel("SESSION STATISTICS")
        stats_hdr.setStyleSheet(
            f"font-size: 9px; font-weight: 800; color: {_D['text_ter']}; "
            f"letter-spacing: 1.8px; background: transparent;"
        )
        stats_hdr_row.addWidget(stats_hdr)
        stats_hdr_row.addStretch()

        self._live_badge = QWidget()
        self._live_badge.setFixedSize(60, 22)
        self._live_badge.setStyleSheet(f"""
            QWidget {{
                background: {_D['green_dim']};
                border-radius: 6px;
                border: 1px solid {_D['green']}40;
            }}
        """)
        lb_lay = QHBoxLayout(self._live_badge)
        lb_lay.setContentsMargins(6, 0, 6, 0)
        lb_lay.setSpacing(4)

        live_dot = QLabel("●")
        live_dot.setStyleSheet(
            f"font-size: 7px; color: {_D['green']}; background: transparent;"
        )
        live_txt = QLabel("LIVE")
        live_txt.setStyleSheet(
            f"font-size: 9px; font-weight: 800; color: {_D['green']}; "
            f"letter-spacing: 0.8px; background: transparent;"
        )
        lb_lay.addWidget(live_dot, alignment=Qt.AlignVCenter)
        lb_lay.addWidget(live_txt, alignment=Qt.AlignVCenter)

        self._live_badge.setVisible(False)
        stats_hdr_row.addWidget(self._live_badge, alignment=Qt.AlignVCenter)

        pl.addLayout(stats_hdr_row)
        pl.addSpacing(10)

        self._stats_panel = SessionStatsPanel()
        pl.addWidget(self._stats_panel)
        pl.addStretch()

        parent_layout.addWidget(panel)

    @staticmethod
    def _hr() -> QFrame:
        f = QFrame()
        f.setFrameShape(QFrame.HLine)
        f.setFixedHeight(1)
        f.setStyleSheet(f"background: {_D['border']}; border: none;")
        return f

    def _btn_connect_style(self) -> str:
        return f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FFB333, stop:1 #FF9900);
                color: {_D['bg_main']};
                border-radius: 12px;
                font-size: 14px; font-weight: 800;
                letter-spacing: 0.5px; border: none;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FFC266, stop:1 #FFB333);
            }}
            QPushButton:pressed  {{ background: #E68A00; }}
            QPushButton:disabled {{
                background: {_D['bg_surface']};
                color: {_D['text_ter']};
                border: 1px solid {_D['border']};
            }}
        """

    def _btn_disconnect_style(self) -> str:
        return f"""
            QPushButton {{
                background: transparent;
                color: {_D['red']};
                border-radius: 12px;
                font-size: 14px; font-weight: 800;
                letter-spacing: 0.5px;
                border: 2px solid {_D['red']};
            }}
            QPushButton:hover   {{ background: {_D['red_dim']}; }}
            QPushButton:pressed {{ background: rgba(248, 81, 73, 0.2); }}
            QPushButton:disabled {{
                background: {_D['bg_surface']};
                color: {_D['text_ter']};
                border: 1px solid {_D['border']};
            }}
        """

    def _btn_connecting_style(self) -> str:
        return f"""
            QPushButton {{
                background: {_D['amber_dim']};
                color: {_D['amber']};
                border-radius: 12px;
                font-size: 14px; font-weight: 800;
                letter-spacing: 0.5px;
                border: 1px solid {_D['amber']};
            }}
        """

    def _on_tor_toggled(self, enabled: bool):
        self._topology.set_tor_enabled(enabled)
        self.tor_toggled.emit(enabled)

    def _on_action(self):
        if self._conn_state == "disconnected":
            self.do_connect.emit()
        elif self._conn_state == "connected":
            self.do_disconnect.emit()

    def get_state(self) -> str:
        return self._conn_state

    def set_username(self, name: str):
        self._user_lbl.setText(name)

    def set_vpn_data(self, data: dict, tor_mode: bool = False):
        vpn_section = data.get("vpn", {})
        tor_section = data.get("tor", {})

        vpn_ip       = vpn_section.get("ip", "—")
        vpn_endpoint = vpn_section.get("endpoint", "—")
        vpn_host     = vpn_endpoint.split(":")[0] if ":" in vpn_endpoint else vpn_endpoint
        tor_ip       = tor_section.get("ip", "—")
        primary_ip   = tor_ip if tor_mode else vpn_ip

        self._dr_ip.set_value(primary_ip)
        self._dr_server.set_value(vpn_host or "—")
        self._stats_panel.c_ip.set_value(primary_ip)
        self._stats_panel.c_server.set_value(vpn_host or "—")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "—"

        self._topology.set_ips({
            "user": local_ip,
            "vpn":  vpn_host or "—",
            "tor":  "—",
            "web":  "—",
        })

    def is_tor_enabled(self) -> bool:
        return self._tor_toggle.is_on()

    def go_connecting(self):
        self._conn_state = "connecting"
        self._dot.set_state("connecting")
        self._live_badge.setVisible(False)
        self._topology.reset_all()
        self._topology.set_connected(False)
        self._topology.set_node_state("pc", "blinking_yellow")
        self._topology.animate_line(
            "vpn", _D["amber"],
            lambda: self._topology.set_node_state("vpn", "blinking_orange"),
        )
        self._status_lbl.setText("CONNECTING")
        self._status_lbl.setStyleSheet(
            f"font-size: 11px; font-weight: 800; color: {_D['amber']}; "
            f"letter-spacing: 0.6px; background: transparent;"
        )
        self._sub_lbl.setText("Establishing encrypted tunnel…")
        self._sub_lbl.setStyleSheet(
            f"font-size: 11px; color: {_D['text_ter']}; background: transparent;"
        )
        self._server_badge.setText("● Connecting…")
        self._server_badge.setStyleSheet(
            f"font-size: 11px; color: {_D['amber']}; background: transparent; font-weight: 600;"
        )
        self._action_btn.setEnabled(False)
        self._action_btn.setText("Connecting…")
        self._action_btn.setStyleSheet(self._btn_connecting_style())
        self._tor_toggle.setEnabled(False)

    def go_connected(self):
        self._conn_state = "connected"
        self._dot.set_state("connected")
        self._live_badge.setVisible(True)
        self._topology.set_node_state("pc", "success")
        self._topology.animate_line("vpn", _D["green_hi"], self._step2)
        self._status_lbl.setText("PROTECTED")
        self._status_lbl.setStyleSheet(
            f"font-size: 11px; font-weight: 800; color: {_D['green']}; "
            f"letter-spacing: 0.6px; background: transparent;"
        )
        self._sub_lbl.setText("All traffic is encrypted")
        self._sub_lbl.setStyleSheet(
            f"font-size: 11px; color: {_D['text_sec']}; background: transparent;"
        )
        self._server_badge.setText("● Secured")
        self._server_badge.setStyleSheet(
            f"font-size: 11px; color: {_D['green']}; background: transparent; font-weight: 600;"
        )
        self._action_btn.setEnabled(True)
        self._action_btn.setText("Disconnect")
        self._action_btn.setStyleSheet(self._btn_disconnect_style())
        self._elapsed.start()
        self._tor_toggle.setEnabled(True)

    def _step2(self):
        self._topology.set_node_state("vpn", "vpn_success")
        if self._topology._tor_enabled:
            self._topology.animate_line("tor", _D["tor"], self._step3)
        else:
            self._topology.animate_line("web", _D["green_hi"], self._step4)

    def _step3(self):
        self._topology.set_node_state("tor", "tor_success")
        self._topology.animate_line("web", _D["tor"], self._step4)

    def _step4(self):
        self._topology.set_node_state("web", "success")
        self._topology.set_connected(True)

    def go_disconnected(self, error: Optional[str] = None):
        self._conn_state = "disconnected"
        self._dot.set_state("disconnected")
        self._live_badge.setVisible(False)
        self._topology.reset_all()
        self._status_lbl.setText("NOT PROTECTED")
        self._status_lbl.setStyleSheet(
            f"font-size: 11px; font-weight: 800; color: {_D['red']}; "
            f"letter-spacing: 0.6px; background: transparent;"
        )
        if error:
            self._sub_lbl.setText(error[:70])
            self._sub_lbl.setStyleSheet(
                f"font-size: 11px; color: {_D['red']}; background: transparent;"
            )
        else:
            self._sub_lbl.setText("Your traffic is exposed")
            self._sub_lbl.setStyleSheet(
                f"font-size: 11px; color: {_D['text_ter']}; background: transparent;"
            )
        self._server_badge.setText("● Not connected")
        self._server_badge.setStyleSheet(
            f"font-size: 11px; color: {_D['red']}; background: transparent; font-weight: 600;"
        )
        self._action_btn.setEnabled(True)
        self._action_btn.setText("Connect")
        self._action_btn.setStyleSheet(self._btn_connect_style())
        self._dr_server.set_value("—"); self._dr_ip.set_value("—")
        self._dr_dns.set_value("—")
        self._stats_panel.c_ip.set_value("—")
        self._stats_panel.c_server.set_value("—")
        self._elapsed.stop()
        self._dr_duration.set_value("00:00:00")
        self._stats_panel.c_time.set_value("00:00:00")
        self._stats_panel.c_down.set_value("0 B")
        self._stats_panel.c_up.set_value("0 B")
        self._tor_toggle.setEnabled(True)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "—"
        self._topology.set_ips({"user": local_ip, "vpn": "—", "tor": "—", "web": "—"})


# ═══════════════════════════════════════════════════════════════════════════
# §11  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    # Fallback path used only when keyring is unavailable
    _CFG_PATH = os.path.expanduser("~/.tornado_vpn_session.json")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Tornado VPN CLIENT")
        self.setFixedSize(960, 660)

        if CUSTOM_LOGO_PATH and os.path.isfile(CUSTOM_LOGO_PATH):
            self.setWindowIcon(QIcon(CUSTOM_LOGO_PATH))
        else:
            pm = QPixmap(32, 32)
            pm.fill(QColor(_D["green"]))
            self.setWindowIcon(QIcon(pm))

        self._api:          Optional[TornadoAPI] = None
        self._priv_key:     Optional[str]        = None
        self._conf_path:    Optional[str]        = None
        self._workers:      list                 = []
        self._vpn_config:   Optional[dict]       = None
        self._tor_config:   Optional[dict]       = None
        self._last_vpn_data: Optional[dict]      = None
        self._username:     Optional[str]        = None
        self._reauth_in_flight: bool             = False

        self._hb = QTimer(self)
        self._hb.timeout.connect(self._heartbeat)

        self._auth_timer = QTimer(self)
        self._auth_timer.setSingleShot(True)
        self._auth_timer.timeout.connect(self._do_reauth)

        self._stack = SlidingStack()
        self._login = LoginPage()
        self._dash  = DashboardPage()
        self._stack.addWidget(self._login)
        self._stack.addWidget(self._dash)
        self.setCentralWidget(self._stack)

        self._login.do_login.connect(self._do_login)
        self._dash.do_connect.connect(self._do_connect)
        self._dash.do_disconnect.connect(self._do_disconnect)
        self._dash.do_logout.connect(self._do_logout)
        self._dash.tor_toggled.connect(self._on_tor_toggled)

        self._check_saved_session()

    # ── Endpoint resolution ───────────────────────────────────────────────

    def _resolve_endpoint(self, cfg: dict) -> str:
        """Forces the login-server IP, preventing endpoint-redirect attacks."""
        endpoint = cfg.get("endpoint", "")
        api_port = (endpoint.split(":")[-1] if ":" in endpoint
                    else str(DEFAULT_PORT))
        if self._api and self._api.host:
            return f"{self._api.host}:{api_port}"
        return endpoint

    def _derive_dns(self, ip_str: str) -> str:
        """Converts a client IP (e.g. 10.8.0.5) to its gateway (10.8.0.1)."""
        if not ip_str or ip_str.count(".") != 3:
            return ""
        return ip_str.rsplit(".", 1)[0] + ".1"

    # ── Session persistence (keyring → file fallback) ─────────────────────

    def _save_session(self, server: str, username: str, refresh_token: str):
        data = json.dumps({
            "server": server,
            "username": username,
            "refresh_token": refresh_token,
        })
        if _HAS_KEYRING:
            try:
                keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT, data)
                log.info("[Auth] Session saved to system keyring.")
                return
            except Exception as e:
                log.warning(f"[Auth] keyring save failed ({e}), falling back to file.")
        # FIX: Atomic file creation with correct permissions — no TOCTOU window
        try:
            fd = os.open(
                self._CFG_PATH,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w") as f:
                f.write(data)
            log.info("[Auth] Session saved to file (keyring unavailable).")
        except Exception as e:
            log.error(f"[Auth] Failed to save session: {e}")

    def _load_session(self) -> Optional[dict]:
        if _HAS_KEYRING:
            try:
                data = keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
                if data:
                    return json.loads(data)
            except Exception as e:
                log.warning(f"[Auth] keyring load failed: {e}")
        if os.path.exists(self._CFG_PATH):
            try:
                with open(self._CFG_PATH, "r") as f:
                    return json.loads(f.read())
            except Exception as e:
                log.error(f"[Auth] Failed to load session file: {e}")
        return None

    def _clear_session(self):
        if _HAS_KEYRING:
            try:
                keyring.delete_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
            except Exception:
                pass  # key may not exist — that's fine
        if os.path.exists(self._CFG_PATH):
            try:
                os.remove(self._CFG_PATH)
            except Exception as e:
                log.error(f"[Auth] Failed to remove session file: {e}")

    # ── JWT scheduling & reauth ───────────────────────────────────────────

    def _check_saved_session(self):
        cfg = self._load_session()
        if not cfg:
            return

        srv = cfg.get("server")
        rt  = cfg.get("refresh_token")
        if not srv or not rt:
            return

        self._login._set_busy(True)
        self._api               = TornadoAPI(srv)
        self._api.refresh_token = rt
        self._username          = cfg.get("username", "user")
        self._dash.set_username(self._username)

        w = ReauthWorker(self._api)
        w.success.connect(self._on_startup_reauth_ok)
        w.failed.connect(self._on_startup_reauth_fail)
        self._keep(w)

    def _on_startup_reauth_ok(self, data: dict):
        log.info("[Auth] Saved session restored successfully.")
        if self._api and self._username:
            self._save_session(self._api.base_url, self._username, self._api.refresh_token)
        self._login.reset()
        self._schedule_token_refresh()
        self._stack.slide_to(1, forward=False)

    def _on_startup_reauth_fail(self, msg: str):
        log.warning(f"[Auth] Saved session expired: {msg}")
        self._clear_session()
        self._api = None
        self._login.reset()

    def _schedule_token_refresh(self):
        if not self._api or not self._api.access_token:
            return
        exp_timestamp   = extract_jwt_exp(self._api.access_token)
        seconds_left    = exp_timestamp - int(time.time())
        refresh_in_secs = max(seconds_left - 60, 0)

        if refresh_in_secs == 0:
            self._do_reauth()
        else:
            log.info(
                f"[Auth] Token expires in {seconds_left}s. "
                f"Refresh scheduled in {refresh_in_secs}s."
            )
            self._auth_timer.start(refresh_in_secs * 1000)

    def _do_reauth(self):
        if not self._api:
            return
        # FIX: Guard prevents duplicate in-flight reauth requests
        if self._reauth_in_flight:
            log.info("[Auth] Reauth already in flight — ignoring duplicate request.")
            return
        self._reauth_in_flight = True
        w = ReauthWorker(self._api)
        w.success.connect(self._on_reauth_ok)
        w.failed.connect(self._on_reauth_fail)
        self._keep(w)

    def _on_reauth_ok(self, data: dict):
        self._reauth_in_flight = False
        log.info("[Auth] Access token refreshed silently.")
        if self._api and self._username:
            self._save_session(self._api.base_url, self._username, self._api.refresh_token)
        self._schedule_token_refresh()

    def _on_reauth_fail(self, msg: str):
        self._reauth_in_flight = False
        log.warning(f"[Auth] Silent reauth failed: {msg}")
        self._do_logout()
        self._login.show_error("Session expired. Please sign in again.")

    # ── Login flow ────────────────────────────────────────────────────────

    def _do_login(self, srv: str, user: str, pw: str):
        self._api = TornadoAPI(srv)
        w = LoginWorker(self._api, user, pw)
        w.success.connect(self._on_login_ok)
        w.failed.connect(self._on_login_fail)
        self._keep(w)

    def _on_login_ok(self, data: dict):
        self._username = data.get("user", {}).get("username", "user")
        self._dash.set_username(self._username)
        self._login.reset()
        self._save_session(self._api.base_url, self._username, self._api.refresh_token)
        self._schedule_token_refresh()
        self._stack.slide_to(1, forward=True)

    def _on_login_fail(self, msg: str):
        self._login.show_error(f"Login failed: {msg}")

    # ── VPN connect flow ──────────────────────────────────────────────────

    def _do_connect(self):
        self._dash.go_connecting()
        priv, pub = generate_keypair()
        self._priv_key = priv
        w = ConnectWorker(self._api, pub)
        w.success.connect(self._on_vpn_ok)
        w.failed.connect(self._on_vpn_fail)
        self._keep(w)

    def _on_vpn_ok(self, data: dict):
        self._vpn_config    = data.get("vpn", {})
        self._tor_config    = data.get("tor", {})
        self._last_vpn_data = data

        session_info  = data.get("session", {})
        heartbeat_ttl = session_info.get("heartbeat_ttl", 60)
        self._hb.setInterval((heartbeat_ttl // 2) * 1000)

        tor_mode = self._dash.is_tor_enabled()
        cfg      = self._tor_config if tor_mode else self._vpn_config

        self._dash.set_vpn_data(data, tor_mode=tor_mode)

        resolved_endpoint = self._resolve_endpoint(cfg)
        active_dns        = self._derive_dns(cfg.get("ip", "")) or "1.1.1.1"
        self._dash.set_dns(active_dns)

        path = write_wg_config(
            private_key     = self._priv_key,
            vpn_ip          = cfg.get("ip", ""),
            server_pubkey   = cfg.get("server_pubkey", ""),
            server_endpoint = resolved_endpoint,
            dns             = active_dns,
        )
        self._conf_path = path
        wt = WgThread(path, "up")
        wt.done.connect(self._on_wg_up)
        self._keep(wt)

    def _on_wg_up(self, ok: bool, msg: str):
        if ok:
            self._dash.go_connected()
            if self._last_vpn_data:
                tor_mode = self._dash.is_tor_enabled()
                self._dash.set_vpn_data(self._last_vpn_data, tor_mode=tor_mode)
            self._hb.start()
        else:
            self._dash.go_disconnected(f"WireGuard: {msg[:60]}")

    def _on_vpn_fail(self, msg: str):
        self._dash.go_disconnected(f"Server error: {msg[:70]}")

    # ── Disconnect flow ───────────────────────────────────────────────────

    def _do_disconnect(self, on_down=None):
        """
        FIX: Brings the WG interface down asynchronously.
        - The 'done' signal is always connected (was missing before).
        - _conf_path is reset immediately to prevent double-teardown.
        - Optional on_down callback is invoked after the interface is confirmed down,
          eliminating the 800ms blind timer that caused the reconnect race condition.
        """
        self._hb.stop()
        self._dash.go_disconnected()

        conf = self._conf_path
        self._conf_path = None  # Reset immediately — prevents double teardown

        if conf:
            wt = WgThread(conf, "down")

            def _handle_down(ok: bool, msg: str):
                log.info(f"[WG] Interface down: ok={ok} msg={msg}")
                if on_down:
                    on_down()

            wt.done.connect(_handle_down)
            self._keep(wt)
        else:
            # No interface was up — fire callback immediately if requested
            if on_down:
                QTimer.singleShot(0, on_down)

    # ── Tor toggle ────────────────────────────────────────────────────────

    def _on_tor_toggled(self, enabled: bool):
        if self._dash.get_state() != "connected":
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Routing Mode Changed")
        msg.setText(
            "Switched to <b>Tor routing</b>." if enabled
            else "Switched to <b>Standard VPN</b>."
        )
        msg.setInformativeText("Reconnect to apply the new routing configuration?")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setDefaultButton(QMessageBox.Yes)
        msg.setStyleSheet(f"""
            QMessageBox {{ background: {_D['bg_panel']}; }}
            QLabel {{ color: {_D['text_pri']}; font-size: 13px; }}
            QPushButton {{
                background: {_D['green']}; color: {_D['bg_main']};
                border-radius: 8px; padding: 6px 18px;
                font-weight: 700; border: none;
            }}
            QPushButton:hover {{ background: {_D['green_hi']}; }}
        """)
        if msg.exec_() == QMessageBox.Yes:
            # FIX: Pass reconnect as a callback so it fires AFTER wg-quick down
            # confirms the interface is down — no blind 800ms timer.
            self._do_disconnect(on_down=self._reconnect_after_toggle)

    def _reconnect_after_toggle(self):
        """
        FIX: Called from WgThread.done — the interface is guaranteed to be
        down before this runs, eliminating the 'device busy' race condition.
        """
        if not self._vpn_config and not self._tor_config:
            return
        tor_mode = self._dash.is_tor_enabled()
        cfg = self._tor_config if tor_mode else self._vpn_config
        if not cfg:
            return

        self._dash.go_connecting()
        resolved_endpoint = self._resolve_endpoint(cfg)
        active_dns        = self._derive_dns(cfg.get("ip", "")) or "1.1.1.1"
        self._dash.set_dns(active_dns)

        path = write_wg_config(
            private_key     = self._priv_key,
            vpn_ip          = cfg.get("ip", ""),
            server_pubkey   = cfg.get("server_pubkey", ""),
            server_endpoint = resolved_endpoint,
            dns             = active_dns,
        )
        self._conf_path = path
        wt = WgThread(path, "up")
        wt.done.connect(self._on_wg_up)
        self._keep(wt)

    # ── Heartbeat ─────────────────────────────────────────────────────────

    def _heartbeat(self):
        if not self._api:
            return
        w = HeartbeatWorker(self._api)
        w.success.connect(self._on_heartbeat_ok)
        w.failed.connect(self._on_heartbeat_fail)
        self._keep(w)

    def _on_heartbeat_ok(self, data: dict):
        status = data.get("status")
        if status == "reconnected":
            log.info("[Heartbeat] Server recovered our session successfully.")
        else:
            log.debug("[Heartbeat] OK")

    def _on_heartbeat_fail(self, msg: str):
        log.warning(f"[Heartbeat] Failed: {msg}")

        # FIX: Consolidated and deduplicated condition checks.
        # Try a silent token refresh first for any auth-rejection signals.
        reauth_triggers = ["invalid_token", "Authentication failed"]
        if any(t in msg for t in reauth_triggers):
            log.info("[Heartbeat] Token rejected — attempting reactive refresh.")
            self._do_reauth()
            return

        # Truly fatal session errors that require a full logout.
        fatal_triggers = ["session_expired", "Session expired"]
        if any(t in msg for t in fatal_triggers):
            log.warning("[Heartbeat] Fatal session error — forcing logout.")
            self._do_logout()
            self._login.show_error(
                "Your session was terminated by the server. Please sign in again."
            )
            return

        # Transient network / connection error — WireGuard is stateless,
        # so we do NOT disconnect; we just wait for the next heartbeat tick.
        log.info("[Heartbeat] Transient error — will retry on next tick.")

    # ── Logout flow ───────────────────────────────────────────────────────

    def _do_logout(self):
        """
        FIX: All teardown is now asynchronous — no UI thread blocking.
        Previously wg_down() was called synchronously (15-second potential freeze).
        """
        # Guard: already logged out
        if self._api is None and self._stack.currentIndex() == 0:
            return

        self._hb.stop()
        if self._auth_timer.isActive():
            self._auth_timer.stop()

        # FIX: Async WG teardown — fire and continue
        conf = self._conf_path
        self._conf_path = None
        if conf:
            wt = WgThread(conf, "down")
            wt.done.connect(
                lambda ok, msg: log.info(f"[WG] logout down: ok={ok} msg={msg}")
            )
            self._keep(wt)

        # Fire logout API call non-blocking
        if self._api:
            w = LogoutWorker(self._api)
            w.success.connect(lambda d: log.info("[Auth] Logout confirmed by server."))
            w.failed.connect(lambda m: log.warning(f"[Auth] Logout API call failed: {m}"))
            self._keep(w)
            self._api = None

        self._vpn_config    = None
        self._tor_config    = None
        self._priv_key      = None
        self._last_vpn_data = None
        self._username      = None
        self._reauth_in_flight = False

        self._clear_session()
        self._dash.go_disconnected()
        self._stack.slide_to(0, forward=False)

    # ── Worker lifetime management ────────────────────────────────────────

    def _keep(self, worker: QThread):
        """
        FIX: Workers are now cleaned up via their finished signal instead of
        being eagerly removed on the next _keep() call.  The old approach
        could GC a worker while its signals were still queued in the event
        loop, causing silent drops or segfaults.
        """
        self._workers.append(worker)

        def _prune():
            try:
                self._workers.remove(worker)
            except ValueError:
                pass  # already pruned

        worker.finished.connect(_prune)
        worker.start()

    # ── App close ─────────────────────────────────────────────────────────

    def closeEvent(self, event):
        """
        FIX: Uses non-blocking Popen instead of subprocess.run to avoid
        freezing the UI on close.  We do not logout here so the "remember me"
        session is preserved for the next launch.
        """
        self._hb.stop()
        if self._auth_timer.isActive():
            self._auth_timer.stop()

        conf = self._conf_path
        self._conf_path = None

        if conf and self._dash.get_state() == "connected":
            try:
                subprocess.Popen(
                    ["sudo", "wg-quick", "down", conf],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                log.error(f"[closeEvent] wg-quick down failed to launch: {e}")

        event.accept()


# ═══════════════════════════════════════════════════════════════════════════
# §12  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps,    True)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    if sys.platform == "win32":
        app.setFont(QFont("Segoe UI", 10))
    elif sys.platform == "darwin":
        app.setFont(QFont("SF Pro Display", 11))
    else:
        app.setFont(QFont("Ubuntu", 10))

    pal = app.palette()
    pal.setColor(pal.Window,        QColor(_D["bg_main"]))
    pal.setColor(pal.Base,          QColor(_D["bg_panel"]))
    pal.setColor(pal.AlternateBase, QColor(_D["bg_surface"]))
    pal.setColor(pal.WindowText,    QColor(_D["text_pri"]))
    pal.setColor(pal.Text,          QColor(_D["text_pri"]))
    pal.setColor(pal.Button,        QColor(_D["bg_surface"]))
    pal.setColor(pal.ButtonText,    QColor(_D["text_pri"]))
    app.setPalette(pal)

    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()