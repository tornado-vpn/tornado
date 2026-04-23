# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import grp
import uuid
import signal
import stat
from typing import Dict

from utils.wg_logging_utils import get_logger, get_context_logger

# ================= CONFIG =================

_CONFIG_PATH = os.environ.get("WG_MANAGER_CONFIG", "wg_manager_config.json")
_SESSION_CONFIG_PATH = os.environ.get("SESSION_MANAGER_CONFIG", "session_manager_config.json")
_ENV_PATH = "/opt/tornado/.env"

def _load_dotenv(path: str) -> None:
    """Manually load key=value pairs from a .env file into os.environ."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())
    except FileNotFoundError:
        pass  # not present in dev environments — that's fine

_load_dotenv(_ENV_PATH)

def _load_config(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"WG Manager config not found: {path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"WG Manager config is malformed: {e}")


_cfg = _load_config(_CONFIG_PATH)

_session_cfg = _load_config(_SESSION_CONFIG_PATH)

# Socket
SOCKET_DIR      = _cfg["socket"]["dir"]
WG_SOCKET_PATH  = _cfg["socket"]["path"]
SOCKET_GROUP    = _cfg["socket"]["group"]
SOCKET_DIR_MODE = int(_cfg["socket"]["dir_mode"], 8)
SOCKET_PERMS    = int(_cfg["socket"]["permissions"], 8)

# WireGuard binaries & paths
WG_BIN          = _cfg["wireguard"]["bin"]
WG_QUICK_BIN    = _cfg["wireguard"]["wg_quick_bin"]
WG_CONF_DIR     = _cfg["wireguard"]["conf_dir"]
WG_KEYS_DIR     = _cfg["wireguard"]["keys_dir"]
OUTBOUND_IFACE = os.environ.get("OUTBOUND_IFACE") or _cfg["wireguard"].get("outbound_iface", "eth0")
HAPROXY_PORT    = _cfg["wireguard"]["haproxy_port"]

# Dual interfaces
#   wg0 → Remote-access VPN   (vpn_cidr  10.8.0.0/24  from IPAM vpn pool)
#   wg1 → HAProxy routing     (tor_cidr  10.9.0.0/24  from IPAM tor pool)
WG_IFACE_VPN   = _cfg["wireguard"]["interfaces"]["vpn"]    # "wg0"
WG_IFACE_PROXY = _cfg["wireguard"]["interfaces"]["proxy"]  # "wg1"

# Derived paths
WG0_CONF_PATH   = os.path.join(WG_CONF_DIR,  f"{WG_IFACE_VPN}.conf")
WG1_CONF_PATH   = os.path.join(WG_CONF_DIR,  f"{WG_IFACE_PROXY}.conf")
WG0_KEY_PATH    = os.path.join(WG_KEYS_DIR,  f"{WG_IFACE_VPN}.key")
WG1_KEY_PATH    = os.path.join(WG_KEYS_DIR,  f"{WG_IFACE_PROXY}.key")

# Upstream sockets
IPAM_SOCKET_PATH    = _cfg["upstream"]["ipam_socket"]
SESSION_SOCKET_PATH = _cfg["upstream"]["session_socket"]

SESSION_HEARTBEAT_TTL = _session_cfg.get("session", {}).get("heartbeat_ttl", 90)
SESSION_HARD_TTL      = _session_cfg.get("session", {}).get("hard_ttl", 300)

SERVER_PUBKEYS = {"vpn": "", "tor": ""}
# ==========================================

logger = get_logger()


# ─────────────────────────────────────────
#  WG CONF TEMPLATES
# ─────────────────────────────────────────

def _wg0_conf(private_key: str) -> str:
    """
    Generates wg0.conf content.
    Role      : Remote-access VPN
    Pool      : 10.8.0.0/24  (vpn:ipam:pool:vpn in Redis)
    NOTE: wg_manager only calls `wg set` at runtime — it never touches
          iptables directly. All firewall/NAT rules live here exclusively.
    """
    return f"""\
# /etc/wireguard/{WG_IFACE_VPN}.conf
# Interface : {WG_IFACE_VPN}
# Role      : Remote-access VPN
# Pool      : 10.8.0.0/24  (vpn:ipam:pool:vpn in Redis)
# Managed by: wg_manager via `wg set {WG_IFACE_VPN} peer <key> allowed-ips <vpn_ip>/32`
#
# NOTE: wg_manager only calls `wg set` — it never touches iptables.
#       All firewall/NAT rules live here in PostUp/PostDown exclusively.
[Interface]
Address    = 10.8.0.1/24
ListenPort = 51820
PrivateKey = {private_key}
# ── NAT: let VPN clients reach the internet ──────────────────────────────────
PostUp   = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o {OUTBOUND_IFACE} -j MASQUERADE
PostUp   = iptables -A FORWARD -i {WG_IFACE_VPN} -o {OUTBOUND_IFACE} -j ACCEPT
PostUp   = iptables -A FORWARD -i {OUTBOUND_IFACE} -o {WG_IFACE_VPN} -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o {OUTBOUND_IFACE} -j MASQUERADE || true
PostDown = iptables -D FORWARD -i {WG_IFACE_VPN} -o {OUTBOUND_IFACE} -j ACCEPT || true
PostDown = iptables -D FORWARD -i {OUTBOUND_IFACE} -o {WG_IFACE_VPN} -m state --state RELATED,ESTABLISHED -j ACCEPT || true
# Peers are added dynamically by wg_manager — do NOT add [Peer] blocks here.
"""


def _wg1_conf(private_key: str) -> str:

    return f"""\
# /etc/wireguard/{WG_IFACE_PROXY}.conf
# Interface : {WG_IFACE_PROXY}
# Role      : HAProxy routing (tor/proxy traffic lane)
# Pool      : 10.9.0.0/24  (vpn:ipam:pool:tor in Redis)
# Managed by: wg_manager via `wg set {WG_IFACE_PROXY} peer <key> allowed-ips <tor_ip>/32`
#
[Interface]
Address    = 10.9.0.1/24
ListenPort = 51821
PrivateKey = {private_key}

# -- Route Localnet (Required for the Python script's 127.0.0.1 DNAT to work) --
PostUp = sysctl -w net.ipv4.conf.%i.route_localnet=1

# -- The Baseline Tor Routing Rules --
# Redirect DNS (UDP 53) to Tor's DNSPort (Matches JSON config: 9053)
PostUp = iptables -t nat -A PREROUTING -i %i -p udp --dport 53 -j REDIRECT --to-ports 9053

# Redirect all TCP traffic to Tor's TransPort (Matches JSON config: 9040)
PostUp = iptables -t nat -A PREROUTING -i %i -p tcp -j REDIRECT --to-ports 9040

# -- Block QUIC/WebRTC Leaks --
# Instantly reject all other UDP traffic trying to route through the server.
# This forces browsers to immediately fall back to TCP for web traffic.
PostUp = iptables -A FORWARD -i %i -p udp -j REJECT --reject-with icmp-port-unreachable

# Cleanup on shutdown
PostDown = sysctl -w net.ipv4.conf.%i.route_localnet=0
PostDown = iptables -t nat -D PREROUTING -i %i -p udp --dport 53 -j REDIRECT --to-ports 9053
PostDown = iptables -t nat -D PREROUTING -i %i -p tcp -j REDIRECT --to-ports 9040
PostDown = iptables -D FORWARD -i %i -p udp -j REJECT --reject-with icmp-port-unreachable || true
"""


# ── Route wg1 traffic to HAProxy ─────────────────────────────────────────────
# PostUp   = iptables -A FORWARD -i {WG_IFACE_PROXY} -j ACCEPT
# PostUp   = iptables -t nat -A PREROUTING -i {WG_IFACE_PROXY} -s 10.9.0.0/24 -p tcp -j REDIRECT --to-port {HAPROXY_PORT}
# PostUp   = iptables -t nat -A PREROUTING -i {WG_IFACE_PROXY} -s 10.9.0.0/24 -p udp -j REDIRECT --to-port {HAPROXY_PORT}
# PostDown = iptables -D FORWARD -i {WG_IFACE_PROXY} -j ACCEPT || true
# PostDown = iptables -t nat -D PREROUTING -i {WG_IFACE_PROXY} -s 10.9.0.0/24 -p tcp -j REDIRECT --to-port {HAPROXY_PORT} || true
# PostDown = iptables -t nat -D PREROUTING -i {WG_IFACE_PROXY} -s 10.9.0.0/24 -p udp -j REDIRECT --to-port {HAPROXY_PORT} || true


# ─────────────────────────────────────────
#  KEY GENERATION
# ─────────────────────────────────────────

async def _generate_keypair() -> tuple[str, str]:
    """
    Generates a WireGuard keypair using the wg CLI.
    Returns (private_key, public_key) as stripped strings.

    Equivalent to:
      private=$(wg genkey)
      public=$(echo $private | wg pubkey)
    """
    # Generate private key
    proc = await asyncio.create_subprocess_exec(
        WG_BIN, "genkey",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            f"wg genkey failed: {stderr.decode().strip()}"
        )
    private_key = stdout.decode().strip()

    # Derive public key from private key
    proc = await asyncio.create_subprocess_exec(
        WG_BIN, "pubkey",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate(input=private_key.encode())
    if proc.returncode != 0:
        raise RuntimeError(
            f"wg pubkey failed: {stderr.decode().strip()}"
        )
    public_key = stdout.decode().strip()

    return private_key, public_key


def _write_key_file(path: str, private_key: str) -> None:
    """
    Writes a private key to disk with 0o600 permissions (owner-read only).
    Always overwrites — no append.
    """
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    # Open with O_CREAT | O_WRONLY | O_TRUNC so the file is never world-readable
    # even for a brief window before chmod.
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(private_key + "\n")
    except Exception:
        os.close(fd)
        raise


def _read_key_file(path: str) -> str:
    """Reads a private key from disk, returns stripped string."""
    with open(path, "r") as f:
        return f.read().strip()


def _delete_key_files() -> None:
    """
    Removes both key files from disk on shutdown.
    Errors are logged but not raised — cleanup must not block shutdown.
    """
    for path in (WG0_KEY_PATH, WG1_KEY_PATH):
        try:
            if os.path.exists(path):
                os.remove(path)
                logger.info(
                    "key_file_deleted",
                    extra={"extra_fields": {"path": path}}
                )
        except Exception as e:
            logger.warning(
                "key_file_delete_failed",
                extra={"extra_fields": {"path": path, "error": str(e)}}
            )


# ─────────────────────────────────────────
#  WG CONF WRITE / DELETE
# ─────────────────────────────────────────

def _write_conf(path: str, content: str) -> None:
    """
    Writes a wg conf file with 0o600 permissions.
    The conf contains the private key so it must not be world-readable.
    """
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise


def _delete_conf_files() -> None:
    """
    Removes both .conf files from disk on shutdown.
    Errors are logged but not raised.
    """
    for path in (WG0_CONF_PATH, WG1_CONF_PATH):
        try:
            if os.path.exists(path):
                os.remove(path)
                logger.info(
                    "conf_file_deleted",
                    extra={"extra_fields": {"path": path}}
                )
        except Exception as e:
            logger.warning(
                "conf_file_delete_failed",
                extra={"extra_fields": {"path": path, "error": str(e)}}
            )


# ─────────────────────────────────────────
#  WG-QUICK INTERFACE LIFECYCLE
# ─────────────────────────────────────────

async def _wg_quick(action: str, iface: str) -> None:
    """
    Runs `wg-quick <action> <iface>`.
    action is "up" or "down".
    Raises RuntimeError on non-zero exit so the caller can decide
    whether to abort startup or continue with cleanup.
    """
    logger.info(
        "wg_quick_exec",
        extra={"extra_fields": {"action": action, "iface": iface}}
    )

    proc = await asyncio.create_subprocess_exec(
        WG_QUICK_BIN, action, iface,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=15.0  # ← add this
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"wg-quick {action} {iface} timed out")

    if proc.returncode != 0:
        raise RuntimeError(
            f"wg-quick {action} {iface} failed "
            f"(rc={proc.returncode}): {stderr.decode().strip()}"
        )

    logger.info(
        "wg_quick_success",
        extra={"extra_fields": {"action": action, "iface": iface}}
    )


async def bring_up_interfaces() -> None:
    """
    Full startup sequence for both WireGuard interfaces:

      0. Force clean any existing interfaces to prevent dirty state crashes
      1. Generate fresh keypairs for wg0 and wg1 (always overwrite)
      2. Write private keys to WG_KEYS_DIR with 0o600
      3. Write wg0.conf and wg1.conf to WG_CONF_DIR with 0o600
      4. wg-quick up wg0
      5. wg-quick up wg1

    Raises on any failure — caller should treat this as fatal and abort.
    """
    logger.info(
        "interfaces_bring_up_started",
        extra={"extra_fields": {
            "wg0": WG_IFACE_VPN,
            "wg1": WG_IFACE_PROXY,
            "keys_dir": WG_KEYS_DIR,
            "conf_dir": WG_CONF_DIR,
            "outbound_iface": OUTBOUND_IFACE,
            "haproxy_port": HAPROXY_PORT,
        }}
    )

    # ── 0: Force clean previous dirty state ──────────────────────────────────
    for iface in (WG_IFACE_VPN, WG_IFACE_PROXY):
        proc = await asyncio.create_subprocess_exec(
            "ip", "link", "delete", "dev", iface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate() # We don't care if it fails, it just means it wasn't there

    # ── 1 & 2: Generate keypairs and write key files ─────────────────────────
    logger.info("generating_keypair", extra={"extra_fields": {"iface": WG_IFACE_VPN}})
    wg0_priv, wg0_pub = await _generate_keypair()
    SERVER_PUBKEYS["vpn"] = wg0_pub
    _write_key_file(WG0_KEY_PATH, wg0_priv)
    logger.info(
        "keypair_written",
        extra={"extra_fields": {
            "iface":      WG_IFACE_VPN,
            "key_path":   WG0_KEY_PATH,
            "public_key": wg0_pub,
        }}
    )

    logger.info("generating_keypair", extra={"extra_fields": {"iface": WG_IFACE_PROXY}})
    wg1_priv, wg1_pub = await _generate_keypair()
    SERVER_PUBKEYS["tor"] = wg1_pub
    _write_key_file(WG1_KEY_PATH, wg1_priv)
    logger.info(
        "keypair_written",
        extra={"extra_fields": {
            "iface":      WG_IFACE_PROXY,
            "key_path":   WG1_KEY_PATH,
            "public_key": wg1_pub,
        }}
    )

    # ── 3: Write conf files ──────────────────────────────────────────────────
    _write_conf(WG0_CONF_PATH, _wg0_conf(wg0_priv))
    logger.info(
        "conf_written",
        extra={"extra_fields": {"iface": WG_IFACE_VPN, "path": WG0_CONF_PATH}}
    )

    _write_conf(WG1_CONF_PATH, _wg1_conf(wg1_priv))
    logger.info(
        "conf_written",
        extra={"extra_fields": {"iface": WG_IFACE_PROXY, "path": WG1_CONF_PATH}}
    )

    # ── 4 & 5: Bring up interfaces ───────────────────────────────────────────
    try:
        await _wg_quick("up", WG_IFACE_VPN)
    except RuntimeError:
        logger.error(
            "wg0_up_failed",
            extra={"extra_fields": {"wg0": WG_IFACE_VPN}}
        )
        raise

    try:
        await _wg_quick("up", WG_IFACE_PROXY)
    except RuntimeError:
        # wg1 failed — bring down wg0 before propagating
        logger.error(
            "wg1_up_failed_bringing_down_wg0",
            extra={"extra_fields": {"wg0": WG_IFACE_VPN}}
        )
        try:
            await _wg_quick("down", WG_IFACE_VPN)
        except RuntimeError:
            logger.error("wg0_rollback_down_failed")
        raise

    logger.info(
        "both_interfaces_up",
        extra={"extra_fields": {
            "wg0": WG_IFACE_VPN,
            "wg1": WG_IFACE_PROXY,
        }}
    )


async def tear_down_interfaces() -> None:
    """
    Full shutdown sequence for both WireGuard interfaces:

      1. wg-quick down wg1
      2. wg-quick down wg0
      3. Delete wg0.conf and wg1.conf
      4. Delete key files from WG_KEYS_DIR

    Both `wg-quick down` calls are always attempted even if one fails.
    Conf and key deletion are always attempted regardless of wg-quick results.
    Errors are logged but never raised — shutdown must complete cleanly.
    """
    logger.info("interfaces_tear_down_started")

    # ── 1 & 2: Bring down interfaces ─────────────────────────────────────────
    # Bring down in reverse order: wg1 first, then wg0.
    # Both are attempted regardless of individual failure.
    for iface in (WG_IFACE_PROXY, WG_IFACE_VPN):
        try:
            await _wg_quick("down", iface)
        except RuntimeError as e:
            logger.error(
                "wg_quick_down_failed",
                extra={"extra_fields": {"iface": iface, "error": str(e)}}
            )

    # ── 3: Delete conf files ─────────────────────────────────────────────────
    _delete_conf_files()

    # ── 4: Delete key files ──────────────────────────────────────────────────
    _delete_key_files()

    logger.info("interfaces_tear_down_complete")


# ─────────────────────────────────────────
#  SESSION MANAGER CLIENT
# ─────────────────────────────────────────

async def call_session_manager(
    action: str,
    payload: dict,
    timeout: int = 5
) -> dict:
    """
    Sends a request to the Session Manager service.

    Used (fire-and-forget via create_task) after a peer is successfully
    added to both interfaces.
    """
    user_id    = payload.get("user_id")
    device_id  = payload.get("device_id")
    request_id = payload.get("request_id")

    log = get_context_logger(
        request_id=request_id,
        user_id=user_id,
        device_id=device_id
    )

    if not os.path.exists(SESSION_SOCKET_PATH):
        log.error(
            "session_service_unavailable",
            extra={"extra_fields": {"path": SESSION_SOCKET_PATH}}
        )
        return {"status": "error", "error": "session_service_unavailable"}

    log.info(
        "session_manager_call_initiated",
        extra={"extra_fields": {"action": action}}
    )

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(SESSION_SOCKET_PATH),
            timeout=timeout
        )

        writer.write(json.dumps({"action": action, "payload": payload}).encode())
        await writer.drain()

        data = await reader.read(8192)
        writer.close()
        await writer.wait_closed()

        if not data:
            log.warning("session_manager_empty_response")
            return {"status": "error", "error": "empty_response"}

        response = json.loads(data.decode())
        log.info(
            "session_manager_response_received",
            extra={"extra_fields": {"response_status": response.get("status")}}
        )
        return response

    except asyncio.TimeoutError:
        log.error(
            "session_manager_timeout",
            extra={"extra_fields": {"timeout_seconds": timeout}}
        )
        return {"status": "error", "error": "connection_timeout"}

    except Exception as e:
        log.error(
            "session_manager_communication_failed",
            exc_info=True,
            extra={"extra_fields": {"error_type": type(e).__name__}}
        )
        return {"status": "error", "error": str(e)}


# ─────────────────────────────────────────
#  IPAM CLIENT
# ─────────────────────────────────────────

async def call_ipam(
    action: str,
    user_id: str,
    device_id: str,
    request_id: str = None,
    client_ip: str = None
) -> Dict:
    """
    Communicates with the IPAM service over its Unix socket.

    Actions:
      "allocate" → draws one IP from vpn pool  (10.8.0.0/24)
                   and one IP from tor pool     (10.9.0.0/24)
                   returns { "status": "allocated",
                              "vpn_ip": "10.8.0.x",
                              "tor_ip": "10.9.0.x" }

      "release"  → returns both IPs back to their respective pools,
                   removes the mapping entry from Redis
    """
    log = get_context_logger(
        request_id=request_id,
        user_id=user_id,
        device_id=device_id,
        client_ip=client_ip
    )

    try:
        log.info(
            "ipam_call_initiated",
            extra={"extra_fields": {"action": action, "socket": IPAM_SOCKET_PATH}}
        )

        reader, writer = await asyncio.open_unix_connection(IPAM_SOCKET_PATH)

        writer.write(json.dumps({
            "request_id": request_id,
            "action":     action,
            "user_id":    user_id,
            "device_id":  device_id
        }).encode())
        await writer.drain()

        data = await reader.read(4096)
        writer.close()
        await writer.wait_closed()

        if not data:
            log.error("ipam_empty_response")
            return {"status": "error", "error": "empty_response"}

        response = json.loads(data.decode())
        log.info(
            "ipam_response_received",
            extra={"extra_fields": {"ipam_status": response.get("status")}}
        )
        return response

    except Exception as e:
        log.error(
            "ipam_unreachable",
            exc_info=True,
            extra={"extra_fields": {"error_detail": str(e)}}
        )
        return {"status": "error", "error": "ipam_unreachable"}


# ─────────────────────────────────────────
#  WIREGUARD COMMAND HELPER
# ─────────────────────────────────────────

async def run_wg(args: list, log_ctx=None) -> bool:
    """
    Executes a single `wg` CLI command.

    NOTE: This service only ever calls `wg set …` — it never calls
    `wg-quick`, so it does NOT touch iptables / nftables / ufw.
    Firewall rules (NAT, FORWARD) are managed exclusively by the
    wg-quick PostUp/PostDown hooks in each interface's .conf file.
    """
    log = log_ctx or logger

    log.info(
        "wg_exec_started",
        extra={"extra_fields": {"binary": WG_BIN, "args": args}}
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            WG_BIN,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            log.error(
                "wg_exec_failed",
                extra={"extra_fields": {
                    "return_code": proc.returncode,
                    "stderr":      stderr.decode().strip(),
                    "args":        args
                }}
            )
            return False

        log.info("wg_exec_success", extra={"extra_fields": {"args": args}})
        return True

    except Exception as e:
        log.error(
            "wg_exec_exception",
            exc_info=True,
            extra={"extra_fields": {"error_detail": str(e)}}
        )
        return False


# ─────────────────────────────────────────
#  PEER ADD  (internal helper)
# ─────────────────────────────────────────

async def _add_peer(
    public_key: str,
    vpn_ip: str,
    tor_ip: str,
    log
) -> tuple[bool, str]:
    """
    Adds a peer to BOTH interfaces atomically:

      wg0  ← vpn_ip/32   (10.8.0.x — remote-access VPN, 10.8.0.0/24 pool)
      wg1  ← tor_ip/32   (10.9.0.x — HAProxy routing,   10.9.0.0/24 pool)

    Each interface carries ONLY its own IP — the two pools are fully
    separated and no peer ever appears with both IPs on the same interface.

    Returns (success: bool, failed_interface: str | "")
    """
    # ── wg0: remote-access VPN ──────────────────────────────────────────────
    ok_vpn = await run_wg(
        ["set", WG_IFACE_VPN, "peer", public_key, "allowed-ips", f"{vpn_ip}/32"],
        log_ctx=log
    )
    if not ok_vpn:
        log.error(
            "wg0_peer_add_failed",
            extra={"extra_fields": {"vpn_ip": vpn_ip, "interface": WG_IFACE_VPN}}
        )
        return False, WG_IFACE_VPN

    # ── wg1: HAProxy routing ────────────────────────────────────────────────
    ok_proxy = await run_wg(
        ["set", WG_IFACE_PROXY, "peer", public_key, "allowed-ips", f"{tor_ip}/32"],
        log_ctx=log
    )
    if not ok_proxy:
        log.error(
            "wg1_peer_add_failed",
            extra={"extra_fields": {"tor_ip": tor_ip, "interface": WG_IFACE_PROXY}}
        )
        # Roll back wg0 so the kernel stays consistent
        ok_rollback = await run_wg(
            ["set", WG_IFACE_VPN, "peer", public_key, "remove"],
            log_ctx=log
        )
        if not ok_rollback:
            log.error(
                "wg0_peer_rollback_failed",
                extra={"extra_fields": {"vpn_ip": vpn_ip}}
            )
        else:
            log.warning(
                "wg0_peer_rolled_back",
                extra={"extra_fields": {"vpn_ip": vpn_ip}}
            )
        return False, WG_IFACE_PROXY

    return True, ""


# ─────────────────────────────────────────
#  PEER REMOVE  (internal helper)
# ─────────────────────────────────────────

async def _remove_peer(public_key: str, log) -> tuple[bool, bool]:
    """
    Removes the peer from BOTH interfaces.

    Returns (wg0_ok: bool, wg1_ok: bool).
    Both removals are always attempted even if one fails so that the
    kernel state stays as clean as possible.
    """
    ok_vpn = await run_wg(
        ["set", WG_IFACE_VPN, "peer", public_key, "remove"],
        log_ctx=log
    )
    ok_proxy = await run_wg(
        ["set", WG_IFACE_PROXY, "peer", public_key, "remove"],
        log_ctx=log
    )
    return ok_vpn, ok_proxy


# ─────────────────────────────────────────
#  CORE REQUEST HANDLER
# ─────────────────────────────────────────

async def handle_client(reader, writer):
    response = {"status": "error"}

    try:
        raw = await reader.read(4096)
        if not raw:
            return

        req    = json.loads(raw.decode())
        action = req.get("action")

        # ── health check ────────────────────────────────────────────────────
        if action == "ping":
            try:
                writer.write(json.dumps({"status": "pong"}).encode())
                if not writer.transport.is_closing():
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            return

        # ── extract & validate common fields ────────────────────────────────
        user_id    = req.get("user_id")
        device_id  = req.get("device_id")
        public_key = req.get("public_key")
        request_id = req.get("request_id") or str(uuid.uuid4())
        client_ip  = req.get("client_ip")

        log = get_context_logger(
            client_ip=client_ip,
            request_id=request_id,
            user_id=user_id,
            device_id=device_id
        )

        log.info(
            "wg_request_received",
            extra={"extra_fields": {
                "action":     action,
                "public_key": f"{public_key[:10]}..." if public_key else None
            }}
        )

        if action not in {"add_peer", "remove_peer"}:
            log.warning(
                "invalid_action_attempted",
                extra={"extra_fields": {"action": action}}
            )
            response = {"error": "invalid_action"}
            return

        if not user_id or not device_id or not public_key:
            log.warning("missing_required_fields")
            response = {"error": "missing_fields"}
            return

        # ════════════════════════════════════════
        #  ADD PEER
        # ════════════════════════════════════════
        if action == "add_peer":
            # 1. Ask IPAM for a vpn_ip (10.8.0.x) and a tor_ip (10.9.0.x)
            #    IPAM pops one address from each Redis pool:
            #      vpn:ipam:pool:vpn  → vpn_ip
            #      vpn:ipam:pool:tor  → tor_ip
            #    and writes the mapping to vpn:ipam:map
            ipam = await call_ipam(
                "allocate", user_id, device_id, request_id, client_ip
            )

            if ipam.get("status") != "allocated":
                log.error(
                    "ipam_allocation_failed",
                    extra={"extra_fields": {"ipam_response": ipam}}
                )
                response = {"status": "error", "error": "ipam_failed", "details": ipam}
                return

            vpn_ip = ipam["vpn_ip"]   # e.g. "10.8.0.5"   → goes to wg0
            tor_ip = ipam["tor_ip"]   # e.g. "10.9.0.5"   → goes to wg1

            log.info(
                "ipam_addresses_allocated",
                extra={"extra_fields": {
                    "vpn_ip":    vpn_ip,
                    "tor_ip":    tor_ip,
                    "wg0_iface": WG_IFACE_VPN,
                    "wg1_iface": WG_IFACE_PROXY
                }}
            )

            # 2. Apply to kernel — wg0 gets vpn_ip, wg1 gets tor_ip
            ok, failed_iface = await _add_peer(public_key, vpn_ip, tor_ip, log)

            if not ok:
                # _add_peer already rolled back wg0 if wg1 failed
                log.error(
                    "peer_add_failed_releasing_ipam",
                    extra={"extra_fields": {"failed_interface": failed_iface}}
                )
                await call_ipam(
                    "release", user_id, device_id, request_id, client_ip
                )
                response = {
                    "status": "error",
                    "error":  f"wg_update_failed_on_{failed_iface}"
                }
                return

            log.info(
                "peer_added_to_both_interfaces",
                extra={"extra_fields": {
                    "wg0": f"{WG_IFACE_VPN} ← {vpn_ip}/32",
                    "wg1": f"{WG_IFACE_PROXY} ← {tor_ip}/32"
                }}
            )

            # 3. Notify session manager (fire-and-forget)
            session_payload = {
                "request_id": request_id,
                "client_ip":  client_ip,
                "session_id": f"{user_id}-{device_id}",
                "user_id":    user_id,
                "device_id":  device_id,
                "public_key": public_key,
                "vpn_ip":     vpn_ip,
                "tor_ip":     tor_ip
            }
            log.info("triggering_session_manager_task")
            asyncio.create_task(
                call_session_manager("create_session", session_payload)
            )

            response = {
                "status": "ok",
                "vpn_ip": vpn_ip,   # client uses this on wg0
                "tor_ip": tor_ip,    # client uses this on wg1
                "server_pubkeys": {     # <--- MUST BE HERE
                    "vpn": SERVER_PUBKEYS["vpn"],
                    "tor": SERVER_PUBKEYS["tor"]
                },
                "heartbeat_ttl": SESSION_HEARTBEAT_TTL,
                "hard_ttl": SESSION_HARD_TTL
            }

        # ════════════════════════════════════════
        #  REMOVE PEER
        # ════════════════════════════════════════
        elif action == "remove_peer":
            log.info("peer_removal_initiated")

            # 1. Release IPs back to Redis pools FIRST so the pool stays
            #    consistent even if the wg kernel calls below partially fail
            await call_ipam(
                "release", user_id, device_id, request_id, client_ip
            )

            # 2. Remove from both interfaces; always attempt both
            ok_vpn, ok_proxy = await _remove_peer(public_key, log)

            if not ok_vpn or not ok_proxy:
                log.error(
                    "wg_peer_removal_partial_failure",
                    extra={"extra_fields": {
                        f"{WG_IFACE_VPN}_removed":   ok_vpn,
                        f"{WG_IFACE_PROXY}_removed": ok_proxy
                    }}
                )
                response = {
                    "status": "error",
                    "error":  "wg_remove_partial_failure",
                    "details": {
                        WG_IFACE_VPN:   ok_vpn,
                        WG_IFACE_PROXY: ok_proxy
                    }
                }
                return

            log.info(
                "peer_removed_from_both_interfaces",
                extra={"extra_fields": {
                    "wg0": WG_IFACE_VPN,
                    "wg1": WG_IFACE_PROXY
                }}
            )
            response = {"status": "ok"}

    except Exception:
        logger.error("wg_handler_internal_error", exc_info=True)
        response = {"error": "internal_error"}

    finally:
        try:
            if not writer.transport.is_closing():
                writer.write(json.dumps(response).encode())
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ─────────────────────────────────────────
#  SERVER BOOTSTRAP
# ─────────────────────────────────────────

async def main():
    """
    Main entry point with graceful shutdown.

    Startup order:
      1. Bring up WireGuard interfaces (keygen → conf write → wg-quick up)
      2. Create Unix socket and start serving

    Shutdown order (SIGINT / SIGTERM):
      1. Stop accepting new connections
      2. Tear down WireGuard interfaces (wg-quick down → delete conf → delete keys)
      3. Remove Unix socket
    """
    stop_event = asyncio.Event()
    loop       = asyncio.get_running_loop()

    def handle_exit_signal(sig_name):
        logger.info(
            "wg_manager_shutdown_initiated",
            extra={"extra_fields": {"signal": sig_name}}
        )
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_exit_signal(s.name))

    logger.info(
        "wg_manager_initializing",
        extra={"extra_fields": {
            "socket":        WG_SOCKET_PATH,
            "wg0_iface":     WG_IFACE_VPN,
            "wg1_iface":     WG_IFACE_PROXY,
            "keys_dir":      WG_KEYS_DIR,
            "conf_dir":      WG_CONF_DIR,
            "outbound_iface": OUTBOUND_IFACE,
            "haproxy_port":  HAPROXY_PORT,
        }}
    )

    try:
        # ── 1. Bring up WireGuard interfaces ─────────────────────────────────
        # Fatal if this fails — no point starting the socket server
        # if the interfaces aren't live.
        await bring_up_interfaces()

        # ── 2. Create Unix socket ─────────────────────────────────────────────
        os.makedirs(SOCKET_DIR, mode=SOCKET_DIR_MODE, exist_ok=True)

        if os.path.exists(WG_SOCKET_PATH):
            os.remove(WG_SOCKET_PATH)

        server = await asyncio.start_unix_server(
            handle_client, path=WG_SOCKET_PATH
        )

        try:
            gid = grp.getgrnam(SOCKET_GROUP).gr_gid
            os.chown(WG_SOCKET_PATH, 0, gid)
            os.chmod(WG_SOCKET_PATH, SOCKET_PERMS)
            logger.info("socket_permissions_secured")
        except Exception as e:
            logger.warning(f"permission_setup_failed: {e}")

        logger.info(
            "wg_manager_started",
            extra={"extra_fields": {"path": WG_SOCKET_PATH}}
        )

        async with server:
            server_task = asyncio.create_task(server.serve_forever())
            await stop_event.wait()

            logger.info("wg_manager_cleaning_up")
            server_task.cancel()

        # ── 3. Tear down WireGuard interfaces ─────────────────────────────────
        # Always runs even if the server task raised — interfaces must come down.
        await tear_down_interfaces()

        if os.path.exists(WG_SOCKET_PATH):
            os.remove(WG_SOCKET_PATH)

        logger.info("wg_manager_stopped_cleanly")

    except Exception:
        logger.critical("wg_manager_bootstrap_failed", exc_info=True)
        # Best-effort teardown if we got far enough to bring interfaces up
        try:
            await tear_down_interfaces()
        except Exception:
            logger.error("teardown_after_bootstrap_failure_failed", exc_info=True)
        raise


if __name__ == "__main__":
    try:
        logger.info(
            "wg_manager_process_start",
            extra={"extra_fields": {"pid": os.getpid()}}
        )
        asyncio.run(main())
    except Exception:
        logger.critical("wg_manager_fatal_crash", exc_info=True)
    finally:
        logger.info("wg_manager_process_exit")