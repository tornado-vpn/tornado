# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

"""
bootstrap_keys.py — JWT key bootstrap service for Tornado VPN.

Runs as a Unix socket microservice alongside the other tornado services.
Responsible for ensuring JWT key files exist and are valid on first deploy
and after any accidental deletion.

Socket actions:
  ping        → {"status": "pong"}
  key_status  → {"status": "ok", "keys": {...}, "all_valid": bool}

How other microservices use this:
  On startup, each service calls _wait_for_bootstrap() which connects to
  this socket, calls key_status, and blocks until all_valid is True.
  This service generates missing/invalid keys before returning all_valid=True.

Key generation rules:
  - Only generates if a key file is missing OR fails PEM validation
  - Never overwrites a key file that is already valid
  - Generates access keypair and refresh keypair independently
  - Writes atomically via tmp + rename
  - After generation, notifies the key rotator via SIGHUP so it adopts
    the new keys as its baseline instead of staging over them
"""

import asyncio
import json
import os
import sys
import logging
import signal
import grp
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────

_CONFIG_PATH = os.environ.get("BOOTSTRAP_CONFIG", "bootstrap_keys_config.json")


def _load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


_cfg = _load_config(_CONFIG_PATH)

KEYS_DIR     = Path(_cfg["keys"]["dir"])
OVERLAP_DIR  = KEYS_DIR / _cfg["keys"].get("overlap_dir", "overlap")

SOCKET_DIR   = _cfg["socket"]["dir"]
SOCKET_PATH  = _cfg["socket"]["path"]
SOCKET_GROUP = _cfg["socket"]["group"]
SOCKET_PERMS = int(_cfg["socket"]["permissions"], 8)

PID_FILE         = _cfg.get("pid_file", "/run/tornado/bootstrap_keys.pid")
ROTATOR_PID_FILE = _cfg.get("rotator_pid_file", "/run/tornado/key_rotator.pid")

KEY_FILES = {
    "access_private":  KEYS_DIR / "access_private.pem",
    "access_public":   KEYS_DIR / "access_public.pem",
    "refresh_private": KEYS_DIR / "refresh_private.pem",
    "refresh_public":  KEYS_DIR / "refresh_public.pem",
}

# ─────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────

logging.basicConfig(
    level=_cfg.get("log_level", "INFO"),
    format="%(asctime)s [%(levelname)s] bootstrap_keys: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("bootstrap_keys")


# ─────────────────────────────────────────
#  KEY VALIDATION
# ─────────────────────────────────────────

def _is_valid_private_key(path: Path) -> bool:
    try:
        data = path.read_bytes()
        if not data.strip():
            return False
        load_pem_private_key(data, password=None)
        return True
    except Exception as e:
        logger.warning(f"invalid_private_key | {path.name}: {e}")
        return False


def _is_valid_public_key(path: Path) -> bool:
    try:
        data = path.read_bytes()
        if not data.strip():
            return False
        load_pem_public_key(data)
        return True
    except Exception as e:
        logger.warning(f"invalid_public_key | {path.name}: {e}")
        return False


def _check_key(name: str, path: Path) -> dict:
    if not path.exists():
        return {"present": False, "valid": False, "reason": "file_not_found"}
    valid = _is_valid_private_key(path) if "private" in name else _is_valid_public_key(path)
    return {"present": True, "valid": valid, "reason": "ok" if valid else "pem_parse_failed"}


def _get_key_statuses() -> dict:
    return {name: _check_key(name, path) for name, path in KEY_FILES.items()}


def _all_valid(statuses: dict) -> bool:
    return all(s["valid"] for s in statuses.values())


# ─────────────────────────────────────────
#  KEY GENERATION
# ─────────────────────────────────────────

def _generate_rsa_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _write_key_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(".bootstrap.tmp")
    fd  = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.rename(str(tmp), str(path))
    logger.info(f"key_written | {path.name}")


def _notify_rotator() -> None:
    """
    Send SIGHUP to the key rotator so it reloads the newly generated keys.
    This prevents the rotator from staging over the fresh keys on its next
    cycle without knowing they changed.
    """
    try:
        pid_path = Path(ROTATOR_PID_FILE)
        if not pid_path.exists():
            logger.warning("rotator_pid_file_not_found | rotator may not be running yet — skipping notify")
            return
        pid = int(pid_path.read_text().strip())
        os.kill(pid, signal.SIGHUP)
        logger.info(f"sighup_sent_to_rotator | pid={pid}")
    except ProcessLookupError:
        logger.warning("rotator_process_not_found | stale pid file")
    except Exception as e:
        logger.error(f"rotator_notify_failed | {e}")


def _ensure_keys() -> dict:
    """
    Check all key files. Generate any that are missing or invalid.
    Returns the final status dict after any generation attempts.
    Never overwrites a key that is already valid.
    """
    KEYS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    OVERLAP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    statuses = _get_key_statuses()

    needs_access  = not statuses["access_private"]["valid"] \
                 or not statuses["access_public"]["valid"]
    needs_refresh = not statuses["refresh_private"]["valid"] \
                 or not statuses["refresh_public"]["valid"]

    generated = []

    if needs_access:
        logger.warning("access_keypair_missing_or_invalid | generating")
        try:
            priv, pub = _generate_rsa_keypair()
            _write_key_atomic(KEY_FILES["access_private"], priv)
            _write_key_atomic(KEY_FILES["access_public"],  pub)
            generated.append("access")
            logger.info("access_keypair_generated")
        except Exception as e:
            logger.critical(f"access_keypair_generation_failed | {e}")

    if needs_refresh:
        logger.warning("refresh_keypair_missing_or_invalid | generating")
        try:
            priv, pub = _generate_rsa_keypair()
            _write_key_atomic(KEY_FILES["refresh_private"], priv)
            _write_key_atomic(KEY_FILES["refresh_public"],  pub)
            generated.append("refresh")
            logger.info("refresh_keypair_generated")
        except Exception as e:
            logger.critical(f"refresh_keypair_generation_failed | {e}")

    if generated:
        _notify_rotator()

    # Re-validate after any generation so the returned status is always fresh
    return _get_key_statuses()


# ─────────────────────────────────────────
#  SOCKET HANDLER
# ─────────────────────────────────────────

async def handle_client(reader, writer):
    try:
        raw = await reader.read(4096)
        if not raw:
            return

        req    = json.loads(raw.decode())
        action = req.get("action")

        if action == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()

        elif action == "key_status":
            # Run blocking crypto/IO in a thread pool — keeps the event loop free
            loop     = asyncio.get_running_loop()
            statuses = await loop.run_in_executor(None, _ensure_keys)
            all_ok   = _all_valid(statuses)

            if all_ok:
                logger.info("key_status_requested | all_valid=True")
            else:
                logger.error("key_status_requested | all_valid=False — generation failed")

            writer.write(json.dumps({
                "status":    "ok",
                "all_valid": all_ok,
                "keys":      statuses,
            }).encode())
            await writer.drain()

        else:
            logger.warning(f"invalid_action | action={action}")
            writer.write(json.dumps({"error": "invalid_action"}).encode())
            await writer.drain()

    except Exception:
        logger.error("socket_handler_error", exc_info=True)
        try:
            writer.write(json.dumps({"error": "internal_error"}).encode())
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ─────────────────────────────────────────
#  CLIENT HELPER  (imported by other services)
# ─────────────────────────────────────────

async def wait_for_bootstrap(
    socket_path: str | None = None,
    timeout_sec: float = 60.0,
    poll_sec:    float = 1.0,
) -> None:
    """
    Call this from any microservice's startup to ensure keys are ready
    before the service begins handling requests.

    Connects to the bootstrap socket, sends key_status (which generates
    keys if needed), and returns only when all_valid is True.
    Raises RuntimeError if keys are still not valid after timeout_sec.

    Usage:
        # In auth_service.py main():
        from bootstrap_keys import wait_for_bootstrap
        await wait_for_bootstrap(BOOTSTRAP_SOCKET_PATH)
    """
    import time
    target   = socket_path or SOCKET_PATH
    deadline = time.monotonic() + timeout_sec
    attempt  = 0

    while time.monotonic() < deadline:
        attempt += 1
        try:
            reader, writer = await asyncio.open_unix_connection(target)
            writer.write(json.dumps({"action": "key_status"}).encode())
            await writer.drain()

            data = await reader.read(8192)
            writer.close()
            await writer.wait_closed()

            result = json.loads(data.decode())

            if result.get("all_valid"):
                logger.info(f"bootstrap_confirmed | keys_ready attempt={attempt}")
                return

            logger.warning(
                f"bootstrap_keys_not_ready | attempt={attempt} "
                f"keys={result.get('keys', {})}"
            )

        except (ConnectionRefusedError, FileNotFoundError):
            logger.warning(
                f"bootstrap_socket_not_ready | attempt={attempt} path={target}"
            )
        except Exception as e:
            logger.error(f"bootstrap_check_error | attempt={attempt} error={e}")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(poll_sec, remaining))

    raise RuntimeError(
        f"JWT keys not valid after {timeout_sec}s. "
        f"Check bootstrap_keys service at {target}."
    )


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

async def main():
    loop       = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def shutdown_signal():
        logger.info("shutdown_initiated")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_signal)

    # ── Run key check/generation eagerly at startup ───────────────────────────
    # Keys are ensured before the socket opens so the very first key_status
    # call from another service is instant rather than blocking on generation.
    logger.info(f"startup_key_check | keys_dir={KEYS_DIR}")
    initial_statuses = await loop.run_in_executor(None, _ensure_keys)

    if _all_valid(initial_statuses):
        logger.info("startup_key_check_passed | all keys valid")
    else:
        logger.error(
            "startup_key_check_failed | some keys could not be generated — "
            "socket will still open so callers receive a clear error response"
        )

    # ── Unix socket ───────────────────────────────────────────────────────────
    os.makedirs(SOCKET_DIR, exist_ok=True)

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, -1, gid)
        os.chmod(SOCKET_PATH, SOCKET_PERMS)
        logger.info(f"socket_ready | path={SOCKET_PATH} group={SOCKET_GROUP}")
    except Exception as e:
        logger.warning(f"socket_permission_setup_failed | {e}")

    # ── PID file ──────────────────────────────────────────────────────────────
    try:
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        logger.info(f"pid_file_written | {PID_FILE}")
    except Exception as e:
        logger.error(f"pid_file_write_failed | {e}")

    logger.info("bootstrap_keys_service_started")

    async with server:
        await stop_event.wait()

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    if os.path.exists(PID_FILE):
        os.unlink(PID_FILE)

    logger.info("bootstrap_keys_service_stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass