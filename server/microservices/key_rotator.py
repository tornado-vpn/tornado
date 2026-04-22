# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

"""
key_rotator.py — JWT asymmetric key rotation service for Tornado VPN.

Rotation cycle (every `interval_hours`):
  1. Generate new RS256 keypairs (access + refresh)
  2. Enter overlap window:
       - Old public keys stay readable in overlap/ dir (so in-flight tokens remain valid)
       - New private keys written to *.new.pem staging files
  3. After overlap_minutes:
       - Rotate public keys FIRST, send SIGHUP so services reload new public keys
       - Brief grace period, then rotate private keys
       - Atomic rename via os.rename (same filesystem)
  4. Cleanup overlap keys after services have reloaded
  5. Sleep until next rotation

Fixes applied vs original:
  - Public keys rotated BEFORE private keys to eliminate signature mismatch window
  - SIGHUP sent between public and private key cutover (not after both)
  - Overlap keys kept alive until after services have reloaded (not cleaned up immediately)
  - Staged file existence verified before rename to guard against partial failures
  - Cleanup now runs after a generous grace period post-SIGHUP
  - rotate_keys() returns a bool indicating success/failure
  - Cancellation-safe: asyncio.CancelledError re-raised properly in rotation loop
  - All staged *.new.pem files cleaned up on any failure path

Unix socket:
  - ping        → pong  (health check)
  - rotate_now  → triggers immediate rotation out of schedule
  - status      → returns key ages and config
"""

import asyncio
import json
import os
import signal
import logging
import traceback
import grp
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────

_CONFIG_PATH = os.environ.get("KEY_ROTATOR_CONFIG", "key_rotator_config.json")


def _load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


_cfg             = _load_config(_CONFIG_PATH)
KEYS_DIR         = Path(_cfg["keys"]["dir"])
OVERLAP_DIR      = KEYS_DIR / _cfg["keys"]["overlap_dir"]
INTERVAL_HOURS   = _cfg["rotation"]["interval_hours"]
OVERLAP_MINUTES  = _cfg["rotation"]["overlap_minutes"]
RELOAD_PID_FILES = _cfg["services"]["reload_signals"]

# How long to wait (seconds) after SIGHUP before rotating private keys.
# Services need time to reload public keys from disk before tokens start
# being signed with the new private key.
SIGHUP_GRACE_SECONDS = int(_cfg["rotation"].get("sighup_grace_seconds", 10))

# Socket
SOCKET_DIR   = _cfg["socket"]["dir"]
SOCKET_PATH  = _cfg["socket"]["path"]
SOCKET_GROUP = _cfg["socket"]["group"]
SOCKET_PERMS = int(_cfg["socket"]["permissions"], 8)

KEY_FILES = {
    "access_private":  KEYS_DIR / _cfg["keys"]["access_private"],
    "access_public":   KEYS_DIR / _cfg["keys"]["access_public"],
    "refresh_private": KEYS_DIR / _cfg["keys"]["refresh_private"],
    "refresh_public":  KEYS_DIR / _cfg["keys"]["refresh_public"],
}

# ─────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────

logging.basicConfig(
    level=_cfg["logging"]["level"],
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("key_rotator")

# ─────────────────────────────────────────
#  ROTATION STATE
# ─────────────────────────────────────────

# Set by handle_client when "rotate_now" is received.
# The main rotation loop checks this and triggers immediately.
_rotate_now_event: asyncio.Event = None  # initialized in main()


# ─────────────────────────────────────────
#  ENV SECRET ROTATION
# ─────────────────────────────────────────

import secrets
import re

ENV_FILE_PATH = Path(_cfg.get("env", {}).get("path", "/opt/tornado/.env"))
ENV_SECRET_KEY = _cfg.get("env", {}).get("secret_key", "ADMIN_SECRET")


def _generate_admin_secret(nbytes: int = 32) -> str:
    """Generate a cryptographically secure hex secret (256-bit by default)."""
    return secrets.token_hex(nbytes)


def _read_env_file(path: Path) -> str:
    """Read .env file content, returning empty string if missing."""
    if not path.exists():
        logger.warning(f"env_file_not_found | {path}")
        return ""
    return path.read_text(encoding="utf-8")


def _replace_env_secret(content: str, key: str, new_value: str) -> tuple[str, bool]:
    """
    Replace `KEY=<anything>` in env content with `KEY=<new_value>`.
    Returns (new_content, was_found).
    Handles optional surrounding quotes and inline comments safely.
    """
    pattern = re.compile(
        rf'^({re.escape(key)}\s*=\s*)[^\r\n]*',
        re.MULTILINE
    )
    new_content, count = pattern.subn(rf'\g<1>{new_value}', content)
    return new_content, count > 0


def _rotate_env_secret() -> str:
    """
    Generate a new ADMIN_SECRET and atomically write it into the .env file.
    If the key doesn't exist in the file, it is appended.
    Returns the new secret value.
    """
    new_secret = _generate_admin_secret()
    content    = _read_env_file(ENV_FILE_PATH)

    updated_content, found = _replace_env_secret(content, ENV_SECRET_KEY, new_secret)

    if not found:
        separator = "\n" if content and not content.endswith("\n") else ""
        updated_content = content + separator + f"{ENV_SECRET_KEY}={new_secret}\n"
        logger.warning(f"env_key_not_found_appended | key={ENV_SECRET_KEY}")

    tmp = ENV_FILE_PATH.parent / (ENV_FILE_PATH.name + ".tmp")
    fd  = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(updated_content)
    except Exception:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.rename(str(tmp), str(ENV_FILE_PATH))

    logger.info(f"env_secret_rotated | key={ENV_SECRET_KEY} file={ENV_FILE_PATH}")
    return new_secret


# ─────────────────────────────────────────
#  KEY GENERATION
# ─────────────────────────────────────────

def _generate_rsa_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def _write_key_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.rename(tmp, path)


def _backup_current_keys() -> None:
    """
    Copy live keys into OVERLAP_DIR so services that restart mid-rotation
    can fall back to the previous public key for token verification.
    These are kept alive until after SIGHUP + grace period (see rotate_keys).
    """
    OVERLAP_DIR.mkdir(mode=0o700, exist_ok=True)
    for name, src in KEY_FILES.items():
        dst = OVERLAP_DIR / src.name
        if src.exists():
            dst.write_bytes(src.read_bytes())
            os.chmod(str(dst), 0o600)
            logger.info(f"backed_up_key | {src.name} → overlap/")
        else:
            logger.warning(f"backup_skipped_missing | {src.name} (first rotation?)")


def _cleanup_overlap_keys() -> None:
    """Remove backed-up overlap keys. Called only after services have reloaded."""
    for name, src in KEY_FILES.items():
        target = OVERLAP_DIR / src.name
        if target.exists():
            target.unlink()
            logger.info(f"overlap_key_deleted | {target.name}")


def _cleanup_staged_keys(staged: dict) -> None:
    """Remove any *.new.pem staged files — called on failure to avoid stale staging."""
    for name, (staged_path, _) in staged.items():
        if staged_path.exists():
            staged_path.unlink()
            logger.info(f"staged_file_cleaned_up | {staged_path.name}")


# ─────────────────────────────────────────
#  SERVICE RELOAD
# ─────────────────────────────────────────

def _send_sighup_to_services() -> None:
    for pid_file in RELOAD_PID_FILES:
        try:
            pid = int(Path(pid_file).read_text().strip())
            os.kill(pid, signal.SIGHUP)
            logger.info(f"sighup_sent | pid={pid} pid_file={pid_file}")
        except FileNotFoundError:
            logger.warning(f"pid_file_not_found | {pid_file} (service may not be running)")
        except ProcessLookupError:
            logger.warning(f"process_not_found | pid from {pid_file} is stale")
        except Exception as e:
            logger.error(f"sighup_failed | {pid_file}: {e}")


# ─────────────────────────────────────────
#  ROTATION LOGIC
# ─────────────────────────────────────────

async def rotate_keys() -> bool:
    """
    Perform a full key rotation cycle.

    Cutover order (CRITICAL — do not change without understanding the implications):

      1. Backup live keys  → overlap/  (fallback for restarting services)
      2. Generate new keypairs, stage as *.new.pem
      3. Sleep overlap window  (old keys still live; in-flight tokens stay valid)

      4a. Rename new PUBLIC keys into place   ← services can now verify new tokens
      4b. Send SIGHUP to all services         ← services reload new public keys
      4c. Sleep SIGHUP_GRACE_SECONDS          ← wait for all services to reload
      4d. Rename new PRIVATE keys into place  ← auth service now signs with new key

      5. Rotate ADMIN_SECRET in .env
      6. Sleep briefly, then remove overlap/ keys

    This ordering guarantees:
      - A token signed with the NEW private key can always be verified,
        because public keys are rotated and reloaded BEFORE private keys switch.
      - A token signed with the OLD private key can still be verified during
        the grace period, because overlap/ copies of old public keys exist.

    Returns True on success, False on failure.
    """
    now = datetime.now(timezone.utc).isoformat()
    logger.info(f"rotation_started | {now}")

    staged: dict = {}

    try:
        # ── Phase 1 — Backup current live keys ───────────────────────────────
        _backup_current_keys()

        # ── Phase 2 — Generate + stage new keypairs ──────────────────────────
        logger.info("generating_new_access_keypair")
        new_access_priv, new_access_pub = _generate_rsa_keypair()

        logger.info("generating_new_refresh_keypair")
        new_refresh_priv, new_refresh_pub = _generate_rsa_keypair()

        staged = {
            "access_private":  (KEY_FILES["access_private"].with_suffix(".new.pem"),  new_access_priv),
            "access_public":   (KEY_FILES["access_public"].with_suffix(".new.pem"),   new_access_pub),
            "refresh_private": (KEY_FILES["refresh_private"].with_suffix(".new.pem"), new_refresh_priv),
            "refresh_public":  (KEY_FILES["refresh_public"].with_suffix(".new.pem"),  new_refresh_pub),
        }

        for name, (path, data) in staged.items():
            _write_key_atomic(path, data)
            logger.info(f"staged_key | {path.name}")

        # ── Phase 3 — Overlap window ──────────────────────────────────────────
        overlap_sec = OVERLAP_MINUTES * 60
        logger.info(f"overlap_window_started | duration={overlap_sec}s "
                    f"(old keys remain live; in-flight tokens stay valid)")
        await asyncio.sleep(overlap_sec)

        # ── Phase 4a — Rotate PUBLIC keys first ───────────────────────────────
        # Services can verify tokens signed by EITHER the old private key
        # (via overlap/ fallback) or the new private key (via live public key).
        logger.info("rotating_public_keys")
        for name in ("access_public", "refresh_public"):
            staged_path, _ = staged[name]
            live_path = KEY_FILES[name]

            if not staged_path.exists():
                raise RuntimeError(
                    f"Staged public key missing before cutover: {staged_path}. "
                    "Aborting to preserve key consistency."
                )

            os.rename(str(staged_path), str(live_path))
            logger.info(f"public_key_rotated | {staged_path.name} → {live_path.name}")

        # ── Phase 4b — Signal services to reload new public keys ──────────────
        logger.info("sending_sighup_for_public_key_reload")
        _send_sighup_to_services()

        # ── Phase 4c — Grace period: wait for services to reload ──────────────
        # No tokens signed with the new private key exist yet, so nothing can
        # fail verification during this window. Services reload public keys.
        logger.info(f"sighup_grace_period_started | duration={SIGHUP_GRACE_SECONDS}s")
        await asyncio.sleep(SIGHUP_GRACE_SECONDS)

        # ── Phase 4d — Rotate PRIVATE keys ───────────────────────────────────
        logger.info("rotating_private_keys")
        for name in ("access_private", "refresh_private"):
            staged_path, _ = staged[name]
            live_path = KEY_FILES[name]

            if not staged_path.exists():
                raise RuntimeError(
                    f"Staged private key missing before cutover: {staged_path}. "
                    "Aborting to preserve key consistency."
                )

            os.rename(str(staged_path), str(live_path))
            logger.info(f"private_key_rotated | {staged_path.name} → {live_path.name}")

        # ── Phase 4e — Second SIGHUP: tell services to reload new private key ──
        # Private keys are now live. Services still hold the OLD private key in
        # memory and are signing tokens with it. The overlap/ old public key is
        # still present, so those tokens still verify — but we must reload
        # before we clean up overlap/, or verification breaks permanently.
        logger.info("sending_second_sighup_for_private_key_reload")
        _send_sighup_to_services()

        logger.info(f"second_sighup_grace_period | duration={SIGHUP_GRACE_SECONDS}s")
        await asyncio.sleep(SIGHUP_GRACE_SECONDS)

        # ── Phase 5 — Rotate env secret ───────────────────────────────────────
        _rotate_env_secret()

        # ── Phase 6 — Cleanup overlap keys ────────────────────────────────────
        # Services have now reloaded the new private key (via second SIGHUP).
        # New tokens are signed with the new private key, verified by the new
        # live public key. Old tokens (signed before the reload) expire within
        # ACCESS_TOKEN_EXPIRE_MINUTES. Overlap keys are no longer needed.
        await asyncio.sleep(5)
        _cleanup_overlap_keys()

        logger.info(f"rotation_complete | next_in={INTERVAL_HOURS}h")
        return True

    except asyncio.CancelledError:
        # Propagate cancellation — do not swallow it.
        logger.warning("rotation_cancelled | cleaning up staged files")
        _cleanup_staged_keys(staged)
        raise

    except Exception as e:
        logger.error(f"rotation_failed | {e}")
        traceback.print_exc()
        _cleanup_staged_keys(staged)
        return False


# ─────────────────────────────────────────
#  UNIX SOCKET HANDLER
# ─────────────────────────────────────────

async def handle_client(reader, writer):
    try:
        raw = await reader.read(4096)
        if not raw:
            return

        req    = json.loads(raw.decode())
        action = req.get("action")

        # ── ping / pong ───────────────────────────────────────────────────────
        if action == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()
            return

        # ── rotate_now ────────────────────────────────────────────────────────
        elif action == "rotate_now":
            logger.info("rotate_now_requested_via_socket")
            _rotate_now_event.set()
            writer.write(json.dumps({"status": "ok", "message": "rotation_triggered"}).encode())
            await writer.drain()

        # ── status ────────────────────────────────────────────────────────────
        elif action == "status":
            key_ages = {}
            for name, path in KEY_FILES.items():
                if path.exists():
                    age_sec = int(datetime.now(timezone.utc).timestamp() - path.stat().st_mtime)
                    key_ages[name] = f"{age_sec}s ago"
                else:
                    key_ages[name] = "missing"

            overlap_ages = {}
            for name, path in KEY_FILES.items():
                overlap_path = OVERLAP_DIR / path.name
                if overlap_path.exists():
                    age_sec = int(datetime.now(timezone.utc).timestamp() - overlap_path.stat().st_mtime)
                    overlap_ages[name] = f"{age_sec}s ago"
                else:
                    overlap_ages[name] = "not present"

            writer.write(json.dumps({
                "status":           "ok",
                "interval_hours":   INTERVAL_HOURS,
                "overlap_minutes":  OVERLAP_MINUTES,
                "sighup_grace_sec": SIGHUP_GRACE_SECONDS,
                "key_ages":         key_ages,
                "overlap_key_ages": overlap_ages,
            }).encode())
            await writer.drain()

        else:
            logger.warning(f"invalid_action_via_socket | action={action}")
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
#  MAIN LOOP
# ─────────────────────────────────────────

async def main():
    global _rotate_now_event

    stop_event        = asyncio.Event()
    _rotate_now_event = asyncio.Event()
    loop              = asyncio.get_running_loop()

    def shutdown_signal():
        logger.info("key_rotator_shutdown_initiated")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_signal)

    # ── Unix socket setup ─────────────────────────────────────────────────────
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

    logger.info(
        f"key_rotator_started | interval={INTERVAL_HOURS}h "
        f"overlap={OVERLAP_MINUTES}min sighup_grace={SIGHUP_GRACE_SECONDS}s "
        f"keys_dir={KEYS_DIR}"
    )

    # ── Rotation loop ─────────────────────────────────────────────────────────
    async def rotation_loop():
        while not stop_event.is_set():
            success = await rotate_keys()

            if not success:
                logger.error("rotation_failed_will_retry_next_interval")

            _rotate_now_event.clear()

            # Sleep for interval — wakes early on stop or rotate_now
            try:
                done, pending = await asyncio.wait(
                    [
                        asyncio.create_task(stop_event.wait()),
                        asyncio.create_task(_rotate_now_event.wait()),
                    ],
                    timeout=INTERVAL_HOURS * 3600,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # Cancel the task that didn't fire to avoid task leaks
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # timeout = normal interval elapsed

            if stop_event.is_set():
                logger.info("rotation_loop_stopping")
                break

            if _rotate_now_event.is_set():
                logger.info("rotate_now_event_triggered_early_rotation")

    async with server:
        rotation_task = asyncio.create_task(rotation_loop())
        await stop_event.wait()

        logger.info("key_rotator_stopping")
        rotation_task.cancel()
        try:
            await rotation_task
        except asyncio.CancelledError:
            pass

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    logger.info("key_rotator_stopped_cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass