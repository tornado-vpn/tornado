# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db import AsyncSessionLocal
from models import User
from security import verify_password
from tornadoutils.security_utils.jwt_utils import create_tokens, verify_refresh_token, InvalidToken, TokenExpired, reload_keys
import redis.exceptions as redis_exceptions
import redis.asyncio as redis_async
from datetime import datetime, timezone
from uuid import UUID, uuid4
from utils.auth_logging_utils import get_logger
import traceback
import signal
import grp
from utils.brute_force_guard import is_banned, record_failure, clear_failures, remaining_ban_ttl, check_ban
from pathlib import Path

# ================= CONFIG =================

_CONFIG_PATH = os.environ.get("AUTH_SERVICE_CONFIG", "auth_service_config.json")

def _load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

_cfg = _load_config(_CONFIG_PATH)

# Socket
SOCKET_PATH  = _cfg["socket"]["path"]
SOCKET_GROUP = _cfg["socket"]["group"]
SOCKET_PERMS = int(_cfg["socket"]["permissions"], 8)

# Redis
REDIS_URL      = _cfg["redis"]["url"]
DEVICE_TTL_SEC = _cfg["redis"]["device_ttl_sec"]

# Upstream
SESSION_SERVICE_SOCKET = _cfg["upstream"]["session_socket"]

# PID file
PID_FILE = _cfg.get("pid_file", "/run/tornado/auth_service.pid")

# How long to wait (total seconds) for the key rotator to produce live key
# files before giving up and refusing to start.
KEY_WAIT_TIMEOUT_SEC  = int(os.environ.get("AUTH_KEY_WAIT_TIMEOUT", 60))
# How long to sleep between each poll attempt
KEY_WAIT_POLL_SEC     = 1.0

# ==========================================

logger = get_logger()

redis_client = redis_async.from_url(REDIS_URL, decode_responses=True)

CHECK_AND_ADD_DEVICE_LUA = """
local key = KEYS[1]
local device_id = ARGV[1]
local max_devices = tonumber(ARGV[2])

local current_count = redis.call('SCARD', key)

if current_count >= max_devices then
    if redis.call('SISMEMBER', key, device_id) == 0 then
        return {err = "MAX_DEVICES_EXCEEDED"}
    end
end

redis.call('SADD', key, device_id)
redis.call('EXPIRE', key, ARGV[3])
return "OK"
"""


# ================= STARTUP KEY GATE =================

_JWT_KEYS_DIR = Path(os.environ.get("JWT_KEYS_DIR", "/opt/tornado/keys/jwt"))

_REQUIRED_KEY_FILES = [
    "access_private.pem",
    "access_public.pem",
    "refresh_private.pem",
    "refresh_public.pem",
]


def _all_live_keys_present() -> bool:
    """
    Return True only when all four live key files exist AND are non-empty.
    Does NOT check *.new.pem staged files — those belong to the rotator.
    """
    for filename in _REQUIRED_KEY_FILES:
        path = _JWT_KEYS_DIR / filename
        if not path.exists() or path.stat().st_size == 0:
            return False
    return True


def _any_staged_keys_present() -> bool:
    """
    Return True if *.new.pem files exist — the rotator is mid-staging.
    We use this to give a more informative log message.
    """
    return any((_JWT_KEYS_DIR / f.replace(".pem", ".new.pem")).exists()
               for f in _REQUIRED_KEY_FILES)


async def _wait_for_jwt_keys() -> None:
    """
    Block startup until all four live JWT key files are present and non-empty.

    The key rotator is the sole authority for key generation. This service
    never writes key files — it only reads them. If keys are absent at startup
    (e.g. first boot, or interrupted rotation), we wait for the rotator to
    finish rather than generating conflicting keys ourselves.

    Raises RuntimeError after KEY_WAIT_TIMEOUT_SEC seconds if keys never appear.
    """
    if _all_live_keys_present():
        logger.info("jwt_keys_ready", extra={"extra_fields": {
            "keys_dir": str(_JWT_KEYS_DIR)
        }})
        return

    elapsed = 0.0
    last_log_at = -10.0  # force a log on first iteration

    logger.warning("jwt_keys_not_ready_waiting", extra={"extra_fields": {
        "keys_dir":    str(_JWT_KEYS_DIR),
        "timeout_sec": KEY_WAIT_TIMEOUT_SEC,
        "staged_keys": _any_staged_keys_present(),
    }})

    while elapsed < KEY_WAIT_TIMEOUT_SEC:
        await asyncio.sleep(KEY_WAIT_POLL_SEC)
        elapsed += KEY_WAIT_POLL_SEC

        if _all_live_keys_present():
            logger.info("jwt_keys_became_ready", extra={"extra_fields": {
                "waited_sec": elapsed,
                "keys_dir":   str(_JWT_KEYS_DIR),
            }})
            return

        # Log progress every 10 seconds so the journal shows we're alive
        if elapsed - last_log_at >= 10:
            last_log_at = elapsed
            logger.warning("jwt_keys_still_waiting", extra={"extra_fields": {
                "elapsed_sec": elapsed,
                "timeout_sec": KEY_WAIT_TIMEOUT_SEC,
                "staged_keys": _any_staged_keys_present(),
            }})

    raise RuntimeError(
        f"JWT key files not available after {KEY_WAIT_TIMEOUT_SEC}s. "
        f"Ensure the key-rotator service is running and has write access to "
        f"{_JWT_KEYS_DIR}. Expected files: {_REQUIRED_KEY_FILES}"
    )


# =============================================


async def call_session_service(action: str, payload: dict):
    reader, writer = await asyncio.open_unix_connection(SESSION_SERVICE_SOCKET)
    writer.write(json.dumps({"action": action, "payload": payload}).encode())
    await writer.drain()

    data = await reader.read(8192)
    writer.close()
    await writer.wait_closed()
    return json.loads(data.decode())


async def login(db, payload, request_id, client_ip):
    logger.info("login_attempt", extra={"extra_fields": {
        "identifier_present": bool(payload.get("username_or_email")),
        "request_id": request_id,
        "client_ip": client_ip
    }})

    # 1. Brute-force check
    ban_status = await check_ban(redis_client, client_ip)
    if ban_status["banned"]:
        logger.warning("login_blocked_banned_ip", extra={"extra_fields": {
            "client_ip":   client_ip,
            "retry_after": ban_status["retry_after"],
            "request_id":  request_id
        }})
        return {"error": "ip_banned", "detail": "banned", "retry_after": ban_status["retry_after"]}

    # 2. Field validation
    user_id_value = payload.get("username_or_email")
    password      = payload.get("password")
    if not user_id_value or not password:
        await record_failure(redis_client, client_ip)
        logger.warning("login_failed", extra={"extra_fields": {
            "reason": "missing_fields", "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "missing_fields"}

    # 3. DB lookup + password check (single pass)
    result = await db.execute(
        select(User).where(
            (User.username == user_id_value) | (User.email == user_id_value),
            User.deleted_at.is_(None)
        )
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(user.password_hash, password):
        count = await record_failure(redis_client, client_ip)
        logger.warning("login_failed", extra={"extra_fields": {
            "reason": "invalid_credentials", "failure_count": count,
            "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "invalid_credentials"}

    if not user.is_active:
        logger.warning("login_denied", extra={"extra_fields": {
            "reason": "user_inactive", "user_id": str(user.id),
            "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "user_inactive"}

    # 4. Clear failures on success
    await clear_failures(redis_client, client_ip)

    # 5. Device limit enforcement
    device_id        = str(uuid4())
    user_devices_key = f"user:{user.id}:devices"
    max_devices      = user.max_devices or 1

    try:
        await redis_client.eval(
            CHECK_AND_ADD_DEVICE_LUA, 1,
            user_devices_key, device_id, str(max_devices), str(DEVICE_TTL_SEC)
        )
    except redis_exceptions.ResponseError as e:
        if "MAX_DEVICES_EXCEEDED" in str(e):
            logger.warning("login_denied", extra={"extra_fields": {
                "reason": "max_devices_exceeded", "user_id": str(user.id),
                "request_id": request_id, "client_ip": client_ip
            }})
            return {"error": "max_devices_exceeded"}
        logger.error("redis_script_error", extra={"extra_fields": {"error": str(e)}})
        return {"error": "internal_error"}

    # 6. Issue tokens
    tokens = create_tokens(user.id, device_id)
    logger.info("login_success", extra={"extra_fields": {
        "user_id": str(user.id), "device_id": device_id,
        "request_id": request_id, "client_ip": client_ip
    }})
    return {
        "status": "ok",
        "user": {
            "id":        str(user.id),
            "username":  user.username,
            "email":     user.email,
            "is_active": user.is_active,
        },
        "tokens":    tokens,
        "device_id": device_id,
    }


async def reauth(db, payload, request_id, client_ip):
    logger.info("reauth_attempt", extra={"extra_fields": {"request_id": request_id}})

    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        return {"error": "missing_refresh_token"}

    try:
        decoded_payload = verify_refresh_token(refresh_token)
        old_jti         = decoded_payload.get("jti")
        user_id         = decoded_payload.get("sub")
        exp_timestamp   = decoded_payload.get("exp")
        device_id       = decoded_payload.get("device_id")

        if await redis_client.exists(f"revoked_jti:{old_jti}"):
            logger.critical("refresh_token_reuse_detected", extra={"extra_fields": {
                "user_id":    user_id,
                "jti":        old_jti[:8],
                "request_id": request_id,
                "client_ip":  client_ip
            }})
            return {"error": "token_revoked_reuse_detected"}

        result = await db.execute(select(User).where(User.id == user_id))
        user   = result.scalar_one_or_none()
        if not user or not user.is_active:
            return {"error": "user_invalid"}

        now = datetime.now(timezone.utc).timestamp()
        ttl = int(exp_timestamp - now)
        if ttl > 0:
            await redis_client.setex(f"revoked_jti:{old_jti}", ttl, "revoked")

        new_tokens = create_tokens(user.id, device_id)
        logger.info("reauth_success", extra={"extra_fields": {
            "user_id": user_id, "request_id": request_id, "client_ip": client_ip
        }})
        return {"status": "ok", "tokens": new_tokens}

    except TokenExpired:
        logger.warning("refresh_token_expired", extra={"extra_fields": {
            "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "refresh_token_expired"}
    except InvalidToken:
        logger.warning("refresh_token_invalid", extra={"extra_fields": {
            "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "invalid_refresh_token"}


async def logout(db, payload, request_id, client_ip):
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        logger.warning("logout_failed_missing_refresh_token", extra={"extra_fields": {
            "request_id": request_id
        }})
        return {"error": "missing_refresh_token"}

    try:
        decoded   = verify_refresh_token(refresh_token)
        user_id   = decoded["sub"]
        device_id = decoded["device_id"]
        jti       = decoded["jti"]
        exp       = decoded["exp"]

        logger.info("logout_attempt", extra={"extra_fields": {
            "user_id": user_id, "device_id": device_id,
            "request_id": request_id, "client_ip": client_ip
        }})

        now = int(datetime.now(timezone.utc).timestamp())
        ttl = max(0, exp - now)
        if ttl > 0:
            await redis_client.setex(f"revoked_jti:{jti}", ttl, "revoked")

        await redis_client.srem(f"user:{user_id}:devices", device_id)

        session_id = f"{user_id}-{device_id}"
        try:
            await call_session_service(
                action="close_session",
                payload={"session_id": session_id}
            )
        except Exception as e:
            logger.error("session_service_unreachable", extra={"extra_fields": {
                "session_id": session_id, "error": str(e),
                "request_id": request_id, "client_ip": client_ip
            }})
            return {"error": "session_service_unavailable"}

        logger.info("logout_success", extra={"extra_fields": {
            "user_id": user_id, "device_id": device_id, "request_id": request_id
        }})
        return {"status": "logged_out"}

    except TokenExpired:
        logger.warning("refresh_token_expired", extra={"extra_fields": {
            "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "refresh_token_expired"}
    except InvalidToken:
        logger.warning("invalid_refresh_token", extra={"extra_fields": {
            "request_id": request_id, "client_ip": client_ip
        }})
        return {"error": "invalid_refresh_token"}


ACTION_MAP = {
    "login":  login,
    "reauth": reauth,
    "logout": logout,
}


async def handle_client(reader, writer):
    request_id = "unknown"
    client_ip  = "unknown"

    try:
        data    = await reader.read(8192)
        request = json.loads(data.decode())
        action  = request.get("action")

        if action == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        payload    = request.get("payload", {})
        request_id = payload.get("request_id") or str(uuid4())
        client_ip  = payload.get("client_ip") or "unknown"

        logger.info("auth_request_received", extra={"extra_fields": {
            "action": action, "request_id": request_id, "client_ip": client_ip
        }})

        if action not in ACTION_MAP:
            logger.warning("invalid_action", extra={"extra_fields": {
                "action": action, "request_id": request_id, "client_ip": client_ip
            }})
            response = {"error": "invalid_action"}
        else:
            async with AsyncSessionLocal() as db:
                try:
                    response = await ACTION_MAP[action](db, payload, request_id, client_ip)
                    await db.commit()
                except Exception:
                    await db.rollback()
                    raise

        logger.info("auth_request_completed", extra={"extra_fields": {
            "action":     action,
            "status":     response.get("status", "error"),
            "request_id": request_id,
            "client_ip":  client_ip
        }})

    except Exception as e:
        logger.error("auth_internal_error", extra={"extra_fields": {
            "error": str(e), "request_id": request_id, "client_ip": client_ip
        }})
        traceback.print_exc()
        response = {"error": "internal_error"}

    try:
        writer.write(json.dumps(response).encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass


async def main():
    loop       = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def shutdown_signal():
        logger.info("shutdown_initiated", extra={"extra_fields": {"reason": "signal_received"}})
        stop_event.set()

    
    def reload_keys_signal():
        async def _reload():
            try:
                await asyncio.get_event_loop().run_in_executor(None, reload_keys)
                logger.info("jwt_keys_reloaded_via_sighup")
            except Exception as e:
                logger.error("jwt_key_reload_failed", extra={"extra_fields": {"error": str(e)}})

        asyncio.create_task(_reload())

    

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_signal)

    loop.add_signal_handler(signal.SIGHUP, reload_keys_signal)

    # ── Wait for the key rotator to produce live key files ────────────────────
    # This replaces _ensure_jwt_keys_exist(). The auth service never generates
    # keys — it waits for the key rotator (the sole authority) to do so.
    # If the rotator is mid-rotation (*.new.pem files present, live files
    # absent), we simply wait for it to complete the cutover.
    await _wait_for_jwt_keys()

    # ── Socket setup ──────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)

    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except Exception as e:
        logger.error("socket_cleanup_failed", extra={"extra_fields": {"error": str(e)}})

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    try:
        os.chmod(SOCKET_PATH, SOCKET_PERMS)
        group_info = grp.getgrnam(SOCKET_GROUP)
        os.chown(SOCKET_PATH, -1, group_info.gr_gid)
        logger.info("socket_permissions_secured", extra={"extra_fields": {
            "path":  SOCKET_PATH,
            "group": SOCKET_GROUP,
            "mode":  _cfg["socket"]["permissions"],
        }})
    except KeyError:
        logger.error("group_missing", extra={"extra_fields": {"group": SOCKET_GROUP}})
    except Exception as e:
        logger.error("permission_fix_failed", extra={"extra_fields": {"error": str(e)}})

    # ── PID file ──────────────────────────────────────────────────────────────
    try:
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        logger.info("pid_file_written", extra={"extra_fields": {"pid_file": PID_FILE}})
    except Exception as e:
        logger.error(f"pid_file_write_failed | {e}")

    logger.info("service_started", extra={"extra_fields": {"path": SOCKET_PATH}})

    await stop_event.wait()

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    logger.info("service_stopping")
    server.close()
    await server.wait_closed()

    try:
        await redis_client.aclose()
        logger.info("redis_connection_closed")
    except Exception as e:
        logger.error("redis_cleanup_failed", extra={"extra_fields": {"error": str(e)}})

    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    if os.path.exists(PID_FILE):
        os.unlink(PID_FILE)
        logger.info("pid_file_removed")

    logger.info("service_stopped_cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass