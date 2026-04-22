# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import uuid
import os
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from db import AsyncSessionLocal
from models import User, Session, WGSession
from security import hash_password
from sqlalchemy import or_
from datetime import datetime
import redis.asyncio as redis
import time
from utils.user_management_logging_utils import get_logger, get_context_logger
import grp
import signal

# ================= CONFIG =================

_CONFIG_PATH = os.environ.get("USER_SERVICE_CONFIG", "user_service_config.json")

def _load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

_cfg = _load_config(_CONFIG_PATH)

# Socket
SOCKET_DIR   = _cfg["socket"]["dir"]
SOCKET_PATH  = _cfg["socket"]["path"]
SOCKET_GROUP = _cfg["socket"]["group"]
SOCKET_PERMS = int(_cfg["socket"]["permissions"], 8)

# Redis
REDIS_URL = _cfg["redis"]["url"]

# ==========================================

logger = get_logger()

logger.info(
    "user_service_starting",
    extra={"extra_fields": {"socket_path": SOCKET_PATH}}
)

r = redis.from_url(REDIS_URL, decode_responses=True)


async def create_user(db, payload, log):
    exists = await db.execute(
        select(User).where(
            (User.email == payload["email"]) |
            (User.username == payload["username"])
        )
    )
    if exists.scalar():
        log.warning(
            "user_creation_failed",
            extra={"extra_fields": {"reason": "user_exists"}}
        )
        return {"error": "user_exists"}

    user = User(
        username=payload["username"],
        email=payload["email"],
        password_hash=hash_password(payload["password"]),
        max_devices=payload.get("max_devices", 1),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    log.info(
        "user_created",
        extra={"extra_fields": {
            "user_id":  str(user.id),
            "username": user.username,
            "email":    user.email
        }}
    )

    return {
        "status": "ok",
        "user": {
            "id":           str(user.id),
            "username":     user.username,
            "email":        user.email,
            "is_active":    user.is_active,
            "max_devices":  user.max_devices,
            "created_at":   user.created_at.isoformat(),
            "last_login_at": None
        }
    }


async def update_user(db, payload, log):
    uid     = uuid.UUID(payload["user_id"])
    updates = payload.get("updates", {})

    if not updates:
        log.warning(
            "user_update_failed",
            extra={"extra_fields": {"reason": "no_updates"}}
        )
        return {"error": "no_updates"}

    if "password" in updates:
        updates["password_hash"] = hash_password(updates.pop("password"))

    if "username" in updates or "email" in updates:
        conflict = await db.execute(
            select(User.id).where(
                User.id != uid,
                User.deleted_at.is_(None),
                or_(
                    User.username == updates.get("username"),
                    User.email == updates.get("email")
                )
            )
        )
        if conflict.first():
            log.warning(
                "user_update_failed",
                extra={"extra_fields": {"reason": "user_conflict"}}
            )
            return {"error": "user_conflict"}

    stmt = (
        update(User)
        .where(User.id == uid, User.deleted_at.is_(None))
        .values(**updates)
        .returning(
            User.id,
            User.username,
            User.email,
            User.is_active,
            User.max_devices,
            User.created_at
        )
    )

    result = await db.execute(stmt)
    row    = result.first()
    await db.commit()

    if not row:
        log.warning(
            "user_update_failed",
            extra={"extra_fields": {"reason": "user_not_found"}}
        )
        return {"error": "user_not_found"}

    log.info(
        "user_updated",
        extra={"extra_fields": {"updated_fields": list(updates.keys())}}
    )

    return {
        "status": "ok",
        "user": {
            "id":          str(row.id),
            "username":    row.username,
            "email":       row.email,
            "is_active":   row.is_active,
            "max_devices": row.max_devices,
            "created_at":  row.created_at.isoformat()
        }
    }


async def suspend_user(db, payload, log):
    uid    = uuid.UUID(payload["user_id"])
    result = await db.execute(
        select(User).where(User.id == uid, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        log.warning(
            "user_suspend_failed",
            extra={"extra_fields": {"reason": "user_not_found"}}
        )
        return {"error": "user_not_found"}

    if not user.is_active:
        log.warning(
            "user_suspend_failed",
            extra={"extra_fields": {"reason": "user_already_inactive"}}
        )
        return {"error": "user_already_inactive"}

    user.is_active = False
    await db.commit()
    await db.refresh(user)

    await r.publish(
        "vpn:user_events",
        json.dumps({
            "action":    "user_disabled",
            "user_id":   str(user.id),
            "reason":    "suspended",
            "timestamp": int(time.time())
        })
    )

    log.info(
        "user_suspended",
        extra={"extra_fields": {"username": user.username, "email": user.email}}
    )

    return {
        "status": "suspended",
        "user": {
            "id":            str(user.id),
            "username":      user.username,
            "email":         user.email,
            "is_active":     user.is_active,
            "max_devices":   user.max_devices,
            "created_at":    user.created_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
        }
    }


async def delete_user(db, payload, log):
    uid    = uuid.UUID(payload["user_id"])
    result = await db.execute(
        select(User).where(User.id == uid, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        log.warning(
            "user_delete_failed",
            extra={"extra_fields": {"reason": "user_not_found"}}
        )
        return {"error": "user_not_found"}

    await db.execute(
        update(User).where(User.id == uid).values(deleted_at=datetime.utcnow())
    )
    await db.commit()

    await r.publish(
        "vpn:user_events",
        json.dumps({
            "action":    "user_disabled",
            "user_id":   str(uid),
            "reason":    "deleted",
            "timestamp": int(time.time())
        })
    )

    log.info(
        "user_deleted",
        extra={"extra_fields": {"username": user.username, "email": user.email}}
    )

    return {"status": "deleted"}


async def revoke_user(db, payload, log):
    uid    = uuid.UUID(payload["user_id"])
    result = await db.execute(
        select(User).where(User.id == uid, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        log.warning(
            "user_revoke_failed",
            extra={"extra_fields": {"reason": "user_not_found"}}
        )
        return {"error": "user_not_found"}

    if user.is_active:
        log.warning(
            "user_revoke_failed",
            extra={"extra_fields": {"reason": "user_already_active"}}
        )
        return {"error": "user_already_active"}

    user.is_active = True
    await db.commit()
    await db.refresh(user)

    log.info(
        "user_revoked",
        extra={"extra_fields": {"username": user.username, "email": user.email}}
    )

    return {
        "status": "revoked",
        "user": {
            "id":            str(user.id),
            "username":      user.username,
            "email":         user.email,
            "is_active":     user.is_active,
            "max_devices":   user.max_devices,
            "created_at":    user.created_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
        }
    }


async def list_users(db, payload, log):
    from sqlalchemy import func

    limit           = payload.get("limit", 100)
    offset          = payload.get("offset", 0)
    include_deleted = payload.get("include_deleted", False)
    is_active       = payload.get("is_active")
    search          = payload.get("search")

    log.info(
        "list_users_request",
        extra={"extra_fields": {
            "limit":            limit,
            "offset":           offset,
            "include_deleted":  include_deleted,
            "is_active_filter": is_active,
            "search":           search
        }}
    )

    query = select(User)
    if not include_deleted:
        query = query.where(User.deleted_at.is_(None))
    if is_active is not None:
        query = query.where(User.is_active == is_active)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(User.username.ilike(pattern), User.email.ilike(pattern))
        )
    query = query.order_by(User.created_at.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    users  = result.scalars().all()

    count_query = select(func.count(User.id))
    if not include_deleted:
        count_query = count_query.where(User.deleted_at.is_(None))
    if is_active is not None:
        count_query = count_query.where(User.is_active == is_active)
    if search:
        pattern = f"%{search}%"
        count_query = count_query.where(
            or_(User.username.ilike(pattern), User.email.ilike(pattern))
        )

    total_count = (await db.execute(count_query)).scalar()

    users_list = [
        {
            "id":              str(u.id),
            "username":        u.username,
            "email":           u.email,
            "is_active":       u.is_active,
            "max_devices":     u.max_devices,
            "total_sessions":  u.total_sessions,
            "total_bytes_tx":  u.total_bytes_tx,
            "total_bytes_rx":  u.total_bytes_rx,
            "created_at":      u.created_at.isoformat(),
            "last_login_at":   u.last_login_at.isoformat() if u.last_login_at else None,
            "last_seen_at":    u.last_seen_at.isoformat() if u.last_seen_at else None,
            "deleted_at":      u.deleted_at.isoformat() if u.deleted_at else None
        }
        for u in users
    ]

    log.info(
        "list_users_success",
        extra={"extra_fields": {
            "returned_count": len(users_list),
            "total_count":    total_count
        }}
    )

    return {
        "status": "ok",
        "users":  users_list,
        "pagination": {
            "limit":    limit,
            "offset":   offset,
            "total":    total_count,
            "returned": len(users_list)
        }
    }


async def get_user_sessions(db, payload, log):
    from models import vpn_session_history
    from sqlalchemy import func

    user_id     = uuid.UUID(payload["user_id"])
    limit       = payload.get("limit", 50)
    offset      = payload.get("offset", 0)
    active_only = payload.get("active_only", False)
    device_id   = payload.get("device_id")

    log.info(
        "get_user_sessions_request",
        extra={"extra_fields": {
            "user_id":     str(user_id),
            "limit":       limit,
            "offset":      offset,
            "active_only": active_only,
            "device_id":   device_id
        }}
    )

    user = (await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )).scalar_one_or_none()

    if not user:
        log.warning(
            "get_user_sessions_failed",
            extra={"extra_fields": {"reason": "user_not_found"}}
        )
        return {"error": "user_not_found"}

    query = select(vpn_session_history).where(vpn_session_history.user_id == user_id)
    if active_only:
        query = query.where(vpn_session_history.ended_at.is_(None))
    if device_id:
        query = query.where(vpn_session_history.device_id == device_id)
    query = query.order_by(vpn_session_history.started_at.desc()).limit(limit).offset(offset)

    sessions = (await db.execute(query)).scalars().all()

    count_query = select(func.count(vpn_session_history.id)).where(
        vpn_session_history.user_id == user_id
    )
    if active_only:
        count_query = count_query.where(vpn_session_history.ended_at.is_(None))
    if device_id:
        count_query = count_query.where(vpn_session_history.device_id == device_id)

    total_count = (await db.execute(count_query)).scalar()

    sessions_list = []
    for s in sessions:
        duration = (
            int((s.ended_at - s.started_at).total_seconds()) if s.ended_at else None
        )
        sessions_list.append({
            "id":               str(s.id),
            "session_key":      s.session_key,
            "device_id":        s.device_id,
            "public_key":       s.public_key,
            "vpn_ip":           str(s.vpn_ip) if s.vpn_ip else None,
            "tor_ip":           str(s.tor_ip) if s.tor_ip else None,
            "client_ip":        str(s.client_ip) if s.client_ip else None,
            "started_at":       s.started_at.isoformat(),
            "ended_at":         s.ended_at.isoformat() if s.ended_at else None,
            "duration_seconds": duration,
            "bytes_tx":         s.bytes_tx,
            "bytes_rx":         s.bytes_rx,
            "total_bytes":      s.bytes_tx + s.bytes_rx,
            "close_reason":     s.close_reason,
            "is_active":        s.ended_at is None
        })

    log.info(
        "get_user_sessions_success",
        extra={"extra_fields": {
            "returned_count":  len(sessions_list),
            "total_count":     total_count,
            "active_sessions": sum(1 for s in sessions_list if s["is_active"])
        }}
    )

    return {
        "status": "ok",
        "user": {
            "id":       str(user.id),
            "username": user.username,
            "email":    user.email
        },
        "sessions": sessions_list,
        "pagination": {
            "limit":    limit,
            "offset":   offset,
            "total":    total_count,
            "returned": len(sessions_list)
        },
        "stats": {
            "total_sessions":  total_count,
            "active_sessions": sum(1 for s in sessions_list if s["is_active"]),
            "total_bytes_tx":  sum(s["bytes_tx"] for s in sessions_list),
            "total_bytes_rx":  sum(s["bytes_rx"] for s in sessions_list)
        }
    }


ACTION_MAP = {
    "create_user":       create_user,
    "update_user":       update_user,
    "suspend_user":      suspend_user,
    "delete_user":       delete_user,
    "revoke_user":       revoke_user,
    "list_users":        list_users,
    "get_user_sessions": get_user_sessions,
}


async def handle_client(reader, writer):
    log = logger

    try:
        data = await reader.read(8192)
        if not data:
            return

        request = json.loads(data.decode())
        action  = request.get("action")

        if action == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()
            return

        payload    = request.get("payload", {})
        request_id = request.get("request_id") or str(uuid.uuid4())
        user_id    = payload.get("user_id")
        username   = payload.get("username")

        log = get_context_logger(
            request_id=request_id,
            user_id=user_id,
            username=username,
            action=action
        )

        log.info(
            "user_service_request_received",
            extra={"extra_fields": {"payload_keys": list(payload.keys())}}
        )

        if action not in ACTION_MAP:
            log.warning(
                "invalid_action",
                extra={"extra_fields": {"requested_action": action}}
            )
            response = {"error": "invalid_action"}
        else:
            async with AsyncSessionLocal() as db:
                response = await ACTION_MAP[action](db, payload, log)
                if "error" not in response:
                    log.info(
                        "user_service_operation_success",
                        extra={"extra_fields": {"status": response.get("status")}}
                    )

    except json.JSONDecodeError as e:
        log.error(
            "json_decode_error",
            extra={"extra_fields": {"error": str(e)}},
            exc_info=True
        )
        response = {"error": "invalid_json"}

    except ValueError as e:
        log.error(
            "value_error",
            extra={"extra_fields": {"error": str(e)}},
            exc_info=True
        )
        response = {"error": "invalid_request", "detail": str(e)}

    except Exception:
        log.error("user_service_internal_error", exc_info=True)
        response = {"error": "internal_error"}

    writer.write(json.dumps(response).encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main():
    stop_event = asyncio.Event()
    loop       = asyncio.get_running_loop()

    def handle_exit_signal(sig_name):
        logger.info(
            "user_service_shutdown_initiated",
            extra={"extra_fields": {"signal": sig_name}}
        )
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_exit_signal(s.name))

    os.makedirs(SOCKET_DIR, exist_ok=True)

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
        logger.info(
            "old_socket_removed",
            extra={"extra_fields": {"path": SOCKET_PATH}}
        )

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    try:
        os.chmod(SOCKET_PATH, SOCKET_PERMS)
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, -1, gid)
        logger.info(
            "socket_permissions_set",
            extra={"extra_fields": {
                "path":        SOCKET_PATH,
                "permissions": _cfg["socket"]["permissions"],
                "group":       SOCKET_GROUP
            }}
        )
    except Exception as e:
        logger.warning(
            "socket_permissions_failed",
            extra={"extra_fields": {"error": str(e)}},
            exc_info=True
        )

    logger.info(
        "user_service_started",
        extra={"extra_fields": {"socket_path": SOCKET_PATH}}
    )

    async with server:
        server_task = asyncio.create_task(server.serve_forever())
        await stop_event.wait()

        logger.info("user_service_cleaning_up")
        server_task.cancel()

        await r.aclose()
        logger.info("redis_connection_closed")

    logger.info("user_service_stopped_cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        logger.error("user_service_crash", exc_info=True)
