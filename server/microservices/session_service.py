# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import uuid
import redis.asyncio as redis
import grp
from utils.session_logging_utils import get_logger, get_context_logger
import time
from sqlalchemy import insert
from datetime import datetime, UTC
from db import AsyncSessionLocal
from models import vpn_session_history
from sqlalchemy import update, func, bindparam
from models import User
from uuid import UUID
from sqlalchemy import cast
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import signal

# ================= CONFIG =================

_CONFIG_PATH = os.environ.get("SESSION_MANAGER_CONFIG", "session_manager_config.json")

def _load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

_cfg = _load_config(_CONFIG_PATH)

# Socket
SOCKET_DIR   = _cfg["socket"]["dir"]
SOCKET_PATH  = _cfg["socket"]["path"]
SOCKET_GROUP = _cfg["socket"]["group"]
SOCKET_DIR_MODE  = int(_cfg["socket"]["dir_mode"], 8)
SOCKET_PERMS = int(_cfg["socket"]["permissions"], 8)

# Redis
REDIS_URL = _cfg["redis"]["url"]

# Session
HEARTBEAT_TTL  = _cfg["session"]["heartbeat_ttl"]
HARD_TTL       = _cfg["session"]["hard_ttl"]
WATCH_INTERVAL = _cfg["session"]["watch_interval"]

# WireGuard
WG_INTERFACE         = _cfg["wireguard"]["interface"]
WG_PROXY_INTERFACE   = _cfg["wireguard"].get("proxy_interface", "wg1")
WG_BIN               = _cfg["wireguard"]["bin"]
WG_STATS_INTERVAL    = _cfg["wireguard"]["stats_interval_sec"]

# IPAM
IPAM_SOCKET_PATH = _cfg["ipam"]["socket_path"]

# ==========================================

logger = get_logger()

logger.info(
    "session_manager_starting",
    extra={"extra_fields": {
        "heartbeat_ttl": HEARTBEAT_TTL,
        "hard_ttl": HARD_TTL,
        "watch_interval": WATCH_INTERVAL
    }}
)

r = redis.from_url(REDIS_URL, decode_responses=True)


# ==========================================================
# WireGuard Helpers
# ==========================================================

async def finalize_session(session_id: str, meta: dict, reason: str, ctx_log):
    """Persist final session stats into PostgreSQL and update User aggregates."""
    stats    = await r.hgetall(f"vpn:session:{session_id}")
    bytes_rx = int(stats.get("rx_bytes", 0))
    bytes_tx = int(stats.get("tx_bytes", 0))

    async with AsyncSessionLocal() as db:
        async with db.begin():
            await db.execute(
                update(vpn_session_history)
                .where(vpn_session_history.session_key == session_id)
                .values(
                    ended_at=datetime.now(UTC),
                    bytes_rx=bytes_rx,
                    bytes_tx=bytes_tx,
                    close_reason=reason
                )
            )

            raw_device_id = meta.get("device_id")
            device_id_uuid = UUID(raw_device_id) if raw_device_id else None

            await db.execute(
                update(User)
                .where(User.id == meta["user_id"])
                .values(
                    total_sessions=User.total_sessions + 1,
                    total_bytes_rx=User.total_bytes_rx + bytes_rx,
                    total_bytes_tx=User.total_bytes_tx + bytes_tx,
                    last_seen_at=func.now(),
                    last_device_id=cast(meta.get("device_id"), PG_UUID),
                    last_client_ip=meta.get("client_ip"),
                )
            )

    ctx_log.info(
        "session_persisted_to_db",
        extra={"extra_fields": {
            "session_key": session_id,
            "bytes_rx":    bytes_rx,
            "bytes_tx":    bytes_tx,
            "reason":      reason
        }}
    )


async def wg_peer_exists(public_key: str, iface: str, ctx_log=None) -> bool:
    """Check if a WireGuard peer exists on the given interface."""
    log = ctx_log or logger
    try:
        proc = await asyncio.create_subprocess_exec(
            WG_BIN, "show", iface, "peers",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            log.warning(
                "wg_interface_unavailable",
                extra={"extra_fields": {
                    "interface": iface,
                    "error": stderr.decode().strip()
                }}
            )
            return False

        peers = stdout.decode().strip().splitlines()
        return public_key.strip() in peers

    except Exception:
        log.error("wg_peer_exists_failed", exc_info=True)
        return False


async def wg_remove_peer(public_key: str, ctx_log=None) -> bool:
    """
    Remove a WireGuard peer from both interfaces.
    wg_manager owns peer setup; session_manager only removes on cleanup.
    Returns True if both removals succeeded (or peer was already absent).
    """
    log = ctx_log or logger
    results = []

    for iface in (WG_INTERFACE, WG_PROXY_INTERFACE):
        if not await wg_peer_exists(public_key, iface, ctx_log=log):
            log.debug("wg_peer_remove_skip", extra={"extra_fields": {
                "peer": public_key[:10], "interface": iface
            }})
            results.append(True)
            continue

        log.info("wg_peer_remove_requested", extra={"extra_fields": {
            "peer": public_key[:10], "interface": iface
        }})

        proc = await asyncio.create_subprocess_exec(
            WG_BIN, "set", iface,
            "peer", public_key.strip(), "remove",
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            log.error("wg_peer_remove_failed", extra={"extra_fields": {
                "peer":      public_key[:10],
                "interface": iface,
                "error":     stderr.decode().strip()
            }})
            results.append(False)
        else:
            log.info("wg_peer_remove_success", extra={"extra_fields": {
                "peer": public_key[:10], "interface": iface
            }})
            results.append(True)

    return all(results)


async def collect_wg_stats():
    """
    Collect WireGuard traffic stats from both interfaces and update session data.

    wg0 tracks VPN traffic (rx/tx from the remote-access interface).
    wg1 tracks Tor-routed traffic.  We accumulate both into the session so that
    finalize_session reports total bytes across both tunnels.
    """
    while True:
        try:
            for iface in (WG_INTERFACE, WG_PROXY_INTERFACE):
                proc = await asyncio.create_subprocess_exec(
                    WG_BIN, "show", iface, "dump",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    logger.warning(
                        "wg_stats_iface_unavailable",
                        extra={"extra_fields": {
                            "interface": iface,
                            "error":     stderr.decode().strip()
                        }}
                    )
                    continue

                lines = stdout.decode().splitlines()[1:]  # skip header

                for line in lines:
                    fields = line.split("\t")
                    if len(fields) < 7:
                        continue

                    public_key = fields[0]
                    rx_bytes   = int(fields[5])
                    tx_bytes   = int(fields[6])

                    sid = await r.get(f"wg:peer:{public_key}")
                    if not sid:
                        continue

                    # Read existing so we can accumulate across both interfaces
                    existing = await r.hgetall(f"vpn:session:{sid}")
                    if not existing:
                        continue

                    await r.hset(
                        f"vpn:session:{sid}",
                        mapping={
                            "rx_bytes": rx_bytes + int(existing.get("rx_bytes", 0)),
                            "tx_bytes": tx_bytes + int(existing.get("tx_bytes", 0)),
                        }
                    )

        except Exception:
            logger.error("wg_stats_collection_failed", exc_info=True)

        await asyncio.sleep(WG_STATS_INTERVAL)


# ==========================================================
# IPAM Client
# ==========================================================

async def call_ipam(action: str, user_id: str, device_id: str, ctx_log=None):
    """Call IPAM service with timeout and error handling."""
    log = ctx_log or logger
    request_id = getattr(log, 'extra', {}).get('request_id')
    try:
        reader, writer = await asyncio.open_unix_connection(IPAM_SOCKET_PATH)
        try:
            writer.write(json.dumps({
                "request_id": request_id,
                "action":     action,
                "user_id":    user_id,
                "device_id":  device_id
            }).encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)

            if not data:
                log.error("ipam_empty_response")
                return {"error": "empty_response"}

            resp = json.loads(data.decode())

            if "error" in resp:
                log.warning("ipam_action_failed", extra={"extra_fields": {
                    "action":   action,
                    "response": resp
                }})
            else:
                log.debug("ipam_action_success", extra={"extra_fields": {"action": action}})

            return resp
        finally:
            writer.close()
            await writer.wait_closed()

    except asyncio.TimeoutError:
        log.error("ipam_socket_timeout")
        return {"error": "ipam_timeout"}
    except Exception:
        log.error("ipam_socket_error", exc_info=True)
        return {"error": "ipam_unreachable"}


# ==========================================================
# Session Lifecycle
# ==========================================================

async def soft_disconnect(session_id: str, session: dict, ctx_log=None):
    """Mark session as offline without full cleanup."""
    log = ctx_log or logger

    log.warning("heartbeat_lost", extra={"extra_fields": {"session_id": session_id}})

    if session.get("public_key"):
        await wg_remove_peer(session["public_key"], ctx_log=log)

    await r.hset(f"vpn:session:{session_id}", "state", "offline")

    updated_session = await r.hgetall(f"vpn:session:{session_id}")
    if updated_session:
        await r.publish("vpn:live_events", json.dumps({
            "action":     "session_offline",
            "session_id": session_id,
            "user_id":    updated_session.get("user_id"),
            "device_id":  updated_session.get("device_id"),
            "timestamp":  int(time.time())
        }))

    log.info("session_marked_offline")


async def hard_cleanup(session_id: str, meta: dict, ctx_log=None):
    """Perform full cleanup of session resources."""
    log = ctx_log or get_context_logger(
        session_id=session_id,
        user_id=meta.get("user_id"),
        device_id=meta.get("device_id")
    )

    log.info("hard_cleanup_started")

    try:
        await finalize_session(
            session_id=session_id,
            meta=meta,
            reason=meta.get("close_reason", "disconnect"),
            ctx_log=log
        )
    except Exception:
        log.error("session_finalize_failed", exc_info=True)

    if meta.get("public_key"):
        await wg_remove_peer(meta["public_key"], ctx_log=log)

    if meta.get("user_id") and meta.get("device_id"):
        await call_ipam("release", meta["user_id"], meta["device_id"], ctx_log=log)
        await r.delete(f"vpn:device:{meta['user_id']}:{meta['device_id']}")

    session_state = meta.get("state")

    async with r.pipeline() as p:
        p.delete(f"vpn:session:{session_id}")
        p.delete(f"vpn:session:{session_id}:hb")
        p.delete(f"meta:{session_id}")
        await p.execute()

    await r.publish("vpn:live_events", json.dumps({
        "action":     "session_closed",
        "session_id": session_id,
        "user_id":    meta.get("user_id"),
        "device_id":  meta.get("device_id"),
        "state":      session_state,
        "timestamp":  int(time.time())
    }))

    log.info("hard_cleanup_completed")


async def terminate_user_sessions(user_id: str):
    """Forcefully close all active sessions of a user."""
    async for key in r.scan_iter("vpn:session:*"):
        if key.endswith(":hb"):
            continue

        session = await r.hgetall(key)
        if not session:
            continue

        if session.get("user_id") != user_id:
            continue

        sid = session.get("session_id") or key.split(":")[-1]

        ctx = get_context_logger(
            request_id=f"user-disable-{uuid.uuid4().hex[:6]}",
            session_id=sid,
            user_id=user_id,
            device_id=session.get("device_id")
        )

        ctx.warning("force_closing_session_due_to_user_state")
        session["close_reason"] = "revoked"
        await hard_cleanup(sid, session, ctx)


# ==========================================================
# Watchers
# ==========================================================

async def user_event_listener(redis_client):
    """Listen for user event notifications."""
    logger.info("user_event_listener_started")

    pubsub = redis_client.pubsub()
    await pubsub.subscribe("vpn:user_events")

    async for msg in pubsub.listen():
        if msg["type"] != "message":
            continue

        try:
            event  = json.loads(msg["data"])
            action = event.get("action")

            if action != "user_disabled":
                continue

            user_id = event.get("user_id")
            reason  = event.get("reason")

            if not user_id:
                logger.error("user_disabled_event_missing_user_id")
                continue

            logger.warning("user_disabled_event_received", extra={
                "extra_fields": {"user_id": user_id, "reason": reason}
            })

            await terminate_user_sessions(user_id)

        except Exception:
            logger.error("user_event_processing_failed", exc_info=True)


async def heartbeat_watcher(redis_client):
    """Watch for missed heartbeats and mark sessions offline."""
    logger.info("heartbeat_watcher_started")

    while True:
        try:
            async for key in redis_client.scan_iter("vpn:session:*"):
                if key.endswith(":hb") or key.endswith(":finalized"):
                    continue

                key_type = await redis_client.type(key)
                if key_type != "hash":
                    continue

                sid = key.split(":")[-1]

                if not await redis_client.exists(f"{key}:hb"):
                    session = await redis_client.hgetall(key)
                    if session and session.get("state") != "offline":
                        ctx = get_context_logger(
                            request_id=f"auto-hb-{uuid.uuid4().hex[:6]}",
                            session_id=sid,
                            user_id=session.get("user_id"),
                            device_id=session.get("device_id")
                        )
                        await soft_disconnect(sid, session, ctx)

        except Exception:
            logger.error("heartbeat_watcher_error", exc_info=True)

        await asyncio.sleep(WATCH_INTERVAL)


async def expiration_listener(redis_client):
    """Listen for Redis key expiration events."""
    logger.info("expiration_listener_started")

    pubsub = redis_client.pubsub()
    await pubsub.subscribe("__keyevent@0__:expired")

    async for msg in pubsub.listen():
        if msg["type"] != "message":
            continue

        key = msg["data"]
        if key.startswith("vpn:session:") and not key.endswith(":hb"):
            sid      = key.split(":")[-1]
            meta_raw = await redis_client.get(f"meta:{sid}")
            if meta_raw:
                meta = json.loads(meta_raw)
                ctx  = get_context_logger(
                    session_id=sid,
                    user_id=meta.get("user_id"),
                    device_id=meta.get("device_id")
                )
                await hard_cleanup(sid, meta, ctx)


# ==========================================================
# API Handlers
# ==========================================================

async def create_session(payload: dict, ctx_log):
    """
    Create a new VPN session.

    wg_manager has already added the peer to both wg0 and wg1 before calling
    here, so this handler only needs to:
      1. Write session state to Redis
      2. Publish the live event so the dashboard updates
      3. Insert the history row into PostgreSQL
    """
    required_fields = ["session_id", "user_id", "device_id", "public_key", "vpn_ip", "tor_ip"]
    missing = [f for f in required_fields if f not in payload]

    if missing:
        ctx_log.error("missing_required_fields", extra={"extra_fields": {"missing": missing}})
        return {"status": "error", "error": "missing_fields", "fields": missing}

    sid       = payload["session_id"]
    uid       = payload["user_id"]
    did       = payload["device_id"]
    client_ip = payload.get("client_ip")

    payload["state"]     = "online"
    now                  = int(time.time())
    payload["timestamp"] = now

    # Strip None values — redis-py raises DataError on None in hset mappings.
    # Cast everything to str so Redis stores clean string values.
    redis_mapping = {k: str(v) for k, v in payload.items() if v is not None}

    try:
        async with r.pipeline() as p:
            p.hset(f"vpn:session:{sid}", mapping=redis_mapping)
            p.expire(f"vpn:session:{sid}", HARD_TTL)
            p.setex(f"vpn:session:{sid}:hb", HEARTBEAT_TTL, "alive")
            p.set(f"vpn:device:{uid}:{did}", sid, ex=HARD_TTL)
            p.set(f"meta:{sid}", json.dumps(payload), ex=HARD_TTL + 60)
            await p.execute()
    except Exception:
        ctx_log.error("session_redis_write_failed", exc_info=True)
        return {"status": "error", "error": "redis_write_failed"}

    # Publish before DB write so the dashboard updates immediately
    await r.publish("vpn:live_events", json.dumps({
        "action":     "session_created",
        "session_id": sid,
        "device_id":  did,
        "client_ip":  client_ip,
        "vpn_ip":     payload.get("vpn_ip"),
        "tor_ip":     payload.get("tor_ip"),
        "user_id":    uid,
        "timestamp":  now,
        "state":      "online"
    }))

    # NOTE: wg_manager already added the peer to both wg0 and wg1.
    #       session_manager must NOT call wg_add_peer here — doing so would
    #       attempt to overwrite allowed-ips on wg0 with both IPs, breaking the
    #       dual-interface routing that wg_manager set up.

    ctx_log.info("session_created")

    try:
        async with AsyncSessionLocal() as db:
            await db.execute(
                insert(vpn_session_history).values(
                    session_key=sid,
                    user_id=uid,
                    device_id=did,
                    public_key=payload["public_key"],
                    vpn_ip=payload["vpn_ip"],
                    tor_ip=payload.get("tor_ip"),
                    client_ip=client_ip,
                    started_at=datetime.now(UTC),
                    ended_at=None,
                )
            )
            await db.commit()
    except Exception:
        # Non-fatal: session is live in Redis, history write can be retried
        ctx_log.error("session_history_insert_failed", exc_info=True)

    return {
        "status":        "ok",
        "heartbeat_ttl": HEARTBEAT_TTL,
        "hard_ttl":      HARD_TTL
    }


async def heartbeat(payload: dict, ctx_log):
    """Handle client heartbeat/keepalive."""
    required_fields = ["session_id"]
    missing = [f for f in required_fields if f not in payload]

    if missing:
        ctx_log.error("missing_required_fields", extra={"extra_fields": {"missing": missing}})
        return {"status": "error", "error": "missing_fields"}

    sid       = payload["session_id"]
    client_ip = payload.get("client_ip")
    now       = int(time.time())

    session = await r.hgetall(f"vpn:session:{sid}")

    if not session:
        ctx_log.warning("heartbeat_for_expired_session")
        return {"status": "error", "error": "session_expired"}

    await r.setex(f"vpn:session:{sid}:hb", HEARTBEAT_TTL, "alive")
    await r.hset(f"vpn:session:{sid}", "timestamp", now)

    if client_ip:
        await r.hset(f"vpn:session:{sid}", "client_ip", client_ip)

    recovered = False
    session   = await r.hgetall(f"vpn:session:{sid}")

    if session.get("state") == "offline":
        ctx_log.info("attempting_session_recovery", extra={"extra_fields": {"session_id": sid}})

        # Re-add peer to both interfaces on recovery
        public_key = session.get("public_key")
        if public_key:
            for iface, ip_key in ((WG_INTERFACE, "vpn_ip"), (WG_PROXY_INTERFACE, "tor_ip")):
                ip = session.get(ip_key)
                if not ip:
                    continue
                proc = await asyncio.create_subprocess_exec(
                    WG_BIN, "set", iface,
                    "peer", public_key.strip(),
                    "allowed-ips", f"{ip}/32",
                    stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await proc.communicate()
                if proc.returncode != 0:
                    ctx_log.error("wg_recovery_peer_add_failed", extra={"extra_fields": {
                        "interface": iface,
                        "error":     stderr.decode().strip()
                    }})

        await r.hset(
            f"vpn:session:{sid}",
            mapping={
                "state":     "online",
                "client_ip": client_ip or session.get("client_ip", "")
            }
        )

        recovered = True
        ctx_log.info("session_recovered")

    updated_session = await r.hgetall(f"vpn:session:{sid}")

    if not updated_session:
        ctx_log.warning("session_disappeared_after_heartbeat")
        return {"status": "ok"}

    updated_session["timestamp"] = now

    await r.publish("vpn:live_events", json.dumps({
        "action":     "heartbeat_update",
        "session_id": sid,
        "user_id":    updated_session.get("user_id"),
        "device_id":  updated_session.get("device_id"),
        "client_ip":  client_ip or updated_session.get("client_ip"),
        "vpn_ip":     updated_session.get("vpn_ip"),
        "tor_ip":     updated_session.get("tor_ip"),
        "recovered":  recovered,
        "timestamp":  now
    }))

    ctx_log.debug("heartbeat_ok")
    return {"status": "reconnected" if recovered else "ok"}


async def close_session(payload: dict, ctx_log):
    """Close an active VPN session."""
    required_fields = ["session_id"]
    missing = [f for f in required_fields if f not in payload]

    if missing:
        ctx_log.error("missing_required_fields", extra={"extra_fields": {"missing": missing}})
        return {"status": "error", "error": "missing_fields"}

    sid      = payload["session_id"]
    meta_raw = await r.get(f"meta:{sid}")

    if not meta_raw:
        ctx_log.warning("close_session_meta_missing")
        return {"status": "error", "error": "not_found"}

    meta = json.loads(meta_raw)
    await hard_cleanup(sid, meta, ctx_log)

    ctx_log.info("session_closed")
    return {"status": "ok"}


# ==========================================================
# Server
# ==========================================================

async def handle_client(reader, writer):
    """Handle incoming client connections."""
    tx_id = str(uuid.uuid4())[:8]

    try:
        raw = await reader.read(4096)
        req = json.loads(raw.decode())

        action = req.get("action")

        if not isinstance(req, dict):
            raise ValueError("Invalid request format")

        payload = req.get("payload", {})

        if action == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()
            writer.close()
            return

        ctx_log = get_context_logger(
            request_id=payload.get("request_id", tx_id),
            session_id=payload.get("session_id"),
            user_id=payload.get("user_id"),
            device_id=payload.get("device_id"),
            client_ip=payload.get("client_ip")
        )

        handlers = {
            "create_session": create_session,
            "heartbeat":      heartbeat,
            "close_session":  close_session
        }

        handler = handlers.get(action)
        if not handler:
            ctx_log.warning("invalid_action")
            resp = {"status": "error", "error": "invalid_action"}
        else:
            resp = await handler(payload, ctx_log)

    except Exception:
        logger.error("request_handling_failed", exc_info=True)
        resp = {"status": "error", "error": "internal_error"}

    writer.write(json.dumps(resp).encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main():
    """Main server entry point with signal handling and graceful shutdown."""

    stop_event = asyncio.Event()
    loop       = asyncio.get_running_loop()

    def handle_exit_signal(sig_name):
        logger.info(
            "session_manager_shutdown_initiated",
            extra={"extra_fields": {"signal": sig_name}}
        )
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_exit_signal(s.name))

    # ── Socket directory ───────────────────────────────────────────────────
    if not os.path.exists(SOCKET_DIR):
        try:
            os.makedirs(SOCKET_DIR, mode=SOCKET_DIR_MODE, exist_ok=True)
            gid = grp.getgrnam(SOCKET_GROUP).gr_gid
            os.chown(SOCKET_DIR, 0, gid)
        except Exception as e:
            logger.warning(f"Directory setup warning: {e}")

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    # ── Redis ──────────────────────────────────────────────────────────────
    # One shared client for all background tasks (watchers, listeners, stats).
    # The module-level `r` is used by request handlers; close both on shutdown.
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)

    try:
        await redis_client.config_set("notify-keyspace-events", "Ex")
        logger.info("redis_keyspace_notifications_enabled")
    except Exception as e:
        logger.critical(
            "redis_keyspace_notifications_failed",
            extra={"extra_fields": {"error": str(e)}}
        )
        raise

    # ── Unix socket server ─────────────────────────────────────────────────
    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, SOCKET_PERMS)
        logger.info("socket_permissions_secured", extra={"extra_fields": {"path": SOCKET_PATH}})
    except Exception as e:
        logger.error(f"failed_to_set_socket_permissions: {e}")

    logger.info("session_manager_ready")

    tasks = [
        asyncio.create_task(server.serve_forever()),
        asyncio.create_task(heartbeat_watcher(redis_client)),
        asyncio.create_task(expiration_listener(redis_client)),
        asyncio.create_task(user_event_listener(redis_client)),
        asyncio.create_task(collect_wg_stats()),
    ]

    await stop_event.wait()

    # ── Graceful shutdown ──────────────────────────────────────────────────
    logger.info("session_manager_stopping_background_tasks")

    server.close()
    await server.wait_closed()

    for task in tasks:
        task.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)

    # Close both Redis connections: the shared background client and the
    # module-level `r` used by request handlers.
    await redis_client.aclose()
    await r.aclose()

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    logger.info("session_manager_stopped_cleanly")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.critical("session_manager_crash", exc_info=True)