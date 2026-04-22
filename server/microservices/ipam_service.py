# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import redis
import ipaddress
import os
import uuid
import time
from utils.ipam_logging_utils import get_logger, get_context_logger
import grp
import signal

# ================= CONFIG =================

CONFIG_PATH = os.environ.get("IPAM_CONFIG", "ipam_config.json")

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

cfg = load_config(CONFIG_PATH)

# Socket
SOCKET_DIR  = cfg["socket"]["dir"]
SOCKET_PATH = cfg["socket"]["path"]
SOCKET_GROUP = cfg["socket"]["group"]
SOCKET_PERMS = int(cfg["socket"]["permissions"], 8)

# Network
VPN_CIDR = cfg["network"]["vpn_cidr"]
TOR_CIDR = cfg["network"]["tor_cidr"]

# Redis
REDIS_HOST    = cfg["redis"]["host"]
REDIS_PORT    = cfg["redis"]["port"]
VPN_POOL_KEY  = cfg["redis"]["keys"]["vpn_pool"]
TOR_POOL_KEY  = cfg["redis"]["keys"]["tor_pool"]
MAPPING_KEY   = cfg["redis"]["keys"]["mapping"]

# ==========================================

logger = get_logger()

logger.info(
    "ipam_service_starting",
    extra={"extra_fields": {
        "vpn_cidr": VPN_CIDR,
        "tor_cidr": TOR_CIDR
    }}
)

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True
)

# ---------- Lua script (atomic dual allocation) ----------

ALLOCATE_LUA = """
local vpn_pool = KEYS[1]
local tor_pool = KEYS[2]
local map = KEYS[3]

local key = ARGV[1]

local existing = redis.call("HGET", map, key)
if existing then
  return existing
end

local vpn_ip = redis.call("SPOP", vpn_pool)
if not vpn_ip then
  return nil
end

local tor_ip = redis.call("SPOP", tor_pool)
if not tor_ip then
  redis.call("SADD", vpn_pool, vpn_ip)
  return nil
end

local value = cjson.encode({
  vpn_ip = vpn_ip,
  tor_ip = tor_ip
})

redis.call("HSET", map, key, value)
return value
"""

RELEASE_LUA = """
local map = KEYS[1]
local vpn_pool = KEYS[2]
local tor_pool = KEYS[3]
local key = ARGV[1]

local raw = redis.call("HGET", map, key)
if not raw then
  return nil
end

local obj = cjson.decode(raw)

redis.call("HDEL", map, key)
redis.call("SADD", vpn_pool, obj.vpn_ip)
redis.call("SADD", tor_pool, obj.tor_ip)

return raw
"""

release_script  = r.register_script(RELEASE_LUA)
allocate_script = r.register_script(ALLOCATE_LUA)

# --------------------------------------------------------


def log(msg: str):
    print(f"[IPAM] {time.strftime('%Y-%m-%d %H:%M:%S')} | {msg}")


def validate_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except Exception:
        return False


def init_pool(pool_key: str, cidr: str):
    if r.exists(pool_key):
        return

    network = ipaddress.ip_network(cidr)
    ips = [str(ip) for ip in list(network.hosts())[1:]]  # skip gateway
    r.sadd(pool_key, *ips)

    logger.info(
        "ip_pool_initialized",
        extra={"extra_fields": {
            "pool": pool_key,
            "cidr": cidr,
            "size": len(ips)
        }})


async def handle_client(reader, writer):
    try:
        data = await reader.read(4096)
        if not data:
            return

        request = json.loads(data.decode())
        action = request.get("action")

        if action == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()
            return

        user_id   = request.get("user_id")
        device_id = request.get("device_id")
        request_id = request.get("request_id") or str(uuid.uuid4())

        log = get_context_logger(
            request_id=request_id,
            user_id=user_id,
            device_id=device_id
        )

        log.info(
            "ipam_request_received",
            extra={"extra_fields": {"action": action}}
        )

        if not validate_uuid(user_id) or not validate_uuid(device_id):
            log.warning(
                "invalid_identity",
                extra={"extra_fields": {"reason": "uuid_validation_failed"}}
            )
            writer.write(json.dumps({"error": "invalid_identity"}).encode())
            await writer.drain()
            return

        map_key = f"{user_id}:{device_id}"

        # ---------- ALLOCATE ----------
        if action == "allocate":
            result = allocate_script(
                keys=[VPN_POOL_KEY, TOR_POOL_KEY, MAPPING_KEY],
                args=[map_key]
            )

            if result:
                ips = json.loads(result)
                log.info(
                    "ip_allocated",
                    extra={"extra_fields": {
                        "vpn_ip": ips["vpn_ip"],
                        "tor_ip": ips["tor_ip"]
                    }}
                )
                response = {
                    "status": "allocated",
                    "vpn_ip": ips["vpn_ip"],
                    "tor_ip": ips["tor_ip"]
                }
            else:
                log.warning(
                    "ip_pool_exhausted",
                    extra={"extra_fields": {"action": "allocate"}}
                )
                response = {"error": "pool_exhausted"}

        # ---------- RELEASE ----------
        elif action == "release":
            result = release_script(
                keys=[MAPPING_KEY, VPN_POOL_KEY, TOR_POOL_KEY],
                args=[map_key]
            )

            if result:
                log.info("ip_released")
                response = {"status": "released"}
            else:
                log.warning(
                    "release_not_found",
                    extra={"extra_fields": {"reason": "mapping_missing"}}
                )
                response = {"error": "not_found"}

        # ---------- STATUS ----------
        elif action == "status":
            free_vpn = r.scard(VPN_POOL_KEY)
            free_tor = r.scard(TOR_POOL_KEY)
            used     = r.hlen(MAPPING_KEY)

            response = {
                "status": "ok",
                "vpn_free": free_vpn,
                "tor_free": free_tor,
                "used_devices": used
            }
            log.info("ipam_status_checked")

        else:
            response = {"error": "invalid_action"}

        writer.write(json.dumps(response).encode())
        await writer.drain()

    except Exception:
        logger.error("ipam_internal_error", exc_info=True)
        writer.write(json.dumps({"error": "internal_error"}).encode())
        await writer.drain()

    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def handle_exit_signal(sig_name):
        logger.info(
            "ipam_service_shutdown_initiated",
            extra={"extra_fields": {"signal": sig_name}}
        )
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_exit_signal(s.name))

    os.makedirs(SOCKET_DIR, exist_ok=True)

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    init_pool(VPN_POOL_KEY, VPN_CIDR)
    init_pool(TOR_POOL_KEY, TOR_CIDR)

    server = await asyncio.start_unix_server(
        handle_client,
        path=SOCKET_PATH
    )

    try:
        os.chmod(SOCKET_PATH, SOCKET_PERMS)
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, -1, gid)
    except Exception as e:
        logger.warning(f"Could not set socket permissions: {e}")

    log(f"IPAM service listening on {SOCKET_PATH}")

    async with server:
        server_task = asyncio.create_task(server.serve_forever())
        await stop_event.wait()

        logger.info("ipam_service_cleaning_up")
        server_task.cancel()
        r.close()

    logger.info("ipam_service_stopped_cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        logger.error("ipam_service_crash", exc_info=True)
