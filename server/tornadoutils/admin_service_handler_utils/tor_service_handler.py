# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json

TOR_SOCK = "/run/tornado/tor_mgr.sock"


async def call_tor_service(action: str, payload: dict = None) -> dict:
    try:
        reader, writer = await asyncio.open_unix_connection(TOR_SOCK)

        request = {"action": action}
        if payload:
            request.update(payload)

        writer.write(json.dumps(request).encode())
        await writer.drain()

        data = await reader.read(65536)   # larger buffer — circuit data can be big
        writer.close()
        await writer.wait_closed()

        return json.loads(data.decode())

    except FileNotFoundError:
        return {"error": f"tor_service_error: socket not found at {TOR_SOCK}"}
    except ConnectionRefusedError:
        return {"error": "tor_service_error: daemon not running"}
    except Exception as e:
        return {"error": f"tor_service_error: {str(e)}"}


# ── Convenience wrappers ───────────────────────────────────────────────────────

async def tor_ping() -> dict:
    return await call_tor_service("ping")

async def tor_status() -> dict:
    return await call_tor_service("status")

async def tor_health() -> dict:
    return await call_tor_service("health")

async def tor_add_relay() -> dict:
    return await call_tor_service("add_relay")

async def tor_stop_relay(relay_id: str) -> dict:
    return await call_tor_service("stop_relay", {"id": relay_id})

async def tor_stop_all() -> dict:
    return await call_tor_service("stop")

async def tor_circuits(relay_id: str = None) -> dict:
    payload = {"id": relay_id} if relay_id else {}
    return await call_tor_service("relay_circuits", payload)

async def tor_logs(relay_id: str = None, lines: int = 50) -> dict:
    payload = {"lines": lines}
    if relay_id:
        payload["id"] = relay_id
    return await call_tor_service("logs", payload)

async def tor_apply_routing() -> dict:
    return await call_tor_service("apply_routing")

async def tor_remove_routing() -> dict:
    return await call_tor_service("remove_routing")

async def tor_routing_status() -> dict:
    return await call_tor_service("routing_status")


# ── Quick CLI test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    action  = sys.argv[1] if len(sys.argv) > 1 else "health"
    payload = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

    async def _main():
        result = await call_tor_service(action, payload)
        print(json.dumps(result, indent=2))

    asyncio.run(_main())
