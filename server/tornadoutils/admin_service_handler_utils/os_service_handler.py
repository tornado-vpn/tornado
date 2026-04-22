# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
from typing import Optional

from fastapi import HTTPException

SOCKET_PATH = "/run/tornado/os_services.sock"


async def uds_call(command: str, target: Optional[str] = None) -> dict:
    """Send a JSON command to the OS-services Unix socket and return the response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(SOCKET_PATH), timeout=5.0
        )
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raise HTTPException(status_code=503, detail=f"Socket unavailable: {exc}")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timed out connecting to socket.")

    payload: dict = {"command": command}
    if target is not None:
        payload["target"] = target

    try:
        writer.write(json.dumps(payload).encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
        writer.close()
        await writer.wait_closed()
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timed out waiting for response.")

    try:
        return json.loads(raw.decode())
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail=f"Bad response from socket: {exc}")


def raise_if_error(result: dict) -> dict:
    """Propagate socket-level errors as HTTP 400."""
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message", "Unknown error"))
    return result


# ── Convenience wrappers used by the API layer ────────────────────────────────

async def ping() -> dict:
    return await uds_call("ping")


async def list_services() -> dict:
    return raise_if_error(await uds_call("list"))


async def get_status(target: str = "all") -> dict:
    return raise_if_error(await uds_call("status", target=target))


async def start_service(target: str) -> dict:
    return raise_if_error(await uds_call("start", target=target))


async def stop_service(target: str) -> dict:
    return raise_if_error(await uds_call("stop", target=target))


async def restart_service(target: str) -> dict:
    return raise_if_error(await uds_call("restart", target=target))


async def reload_config() -> dict:
    return raise_if_error(await uds_call("reload_config"))
