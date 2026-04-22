# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os

# Path to the auth microservice Unix socket
SOCKET_PATH = "/run/tornado/auth_service.sock"


async def auth_uds_call(action: str, payload: dict, socket_path: str = SOCKET_PATH) -> dict:
    """
    Sends a JSON payload to the Auth microservice over Unix socket
    and returns the JSON response.
    """
    if not os.path.exists(socket_path):
        raise RuntimeError(f"Auth microservice socket not found at {socket_path}")

    reader, writer = await asyncio.open_unix_connection(socket_path)

    request = json.dumps({
        "action": action,
        "payload": payload
    }).encode()

    writer.write(request)
    await writer.drain()

    response_data = await reader.read(8192)
    writer.close()
    await writer.wait_closed()

    if not response_data:
        raise RuntimeError("No response from Auth microservice")

    try:
        response = json.loads(response_data.decode())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON response: {e}")

    return response
