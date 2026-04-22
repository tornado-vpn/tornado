# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os

WG_SOCKET_PATH = "/run/tornado/wg_mgr.sock"

async def call_wg_manager(action: str, data: dict, timeout: int = 5) -> dict:
    """
    Unified handler for communicating with the WireGuard Manager microservice.
    """
    if not os.path.exists(WG_SOCKET_PATH):
        return {"status": "error", "error": "socket_not_found"}

    try:
        # Connect with a timeout to prevent the API from hanging
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(WG_SOCKET_PATH), 
            timeout=timeout
        )

        # Merge action and data into a single request
        request_payload = {
            "action": action,
            **data
        }

        writer.write(json.dumps(request_payload).encode())
        await writer.drain()

        # Read response
        response_data = await reader.read(8192)
        writer.close()
        await writer.wait_closed()

        if not response_data:
            return {"status": "error", "error": "empty_response"}

        return json.loads(response_data.decode())

    except asyncio.TimeoutError:
        return {"status": "error", "error": "connection_timeout"}
    except Exception as e:
        return {"status": "error", "error": str(e)}