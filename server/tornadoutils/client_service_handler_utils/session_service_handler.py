# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os



async def call_session_service(action: str, payload: dict):
    """
    Sends request to the session manager socket.
    """
    try:
        reader, writer = await asyncio.open_unix_connection("/run/tornado/session.sock")
        writer.write(json.dumps({
            "action": action,
            "payload": payload
        }).encode())
        await writer.drain()

        data = await reader.read(8192)
        writer.close()
        await writer.wait_closed()
        return json.loads(data.decode())
    except Exception as e:
        return {"error": f"session_service_error: {str(e)}"}