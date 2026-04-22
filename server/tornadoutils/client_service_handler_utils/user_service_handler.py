# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json

SOCKET_PATH = "/run/tornado/user_service.sock"


async def uds_call(action: str, payload: dict):
    reader, writer = await asyncio.open_unix_connection(SOCKET_PATH)

    request = {
        "action": action,
        "payload": payload
    }

    writer.write(json.dumps(request).encode())
    await writer.drain()

    response = await reader.read(8192)
    writer.close()

    return json.loads(response.decode())
