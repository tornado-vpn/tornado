# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import logging

logger = logging.getLogger(__name__)

class RoutingServiceClient:
    def __init__(self, socket_path: str = "/run/routing/routing.sock"):
        self.socket_path = socket_path

    async def _send_command(self, payload: dict):
        """Internal helper to communicate with the Unix socket."""
        try:
            reader, writer = await asyncio.open_unix_connection(self.socket_path)
            
            writer.write(json.dumps(payload).encode())
            await writer.drain()
            
            data = await reader.read(2048)
            writer.close()
            await writer.wait_closed()
            
            return json.loads(data.decode())
        except Exception as e:
            logger.error(f"Failed to connect to Routing Service: {e}")
            return {"status": "error", "message": "routing_service_unavailable"}

    async def set_user_mode(self, user_id: str, mode: str):
        """Modes: 'normal' or 'tor'"""
        return await self._send_command({
            "action": "set_routing",
            "user_id": user_id,
            "mode": mode
        })

    async def disconnect_user(self, user_id: str):
        """Clean up rules when a user leaves the VPN."""
        return await self._send_command({
            "action": "cleanup",
            "user_id": user_id
        })