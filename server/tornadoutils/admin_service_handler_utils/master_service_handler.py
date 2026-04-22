# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import uuid
import logging

# ================= CONFIG =================
# Ensure this matches the MASTER_SOCKET in your MASTER_service.py
MASTER_SOCKET = "/run/tornado/master.sock"
DEFAULT_TIMEOUT = 5.0  # Seconds to wait before giving up on the Master

logger = logging.getLogger("master_handler")

async def master_uds_call(command: str, target: str = "all", socket_path: str = MASTER_SOCKET) -> dict:
    """
    Communicates with the Master Service via Unix Domain Socket.
    
    :param command: 'start', 'stop', 'restart', 'status', or 'reload_config'
    :param target: Specific service name or 'all'
    :param socket_path: Path to the master controller socket
    :return: Dictionary containing 'status' and 'message' (or 'services' for status)
    """
    
    # 1. Pre-flight check: Does the socket even exist?
    if not os.path.exists(socket_path):
        return {
            "status": "error", 
            "message": f"Master service socket not found at {socket_path}. Is the Master running?"
        }

    writer = None
    try:
        # 2. Establish connection with a timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path), 
            timeout=2.0
        )

        # 3. Prepare the control payload
        payload = {
            "command": command,
            "target": target,
            "request_id": str(uuid.uuid4())
        }

        # 4. Send the request
        writer.write(json.dumps(payload).encode())
        await writer.drain()

        # 5. Read response with timeout 
        # (Prevents blocking your API if the Master is deadlocked)
        response_data = await asyncio.wait_for(
            reader.read(8192), # Increased buffer for 'status all' commands
            timeout=DEFAULT_TIMEOUT
        )

        if not response_data:
            return {"status": "error", "message": "Master service closed connection without response"}

        return json.loads(response_data.decode())

    except asyncio.TimeoutError:
        logger.error(f"Timeout communicating with Master on command: {command}")
        return {"status": "error", "message": "Master service timed out"}
    
    except ConnectionRefusedError:
        return {"status": "error", "message": "Connection refused. Master service might be restarting."}
    
    except json.JSONDecodeError:
        return {"status": "error", "message": "Received malformed response from Master"}
    
    except Exception as e:
        logger.exception("Unexpected error in master_uds_call")
        return {"status": "error", "message": f"Internal Handler Error: {str(e)}"}

    finally:
        # 6. Ensure the socket is always closed gracefully
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass