# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import uuid

# Path to the Master Service Unix socket
MASTER_SOCKET = "/run/tornado/master.sock"

async def master_uds_call(command: str, target: str = "all", socket_path: str = MASTER_SOCKET) -> dict:
    """
    Communicates with the Master Service to control microservices.
    
    :param command: 'start', 'stop', 'restart', or 'reload_config'
    :param target: Specific service name (e.g., 'auth', 'vpn_api') or 'all'
    :param socket_path: Path to the master controller socket
    """
    if not os.path.exists(socket_path):
        raise RuntimeError(f"Master service socket not found at {socket_path}")

    try:
        reader, writer = await asyncio.open_unix_connection(socket_path)

        # Prepare the control payload
        payload = {
            "command": command,
            "target": target,
            "request_id": str(uuid.uuid4())
        }

        writer.write(json.dumps(payload).encode())
        await writer.drain()

        # Read response (Master usually responds with {"status": "ok"})
        response_data = await reader.read(4096)
        
        writer.close()
        await writer.wait_closed()

        if not response_data:
            return {"status": "error", "message": "No response from Master service"}

        return json.loads(response_data.decode())

    except ConnectionRefusedError:
        return {"status": "error", "message": "Master service is not running"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- Examples of Usage ---

async def example_usage():
    # 1. Restart only the Auth service
    # print(await master_uds_call("restart", target="auth"))

    # 2. Stop everything
    # print(await master_uds_call("stop", target="all"))

    # 3. Tell Master to reload services.json if you made manual changes
    print(await master_uds_call("reload_config"))

if __name__ == "__main__":
    asyncio.run(example_usage())