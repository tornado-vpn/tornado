# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import redis.asyncio as redis
import os

# Configuration (Use environment variables for production)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

class RedisManager:
    def __init__(self):
        self.pool = None

    async def connect(self):
        """Initialize the connection pool."""
        if not self.pool:
            self.pool = redis.from_url(
                REDIS_URL, 
                decode_responses=True, 
                encoding="utf-8"
            )
        return self.pool

    async def disconnect(self):
        """Close the connection pool."""
        if self.pool:
            await self.pool.close()

# Create a singleton instance
redis_manager = RedisManager()

async def get_redis_conn():
    """
    Helper function to be used as a FastAPI dependency 
    or inside other services.
    """
    return await redis_manager.connect()