# utils/brute_force_guard.py

import redis.asyncio as redis_async
import redis.exceptions as redis_exceptions

# ── Tunables (or move to your config JSON) ──────────────────────────────────
MAX_ATTEMPTS   = 5          # failures before ban
BAN_DURATION   = 900        # ban length in seconds (15 min)
ATTEMPT_WINDOW = 300        # rolling window to count failures (5 min)
# ─────────────────────────────────────────────────────────────────────────────

_ATTEMPTS_KEY = "bf:attempts:{ip}"   # sorted-set: timestamps of failures
_BAN_KEY      = "bf:ban:{ip}"        # simple string: "1" when banned


async def is_banned(redis_client: redis_async.Redis, ip: str) -> bool:
    """Return True if this IP is currently banned."""
    return bool(await redis_client.exists(_BAN_KEY.format(ip=ip)))


async def record_failure(redis_client: redis_async.Redis, ip: str) -> int:
    """
    Record a failed attempt for this IP.
    Uses a sliding-window sorted set keyed by timestamp.
    Returns the current failure count within the window.
    Bans the IP automatically if MAX_ATTEMPTS is reached.
    """
    import time
    now       = time.time()
    window_start = now - ATTEMPT_WINDOW
    key       = _ATTEMPTS_KEY.format(ip=ip)

    pipe = redis_client.pipeline()
    pipe.zremrangebyscore(key, "-inf", window_start)   # drop old entries
    pipe.zadd(key, {str(now): now})                    # add this failure
    pipe.zcard(key)                                    # count in window
    pipe.expire(key, ATTEMPT_WINDOW)
    results = await pipe.execute()

    count = results[2]  # zcard result

    if count >= MAX_ATTEMPTS:
        await redis_client.setex(_BAN_KEY.format(ip=ip), BAN_DURATION, "1")

    return count


async def clear_failures(redis_client: redis_async.Redis, ip: str) -> None:
    """Clear failure history on successful login (optional but recommended)."""
    await redis_client.delete(_ATTEMPTS_KEY.format(ip=ip))
    await redis_client.delete(_BAN_KEY.format(ip=ip))


async def remaining_ban_ttl(redis_client: redis_async.Redis, ip: str) -> int:
    """How many seconds remain in the ban (-1 if not banned)."""
    ttl = await redis_client.ttl(_BAN_KEY.format(ip=ip))
    return ttl if ttl > 0 else -1



async def check_ban(redis_client: redis_async.Redis, ip: str) -> dict:
    """
    Returns {"banned": False} or {"banned": True, "retry_after": <seconds>}
    Atomic — single Redis call, no race condition.
    """
    ttl = await redis_client.ttl(_BAN_KEY.format(ip=ip))

    if ttl > 0:
        return {"banned": True, "retry_after": ttl}
    elif ttl == -1:
        # Key exists but has no expiry — shouldn't happen, but handle it
        await redis_client.expire(_BAN_KEY.format(ip=ip), BAN_DURATION)
        return {"banned": True, "retry_after": BAN_DURATION}
    else:
        # ttl == -2 means key doesn't exist → not banned
        return {"banned": False}