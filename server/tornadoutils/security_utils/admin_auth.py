# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

"""
auth.py — Admin authentication using .env credentials + JWT tokens.
No database required: credentials live in .env, tokens in signed JWTs.
"""

import os
import time
import hmac
import hashlib
import base64
import json
from typing import Optional
from functools import lru_cache

from dotenv import load_dotenv
from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

import threading
from dataclasses import dataclass, field
from collections import defaultdict

load_dotenv()



# ── Brute-force config (or move to .env) ─────────────────────────────────────
MAX_ATTEMPTS   = 5    # failures before ban
BAN_DURATION   = 900  # seconds (15 min)
ATTEMPT_WINDOW = 300  # rolling window in seconds (5 min)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _IPRecord:
    attempts: list = field(default_factory=list)  # timestamps of failures
    banned_until: float = 0.0                      # epoch timestamp


class BruteForceGuard:
    def __init__(self):
        self._records: dict[str, _IPRecord] = defaultdict(_IPRecord)
        self._lock = threading.Lock()

    def _evict_expired(self) -> None:
        """Must be called inside self._lock."""
        now = time.time()
        window_start = now - ATTEMPT_WINDOW
        dead = [
            ip for ip, rec in self._records.items()
            if rec.banned_until < now and all(t < window_start for t in rec.attempts)
        ]
        for ip in dead:
            del self._records[ip]

    def check_ban(self, ip: str) -> dict:
        now = time.time()
        with self._lock:
            record = self._records.get(ip)   # ← fix bug 1
            if record and record.banned_until > now:
                return {"banned": True, "retry_after": int(record.banned_until - now)}
            return {"banned": False}

    def record_failure(self, ip: str) -> int:
        now = time.time()
        window_start = now - ATTEMPT_WINDOW
        with self._lock:
            self._evict_expired()            # ← fix bug 2
            record = self._records[ip]
            record.attempts = [t for t in record.attempts if t > window_start]
            record.attempts.append(now)
            count = len(record.attempts)
            if count >= MAX_ATTEMPTS:
                record.banned_until = now + BAN_DURATION
            return count

    def clear(self, ip: str) -> None:
        with self._lock:
            self._records.pop(ip, None)

# Singleton — one guard for the whole process
_guard = BruteForceGuard()
# ── Config ────────────────────────────────────────────────────────────────────

_auth_config_cache: dict | None = None

def get_auth_config() -> dict:
    global _auth_config_cache
    if _auth_config_cache is not None:
        return _auth_config_cache
    load_dotenv(override=True)   # ← override=True so rotated values win
    _auth_config_cache = {
        "username":  os.getenv("ADMIN_USERNAME", "admin"),
        "password":  os.getenv("ADMIN_PASSWORD", "changeme"),
        "secret":    os.getenv("ADMIN_SECRET",   "supersecretkey-change-in-production"),
        "token_ttl": int(os.getenv("ADMIN_TOKEN_TTL", "28800")),
    }
    return _auth_config_cache

def invalidate_auth_config() -> None:
    global _auth_config_cache
    _auth_config_cache = None
    logger.info("auth_config_cache_invalidated")

# ── Minimal JWT (HMAC-SHA256, no extra deps) ──────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (padding % 4))

def _sign(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)

def create_token(username: str) -> str:
    cfg = get_auth_config()
    header  = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + cfg["token_ttl"],
    }).encode())
    sig = _sign(header, payload, cfg["secret"])
    return f"{header}.{payload}.{sig}"

def verify_token(token: str) -> Optional[dict]:
    """Returns payload dict if valid, None otherwise."""
    try:
        cfg = get_auth_config()
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig = parts
        expected_sig = _sign(header_b64, payload_b64, cfg["secret"])
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def verify_credentials(username: str, password: str, ip: str = "unknown") -> dict:
    """
    Returns {"ok": True} or {"ok": False, "reason": ..., "retry_after": ...}
    """
    # ── Ban check ────────────────────────────────────────────────────────────
    ban = _guard.check_ban(ip)
    if ban["banned"]:
        return {"ok": False, "reason": "ip_banned", "retry_after": ban["retry_after"]}

    cfg = get_auth_config()
    ok  = (
        hmac.compare_digest(username, cfg["username"]) and
        hmac.compare_digest(password, cfg["password"])
    )

    if not ok:
        count = _guard.record_failure(ip)
        remaining = MAX_ATTEMPTS - count
        return {
            "ok":         False,
            "reason":     "invalid_credentials",
            "attempts_left": max(0, remaining)
        }

    # ── Success — clear history ──────────────────────────────────────────────
    _guard.clear(ip)
    return {"ok": True}


# ── FastAPI dependency ────────────────────────────────────────────────────────

def _extract_token(request: Request) -> Optional[str]:
    """Try cookie first, then Authorization header."""
    token = request.cookies.get("admin_token")
    if token:
        return token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None

def require_auth(request: Request) -> dict:
    """FastAPI dependency — raises 401/redirect if not authenticated."""
    token = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

def get_current_user_optional(request: Request) -> Optional[dict]:
    """Returns payload if authenticated, None otherwise (no exception)."""
    token = _extract_token(request)
    if not token:
        return None
    return verify_token(token)


def require_auth_page(request: Request) -> dict:
    """For HTML page routes — redirects to /login instead of returning 401."""
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return payload