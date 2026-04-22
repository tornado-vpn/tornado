# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import jwt
import os
import time
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from typing import Dict, List
from pathlib import Path
from jwt import PyJWTError
from dotenv import load_dotenv

load_dotenv("/opt/tornado/.env")

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────

_KEYS_DIR   = Path(os.environ.get("JWT_KEYS_DIR", "/opt/tornado/keys/jwt"))
_OVERLAP_DIR = _KEYS_DIR / "overlap"

# ─────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────

ALGORITHM                  = "RS256"
ISSUER                     = "tornado-vpn.local"
AUDIENCE                   = "tornado-vpn-users"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS   = 7

# How many times to retry key loading if files are missing (mid-rotation window).
_KEY_LOAD_RETRIES    = 5
# Base wait in seconds — doubles each attempt: 0.5, 1, 2, 4, 8
_KEY_LOAD_RETRY_BASE = 0.5

# ─────────────────────────────────────────
#  EXCEPTIONS
# ─────────────────────────────────────────

class AuthError(Exception):
    pass

class TokenExpired(AuthError):
    pass

class InvalidToken(AuthError):
    pass

# ─────────────────────────────────────────
#  KEY LOADING
# ─────────────────────────────────────────

def _read_key(filename: str) -> str:
    """
    Read a key file, falling back to the overlap/ directory if the live file
    is temporarily missing (i.e. the rotator is mid-cutover).
    """
    live = _KEYS_DIR / filename
    if live.exists():
        return live.read_text().strip()

    # Fallback: rotator may have moved the live file but not yet written the new one
    overlap = _OVERLAP_DIR / filename
    if overlap.exists():
        logger.warning(f"key_fallback_to_overlap | {filename}")
        return overlap.read_text().strip()

    raise FileNotFoundError(
        f"Key not found in live path or overlap: {filename}"
    )


def _load_keys() -> dict:
    """Load all four key files from disk, with overlap fallback."""
    try:
        return {
            "access_private":  _read_key("access_private.pem"),
            "access_public":   _read_key("access_public.pem"),
            "refresh_private": _read_key("refresh_private.pem"),
            "refresh_public":  _read_key("refresh_public.pem"),
        }
    except FileNotFoundError as e:
        # Keep the original typo in the print so existing log monitors don't break,
        # but also emit a proper logger call.
        print(f"Critcal Error: Key file not found at {e}")
        logger.critical(f"key_file_not_found | {e}")
        raise


def _load_keys_with_retry() -> dict:
    """
    Load keys with exponential-backoff retry.

    The key rotator performs an atomic rename during cutover. There is a
    sub-millisecond window where the live file no longer exists and the new
    file has not appeared yet. Retrying a handful of times with short sleeps
    is sufficient to survive that window without crashing the service.
    """
    last_error = None
    for attempt in range(_KEY_LOAD_RETRIES):
        try:
            return _load_keys()
        except FileNotFoundError as e:
            last_error = e
            wait = _KEY_LOAD_RETRY_BASE * (2 ** attempt)
            logger.warning(
                f"keys_not_ready_retrying | attempt={attempt + 1}/{_KEY_LOAD_RETRIES} "
                f"wait={wait}s error={e}"
            )
            time.sleep(wait)

    raise RuntimeError(
        f"JWT keys unavailable after {_KEY_LOAD_RETRIES} retries: {last_error}"
    )


# ─────────────────────────────────────────
#  MODULE-LEVEL KEY STATE
#
#  Keys are NOT loaded at import time. Loading at import time causes the
#  service to crash-loop if it restarts during a rotation window (the exact
#  failure seen in the journalctl logs). Instead, keys are loaded lazily on
#  first use via _ensure_keys_loaded(), which includes retry logic.
# ─────────────────────────────────────────

ACCESS_PRIVATE_KEY:  str | None = None
ACCESS_PUBLIC_KEY:   str | None = None
REFRESH_PRIVATE_KEY: str | None = None
REFRESH_PUBLIC_KEY:  str | None = None


def _ensure_keys_loaded() -> None:
    """
    Ensure module-level key globals are populated.
    Called at the top of every public function that needs keys.
    Uses retry logic so a service restarting mid-rotation survives.
    """
    global ACCESS_PRIVATE_KEY, ACCESS_PUBLIC_KEY, REFRESH_PRIVATE_KEY, REFRESH_PUBLIC_KEY

    if all([ACCESS_PRIVATE_KEY, ACCESS_PUBLIC_KEY, REFRESH_PRIVATE_KEY, REFRESH_PUBLIC_KEY]):
        return

    keys = _load_keys_with_retry()
    ACCESS_PRIVATE_KEY  = keys["access_private"]
    ACCESS_PUBLIC_KEY   = keys["access_public"]
    REFRESH_PRIVATE_KEY = keys["refresh_private"]
    REFRESH_PUBLIC_KEY  = keys["refresh_public"]
    logger.info("jwt_keys_loaded_from_disk")


def reload_keys() -> None:
    """
    Force-reload all JWT keys from disk, bypassing the 'already loaded' check.
    Call this from a SIGHUP handler so the service picks up rotated keys.

    Example (in your FastAPI app startup):

        import signal, asyncio
        from utils.jwt_utils import reload_keys

        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGHUP, reload_keys)
    """
    global ACCESS_PRIVATE_KEY, ACCESS_PUBLIC_KEY, REFRESH_PRIVATE_KEY, REFRESH_PUBLIC_KEY

    keys = _load_keys_with_retry()
    ACCESS_PRIVATE_KEY  = keys["access_private"]
    ACCESS_PUBLIC_KEY   = keys["access_public"]
    REFRESH_PRIVATE_KEY = keys["refresh_private"]
    REFRESH_PUBLIC_KEY  = keys["refresh_public"]
    logger.info("jwt_keys_reloaded_from_disk")


# ─────────────────────────────────────────
#  MULTI-KEY PUBLIC KEY LOADER
# ─────────────────────────────────────────

def _load_all_access_public_keys() -> List[str]:
    """
    Return live access public key + overlap access public key (if present).

    During a rotation the rotator writes new public keys, sends SIGHUP, waits
    for services to reload, then rotates private keys. The overlap copy of the
    OLD public key stays on disk until after all services have reloaded. This
    function returns both so that tokens signed by either the old or new
    private key can be verified throughout the rotation window.
    """
    keys: List[str] = []

    live = _KEYS_DIR / "access_public.pem"
    if live.exists():
        keys.append(live.read_text().strip())

    overlap = _OVERLAP_DIR / "access_public.pem"
    if overlap.exists():
        overlap_key = overlap.read_text().strip()
        # Only add if it's actually a different key (avoid duplicate verify attempts)
        if not keys or overlap_key != keys[0]:
            keys.append(overlap_key)
            logger.debug("overlap_public_key_loaded | will attempt verification with both keys")

    return keys


def _load_all_refresh_public_keys() -> List[str]:
    """Same as above but for the refresh key pair."""
    keys: List[str] = []

    live = _KEYS_DIR / "refresh_public.pem"
    if live.exists():
        keys.append(live.read_text().strip())

    overlap = _OVERLAP_DIR / "refresh_public.pem"
    if overlap.exists():
        overlap_key = overlap.read_text().strip()
        if not keys or overlap_key != keys[0]:
            keys.append(overlap_key)

    return keys


# ─────────────────────────────────────────
#  TOKEN CREATION
# ─────────────────────────────────────────

def create_tokens(user_id: UUID, device_id: str) -> Dict[str, str]:
    """
    Create a signed access + refresh token pair.

    Uses RS256 with asymmetric keys, issuer/audience claims, JTI for
    revocation support, and explicit token-type claims.
    """
    _ensure_keys_loaded()

    now         = datetime.now(timezone.utc)
    access_jti  = str(uuid4())
    refresh_jti = str(uuid4())

    access_payload = {
        "iss":       ISSUER,
        "aud":       AUDIENCE,
        "sub":       str(user_id),
        "device_id": device_id,
        "iat":       now,
        "nbf":       now,
        "exp":       now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti":       access_jti,
        "type":      "access",
        "scope":     "user",
    }

    refresh_payload = {
        "iss":       ISSUER,
        "aud":       AUDIENCE,
        "sub":       str(user_id),
        "device_id": device_id,
        "iat":       now,
        "nbf":       now,
        "exp":       now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "jti":       refresh_jti,
        "type":      "refresh",
    }

    access_token = jwt.encode(access_payload,  ACCESS_PRIVATE_KEY,  algorithm=ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, REFRESH_PRIVATE_KEY, algorithm=ALGORITHM)

    return {
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "access_jti":    access_jti,
        "refresh_jti":   refresh_jti,
        "device_id":     device_id,
    }


# ─────────────────────────────────────────
#  TOKEN VERIFICATION
# ─────────────────────────────────────────

def verify_access_token(token: str) -> Dict:
    """
    Verify an access token against all available public keys (live + overlap).

    Tries the live public key first. If signature verification fails (e.g. the
    token was signed with the previous private key during a rotation window),
    retries with the overlap public key before raising InvalidToken.

    Raises:
        InvalidToken  — missing, malformed, wrong type, or unverifiable token
        TokenExpired  — token has passed its exp claim
    """
    _ensure_keys_loaded()

    if not token:
        raise InvalidToken("missing_token")

    public_keys = _load_all_access_public_keys()
    if not public_keys:
        raise RuntimeError("No access public keys available — check key directory")

    last_error: Exception | None = None

    for pubkey in public_keys:
        try:
            payload = jwt.decode(
                token,
                pubkey,
                algorithms=["RS256"],       # hard-lock; never allow 'none'
                audience=AUDIENCE,
                issuer=ISSUER,
                options={
                    "require":           ["exp", "iat", "nbf", "sub", "jti"],
                    "verify_signature":  True,
                    "verify_exp":        True,
                    "verify_nbf":        True,
                    "verify_iat":        True,
                    "verify_aud":        True,
                    "verify_iss":        True,
                },
            )

            # Token-type enforcement — must be an access token
            if payload.get("type") != "access":
                raise InvalidToken("wrong_token_type")

            # Clock-skew guard: iat must not be more than 30 s in the future
            now = datetime.now(timezone.utc).timestamp()
            if payload["iat"] > now + 30:
                raise InvalidToken("iat_in_future")

            return payload

        except jwt.ExpiredSignatureError:
            # Expiry is mathematically definitive — no point trying other keys
            raise TokenExpired("token_expired")

        except InvalidToken:
            # Our own type/clock checks — propagate immediately
            raise

        except PyJWTError as e:
            # Signature mismatch or other decode error — try next key
            last_error = e
            continue

    raise InvalidToken(f"invalid_token: {last_error}")


def verify_refresh_token(token: str) -> Dict:
    """
    Verify a refresh token against all available refresh public keys (live + overlap).

    Raises:
        InvalidToken   — missing, malformed, or wrong token type
        TokenExpired   — token has passed its exp claim
    """
    _ensure_keys_loaded()

    if not token:
        raise InvalidToken("missing_token")

    public_keys = _load_all_refresh_public_keys()
    if not public_keys:
        raise RuntimeError("No refresh public keys available — check key directory")

    last_error: Exception | None = None

    for pubkey in public_keys:
        try:
            payload = jwt.decode(
                token,
                pubkey,
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=ISSUER,
                options={
                    "require":          ["exp", "iat", "sub", "jti"],
                    "verify_signature": True,
                    "verify_exp":       True,
                    "verify_iat":       True,
                    "verify_aud":       True,
                    "verify_iss":       True,
                },
            )

            if payload.get("type") != "refresh":
                raise InvalidToken("wrong_token_type")

            return payload

        except jwt.ExpiredSignatureError:
            raise TokenExpired("refresh_token_expired")

        except InvalidToken:
            raise

        except PyJWTError as e:
            last_error = e
            continue

    raise InvalidToken(f"invalid_token: {last_error}")


# ─────────────────────────────────────────
#  REVOCATION CHECK (Redis deny-list)
# ─────────────────────────────────────────

async def verify_access_token_with_revocation(token: str, redis_conn) -> Dict:
    """
    Full access-token verification including JTI deny-list check.

    Performs cryptographic verification first (cheap, local), then checks
    Redis only if the signature is valid (avoids hammering Redis with bad tokens).

    Args:
        token:      Raw JWT string (without 'Bearer ' prefix)
        redis_conn: An async Redis client (e.g. redis.asyncio.Redis)

    Raises:
        InvalidToken  — bad token or JTI found in deny-list
        TokenExpired  — token has passed its exp claim
    """
    payload = verify_access_token(token)

    jti = payload.get("jti")
    if jti and await redis_conn.exists(f"revoked_jti:{jti}"):
        raise InvalidToken("token_revoked")

    return payload