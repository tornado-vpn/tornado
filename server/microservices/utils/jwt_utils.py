import jwt
import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from typing import Dict
from pathlib import Path
from jwt import PyJWTError
from dotenv import load_dotenv
load_dotenv("/opt/tornado/.env")

_KEYS_DIR = Path(os.environ.get("JWT_KEYS_DIR", "/opt/tornado/keys/jwt"))

def _load_keys() -> dict:
    try:
        return {
            "access_private":  (_KEYS_DIR / "access_private.pem").read_text().strip(),
            "access_public":   (_KEYS_DIR / "access_public.pem").read_text().strip(),
            "refresh_private": (_KEYS_DIR / "refresh_private.pem").read_text().strip(),
            "refresh_public":  (_KEYS_DIR / "refresh_public.pem").read_text().strip(),
        }
    except FileNotFoundError as e:
        # This helps you debug exactly which path is failing
        print(f"Critcal Error: Key file not found at {e.filename}")
        raise


# Initial load — fail loudly if keys don't exist yet
_k = _load_keys()
ACCESS_PRIVATE_KEY  = _k["access_private"]
ACCESS_PUBLIC_KEY   = _k["access_public"]
REFRESH_PRIVATE_KEY = _k["refresh_private"]
REFRESH_PUBLIC_KEY  = _k["refresh_public"]

ALGORITHM = "RS256"
ISSUER = "tornado-vpn.local"
AUDIENCE = "tornado-vpn-users"



ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
ALGORITHM = "RS256"

#ISSUER = os.getenv("JWT_ISSUER")
#AUDIENCE = os.getenv("JWT_AUDIENCE")

#ACCESS_PRIVATE_KEY = os.getenv("JWT_ACCESS_PRIVATE_KEY")
#REFRESH_PRIVATE_KEY = os.getenv("JWT_REFRESH_PRIVATE_KEY")

def _ensure_keys_loaded() -> None:
    global ACCESS_PRIVATE_KEY, ACCESS_PUBLIC_KEY, REFRESH_PRIVATE_KEY, REFRESH_PUBLIC_KEY
    if not all([ACCESS_PRIVATE_KEY, ACCESS_PUBLIC_KEY, REFRESH_PRIVATE_KEY, REFRESH_PUBLIC_KEY]):
        keys = _load_keys()
        ACCESS_PRIVATE_KEY  = keys["access_private"]
        ACCESS_PUBLIC_KEY   = keys["access_public"]
        REFRESH_PRIVATE_KEY = keys["refresh_private"]
        REFRESH_PUBLIC_KEY  = keys["refresh_public"]


def create_tokens(user_id: UUID, device_id: str) -> Dict[str, str]:
    """
    Enterprise-grade JWT creation with:
    - Asymmetric keys (RS256)
    - Issuer / Audience
    - JTI for revocation
    - Token typing
    """
    _ensure_keys_loaded() 
    now = datetime.now(timezone.utc)

    access_jti = str(uuid4())
    refresh_jti = str(uuid4())

    access_payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": str(user_id),
        "device_id": device_id,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": access_jti,
        "type": "access",
        "scope": "user"
    }

    refresh_payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": str(user_id),
        "device_id": device_id,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "jti": refresh_jti,
        "type": "refresh"
    }

    access_token = jwt.encode(
        access_payload,
        ACCESS_PRIVATE_KEY,
        algorithm=ALGORITHM,
    )

    #print("KEY TYPE:", type(ACCESS_PRIVATE_KEY))
    #print("KEY VALUE:", ACCESS_PRIVATE_KEY[:100])


    refresh_token = jwt.encode(
        refresh_payload,
        REFRESH_PRIVATE_KEY,
        algorithm=ALGORITHM,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_jti": access_jti,
        "refresh_jti": refresh_jti,
        "device_id": device_id
    }





class AuthError(Exception):
    pass


class TokenExpired(AuthError):
    pass


class InvalidToken(AuthError):
    pass


def verify_access_token(token: str) -> Dict:
     
    """
    Enterprise-grade JWT access token verification.
    """
    _ensure_keys_loaded() 

    if not token:
        raise InvalidToken("missing_token")

    if not ACCESS_PUBLIC_KEY:
        raise RuntimeError("ACCESS_PUBLIC_KEY not configured")

    try:
        payload = jwt.decode(
            token,
            ACCESS_PUBLIC_KEY,
            algorithms=["RS256"],      # 🔒 hard lock
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "require": ["exp", "iat", "nbf", "sub", "jti"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )

        # 🔐 Token type enforcement
        if payload.get("type") != "access":
            raise InvalidToken("wrong_token_type")


        # ⏱ Optional: clock-skew guard (defense-in-depth)
        now = datetime.now(timezone.utc).timestamp()
        if payload["iat"] > now + 30:
            raise InvalidToken("iat_in_future")

        return payload

    except jwt.ExpiredSignatureError:
        raise TokenExpired("token_expired")

    except PyJWTError as e:
        raise InvalidToken(f"invalid_token: {str(e)}")






def verify_refresh_token(token: str) -> Dict:
    _ensure_keys_loaded() 
    
    if not token:
        raise InvalidToken("missing_token")

    try:
        payload = jwt.decode(
            token,
            REFRESH_PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "require": ["exp", "iat", "sub", "jti"],
                "verify_signature": True,
            },
        )

        if payload.get("type") != "refresh":
            raise InvalidToken("wrong_token_type")

        return payload

    except jwt.ExpiredSignatureError:
        raise TokenExpired("refresh_token_expired")
    except PyJWTError as e:
        raise InvalidToken(f"invalid_token: {str(e)}")



async def verify_access_token_with_revocation(token: str, redis_conn) -> Dict:
    # 1. Standard mathematical verification
    payload = verify_access_token(token) # Your existing function
    
    jti = payload.get("jti")
    
    # 2. Check Redis Deny-List
    if await redis_conn.exists(f"revoked_jti:{jti}"):
        raise InvalidToken("token_revoked")
        
    return payload


