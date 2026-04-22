# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

from fastapi import FastAPI, HTTPException, status, Header, Depends
from schemas import *
from tornadoutils.client_service_handler_utils.user_service_handler import uds_call
from tornadoutils.client_service_handler_utils.auth_service_handler import auth_uds_call
from tornadoutils.client_service_handler_utils.wg_service_handler import call_wg_manager
from tornadoutils.client_service_handler_utils.session_service_handler import call_session_service
from tornadoutils.security_utils.jwt_utils import verify_access_token, TokenExpired, InvalidToken
from tornadoutils.logging_utils.auth_logging_utils import get_context_logger, get_logger
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Tuple
from fastapi import Request
from uuid import uuid4
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import logging
from fastapi import APIRouter, Request
import signal, asyncio
from tornadoutils.security_utils.jwt_utils import reload_keys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel
import base64, json as _json



logger = get_logger()

security = HTTPBearer()

# ── Server auth-encryption keypair (separate from WireGuard keys) ───────
_AUTH_KEY_PATH = "/opt/tornado/auth_enc_key.bin"
 

def _load_or_create_auth_key() -> X25519PrivateKey:
    if os.path.exists(_AUTH_KEY_PATH):
        raw = open(_AUTH_KEY_PATH, "rb").read()
        return X25519PrivateKey.from_private_bytes(raw)
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    with open(_AUTH_KEY_PATH, "wb") as fh:
        fh.write(raw)
    os.chmod(_AUTH_KEY_PATH, 0o600)
    logger.info("auth_enc_key_generated")
    return key


_auth_priv: X25519PrivateKey = _load_or_create_auth_key()
_auth_pub_b64: str = base64.b64encode(
    _auth_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode()


# ── Decrypt helper ───────────────────────────────────────────────────────
def _decrypt_login(eph_pub_b64: str, iv_b64: str, ciphertext_b64: str) -> dict:
    """
    ECIES decrypt: ECDH → HKDF-SHA256 → AES-256-GCM
    Raises ValueError on any failure (invalid key, bad tag, bad JSON).
    """
    eph_pub   = X25519PublicKey.from_public_bytes(base64.b64decode(eph_pub_b64))
    shared    = _auth_priv.exchange(eph_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"tornado-vpn-login-v1",
    ).derive(shared)

    iv         = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    plaintext = AESGCM(aes_key).decrypt(iv, ciphertext, None)   # raises on bad tag
    return _json.loads(plaintext)





class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="/opt/tornado/.env", extra="ignore")

    vpn_endpoint_host: str = "127.0.0.1"
    vpn_endpoint_port: int = 51820
    tor_endpoint_port: int = 51821

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

async def get_vpn_user(auth: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = auth.credentials
    try:
        payload = verify_access_token(token)
        return payload["sub"]
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


async def get_vpn_identity(
    auth: HTTPAuthorizationCredentials = Depends(security),
) -> Tuple[str, str]:
    token = auth.credentials
    try:
        payload = verify_access_token(token)

        if payload.get("type") != "access":
            raise ValueError("Invalid token type")

        user_id = payload.get("sub")
        device_id = payload.get("device_id")

        if not user_id or not device_id:
            raise ValueError("Invalid token payload")

        return user_id, device_id

    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(e)}"
        )


app = FastAPI(title="Tornado VPN",docs_url=None, redoc_url=None, openapi_url=None)

#,docs_url=None, redoc_url=None, openapi_url=None

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/auth/pubkey")
async def get_auth_pubkey():
    """Returns the server's ephemeral-login X25519 public key."""
    return {"pubkey": _auth_pub_b64}




# ================================================================== #
#  Auth
# ================================================================== #

@app.post("/auth/login", response_model=AuthResponse)
async def login(req: EncryptedLoginRequest, request: Request):
    request_id = str(uuid4())
    client_ip  = request.client.host
    log = get_context_logger(request_id=request_id, client_ip=client_ip)
    log.info("login_attempt_encrypted")

    # ── 1. Decrypt ────────────────────────────────────────────────────────
    try:
        creds = _decrypt_login(req.ephemeral_pubkey, req.iv, req.ciphertext)
        username_or_email = creds["username_or_email"]
        password          = creds["password"]
    except Exception as exc:
        log.warning("login_decrypt_failed", extra={"extra_fields": {"reason": str(exc)}})
        raise HTTPException(status_code=400, detail="invalid_encrypted_payload")

    # ── 2. Forward to auth service (unchanged) ────────────────────────────
    result = await auth_uds_call(
        action="login",
        payload={
            "username_or_email": username_or_email,
            "password":          password,
            "client_ip":         client_ip,
            "request_id":        request_id,
        },
    )

    if "error" in result:
        log.warning("login_failed", extra={"extra_fields": {"reason": result["error"]}})
        if result["error"] in ["invalid_credentials", "user_inactive", "max_devices_exceeded"]:
            raise HTTPException(status_code=401, detail=result["error"])
        raise HTTPException(status_code=500, detail=result["error"])

    log.info("login_success", extra={"extra_fields": {"user_id": result["user"]["id"]}})
    return {
        "status":    "ok",
        "user":      result["user"],
        "tokens":    result["tokens"],
        "device_id": result["device_id"],
    }


@app.post("/auth/logout", response_model=LogoutResponse)
async def logout_endpoint(req: LogoutRequest, request: Request):
    request_id = str(uuid4())
    client_ip = request.client.host
    log = get_context_logger(request_id=request_id, client_ip=client_ip)
    log.info("logout_attempt")

    result = await auth_uds_call(
        action="logout",
        payload={"refresh_token": req.refresh_token}
    )

    if "error" in result:
        log.warning("logout_failed", extra={"extra_fields": {"reason": result["error"]}})
        if result["error"] in ["invalid_refresh_token", "refresh_token_expired", "missing_refresh_token"]:
            raise HTTPException(status_code=401, detail=result["error"])
        raise HTTPException(status_code=500, detail=result["error"])

    log.info("logout_success")
    return {"status": result.get("status", "logged_out")}


@app.post("/auth/reauth", response_model=ReauthResponse)
async def reauth(req: ReauthRequest, request: Request):
    request_id = str(uuid4())
    client_ip = request.client.host
    log = get_context_logger(request_id=request_id, client_ip=client_ip)
    log.info("reauth_attempt")

    result = await auth_uds_call(
        action="reauth",
        payload={"refresh_token": req.refresh_token}
    )

    if "error" in result:
        error_msg = result["error"]
        log.warning("reauth_failed", extra={"extra_fields": {"reason": error_msg}})
        if error_msg in ["refresh_token_expired", "invalid_refresh_token", "user_inactive", "token_revoked_reuse_detected"]:
            raise HTTPException(status_code=401, detail=error_msg)
        raise HTTPException(status_code=500, detail=error_msg)

    log.info("reauth_success")
    return {"status": "ok", "tokens": result["tokens"]}






@app.post("/vpn/initiate")
async def request_vpn_connection(
    req: VPNConnectRequest,
    request: Request,
    identity=Depends(get_vpn_identity),
    cfg: Settings = Depends(get_settings),
):
    user_id, device_id = identity
    client_ip = request.client.host
    request_id = str(uuid4())
    
    log = get_context_logger(request_id=request_id, client_ip=client_ip)
    log.info("vpn_initiate_attempt", extra={"extra_fields": {"user_id": user_id, "device_id": device_id}})

    # Call wg_manager over the Unix socket
    res = await call_wg_manager("add_peer", {
        "request_id": request_id,
        "client_ip": client_ip,
        "user_id": user_id,
        "device_id": device_id,
        "public_key": req.public_key,
    })

    if res.get("status") == "ok":
        log.info("vpn_initiate_success", extra={"extra_fields": {
            "user_id": user_id,
            "vpn_ip": res["vpn_ip"],
            "tor_ip": res["tor_ip"],
        }})
        
        # Extract the live public keys returned by wg_manager
        pubkeys = res.get("server_pubkeys", {})
 
        # Return a structured payload separating the two interfaces
        return {
        "status": "success",
        "vpn": {
            "ip": res["vpn_ip"],
            "endpoint": f"{cfg.vpn_endpoint_host}:{cfg.vpn_endpoint_port}",
            "server_pubkey": pubkeys.get("vpn", "")
        },
        "tor": {
            "ip": res["tor_ip"],
            "endpoint": f"{cfg.vpn_endpoint_host}:{cfg.tor_endpoint_port}",
            "server_pubkey": pubkeys.get("tor", "")
        },
        "session": {
                "heartbeat_ttl": res.get("heartbeat_ttl", 90),
                "hard_ttl": res.get("hard_ttl", 300)
            }
    }

    log.error("vpn_initiate_failed", extra={"extra_fields": {"user_id": user_id, "error": res.get("error")}})
    raise HTTPException(status_code=502, detail=f"VPN Manager Error: {res.get('error')}")



# ================================================================== #
#  Session
# ================================================================== #

@app.post("/session/heartbeat")
async def session_heartbeat(identity=Depends(get_vpn_identity)):
    user_id, device_id = identity
    session_id = f"{user_id}-{device_id}"
    log = get_context_logger()
    log.info("session_heartbeat", extra={"extra_fields": {"user_id": user_id, "device_id": device_id}})

    try:
        result = await call_session_service(
            action="heartbeat",
            payload={"session_id": session_id}
        )

        if "error" in result:
            log.warning("session_heartbeat_failed", extra={"extra_fields": {"session_id": session_id, "reason": result["error"]}})
            raise HTTPException(status_code=400, detail=result["error"])

        return {"status": result.get("status")}

    except HTTPException:
        raise
    except Exception as e:
        log.error("session_service_unreachable", extra={"extra_fields": {"session_id": session_id, "error": str(e)}})
        raise HTTPException(status_code=500, detail="session_service_unreachable")


# ================================================================== #
#  Debug / Verify
# ================================================================== #

@app.post("/vpn/verify/id")
async def verify_vpn_id(user_id: str = Depends(get_vpn_user)):
    return user_id




@app.on_event("startup")
async def setup_sighup():
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGHUP, reload_keys)