# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

"""
main.py — VPN Admin Control Plane
──────────────────────────────────
Auth:        Cookie-based JWT (credentials from .env, no DB)
Structure:   Routers grouped by domain
Startup:     Redis state builder + background tasks via lifespan

Navigation flow:
  /           → redirects to /main (auth) or /login (no auth)
  /login      → login page; on success redirects to /main
  /main       → index.html shell (sidebar + iframes) ← THE landing page
  /dashboard-page, /sessions-page, … → loaded inside iframes within /main
"""

# ══════════════════════════════════════════════════════════════════════════════
# STDLIB & THIRD-PARTY IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import (
    Annotated, Any, AsyncIterator, Dict, List,
    Literal, Optional, Union,
)
import threading
from functools import lru_cache, partial
import structlog
import redis.asyncio as redis
from dotenv import load_dotenv
from fastapi import (
    Depends, FastAPI, Header, HTTPException,
    Path as FPath, Query, Request, status as http_status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sse_starlette.sse import EventSourceResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from fastapi import Path as fast_Path
from uuid import UUID, uuid4
import signal




load_dotenv()

# ══════════════════════════════════════════════════════════════════════════════
# LOCAL IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

from tornadoutils.security_utils.admin_auth import (
    create_token,
    verify_credentials,
    require_auth,
    get_current_user_optional,
    require_auth_page,
    invalidate_auth_config
)
from tornadoutils.metrics_service import get_live, get_last_1h, get_last_24h, run_aggregator
from schemas import *
from tornadoutils.admin_service_handler_utils.master_service_handler import master_uds_call
from tornadoutils.admin_service_handler_utils.user_service_handler import uds_call
from tornadoutils.admin_service_handler_utils.tor_service_handler import call_tor_service
from tornadoutils.admin_service_handler_utils.key_rotator_service_handler import uds_call_keyrotator
import tornadoutils.admin_service_handler_utils.log_service_handler as lsh
from tornadoutils.admin_service_handler_utils.log_service_handler import (
    LogServiceError,
    LogServiceNotFound,
    LogServiceValidationError,
)
import tornadoutils.admin_service_handler_utils.os_service_handler as sh
import tornadoutils.admin_service_handler_utils.api_service_handler as api_sh




# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Log service
    log_socket:           str   = "/run/tornado/log.sock"
    log_uds_timeout:      float = 10.0
    log_max_limit:        int   = 1000

    # Rate limiting
    rate_limit:           str   = "200/minute"
    analytics_rate_limit: str   = "30/minute"

    # App metadata
    app_env:              str   = "development"
    app_version:          str   = "1.0.0"
    log_level:            str   = "INFO"
    cors_origins:         str   = "*"
    enable_metrics:       bool  = True
    log_export_dir:       str   = "/var/log/tornado/exp/"

    # Admin auth (no DB — stored in .env)
    admin_username:       str   = "admin"
    admin_password:       str   = "changeme"
    admin_secret:         str   = "supersecretkey-change-in-production"
    admin_token_ttl:      int   = 28800       # 8 hours

    # Legacy admin token (for API Bearer auth)
    admin_token:          str   = ""

    @property
    def cors_list(self) -> list[str]:
        return ["*"] if self.cors_origins.strip() == "*" \
            else [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def _sync_handler_config(cfg: Settings) -> None:
    lsh.SOCKET_PATH = cfg.log_socket
    lsh.UDS_TIMEOUT = cfg.log_uds_timeout


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════

def _setup_logging(level: str) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.ExceptionRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
    )

log = structlog.get_logger("vpn-api")


# ══════════════════════════════════════════════════════════════════════════════
# REDIS
# ══════════════════════════════════════════════════════════════════════════════

REDIS_URL           = "redis://localhost:6379/0"
LIVE_EVENTS_CHANNEL = "vpn:live_events"

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND AGGREGATOR
# ══════════════════════════════════════════════════════════════════════════════

agg_thread = threading.Thread(target=run_aggregator, daemon=True)
agg_thread.start()


# ══════════════════════════════════════════════════════════════════════════════
# LIVE SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════

STATE: dict = {
    "total": 0,
    "online": 0,
    "offline": 0,
    "active_users": set(),
    "active_devices": set(),
    "recoveries": 0,
}
SESSION_STATES: dict = {}  # session_id → "online" | "offline" | "closed"

ws_clients:       set[WebSocket] = set()
connected_admins: set[WebSocket] = set()


# ══════════════════════════════════════════════════════════════════════════════
# STATE BUILDER (called once at startup)
# ══════════════════════════════════════════════════════════════════════════════

async def build_initial_state() -> None:
    total = online = offline = 0
    users: set = set()
    devices: set = set()

    async for key in redis_client.scan_iter("vpn:session:*"):
        if key.endswith(":hb") or key.endswith(":finalized"):
            continue
        data = await redis_client.hgetall(key)
        if not data:
            continue

        session_id = key.replace("vpn:session:", "")
        total += 1

        if data.get("state") == "online":
            online += 1
            SESSION_STATES[session_id] = "online"
            uid, did = data.get("user_id"), data.get("device_id")
            if uid:
                users.add(uid)
            if uid and did:
                devices.add((uid, did))
        else:
            offline += 1
            SESSION_STATES[session_id] = "offline"

    STATE.update({
        "total": total, "online": online, "offline": offline,
        "active_users": users, "active_devices": devices, "recoveries": 0,
    })


# ══════════════════════════════════════════════════════════════════════════════
# REDIS EVENT → WEBSOCKET BRIDGE
# ══════════════════════════════════════════════════════════════════════════════

async def redis_event_listener() -> None:
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(LIVE_EVENTS_CHANNEL)

    async for msg in pubsub.listen():
        if msg["type"] != "message":
            continue
        try:
            event  = json.loads(msg["data"])
            action = event.get("action")
            uid    = event.get("user_id")
            did    = event.get("device_id")

            if action == "session_created":
                sid = event.get("session_id")
                if sid not in SESSION_STATES:
                    STATE["total"] += 1
                    STATE["online"] += 1
                    SESSION_STATES[sid] = "online"
                    if uid: STATE["active_users"].add(uid)
                    if uid and did: STATE["active_devices"].add((uid, did))

            elif action == "session_offline":
                sid = event.get("session_id")
                if SESSION_STATES.get(sid) == "online":
                    STATE["online"] -= 1
                    STATE["offline"] += 1
                    SESSION_STATES[sid] = "offline"
                    if uid and did: STATE["active_devices"].discard((uid, did))
                    if uid and not any(u == uid for (u, _) in STATE["active_devices"]):
                        STATE["active_users"].discard(uid)

            elif action == "session_closed":
                sid = event.get("session_id")
                cur = SESSION_STATES.get(sid)
                if cur in ("online", "offline"):
                    STATE["total"] -= 1
                    STATE["online" if cur == "online" else "offline"] -= 1
                    SESSION_STATES.pop(sid, None)
                    if uid and did: STATE["active_devices"].discard((uid, did))
                    if uid and not any(u == uid for (u, _) in STATE["active_devices"]):
                        STATE["active_users"].discard(uid)

            elif action == "heartbeat_update" and event.get("recovered"):
                sid = event.get("session_id")
                if SESSION_STATES.get(sid) == "offline":
                    STATE["recoveries"] += 1
                    STATE["offline"] -= 1
                    STATE["online"] += 1
                    SESSION_STATES[sid] = "online"
                    if uid: STATE["active_users"].add(uid)
                    if uid and did: STATE["active_devices"].add((uid, did))

            payload = {
                "type": "stats_update",
                "stats": {
                    "total":             STATE["total"],
                    "online":            STATE["online"],
                    "offline":           STATE["offline"],
                    "active_users":      len(STATE["active_users"]),
                    "active_devices":    len(STATE["active_devices"]),
                    "session_recoveries": STATE["recoveries"],
                },
                "event": event,
            }
            for ws in list(ws_clients):
                try:
                    await ws.send_json(payload)
                except Exception:
                    ws_clients.discard(ws)
        except Exception:
            continue


async def redis_to_ws_broadcaster() -> None:
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("vpn:live_events")
    log.info("redis_broadcaster_started")

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = json.loads(message["data"])
            if "action" not in data:
                data["action"] = "heartbeat_update"
            if connected_admins:
                await asyncio.gather(
                    *[_send_to_admin(ws, data) for ws in list(connected_admins)]
                )
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.error("redis_broadcaster_error", error=str(e))
    finally:
        await pubsub.unsubscribe("vpn:live_events")
        await pubsub.close()


async def _send_to_admin(ws: WebSocket, data: dict) -> None:
    try:
        await ws.send_json(data)
    except Exception:
        connected_admins.discard(ws)


async def admin_command_listener() -> None:
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("vpn:admin_commands")
    log.info("admin_command_listener_started")

    async for msg in pubsub.listen():
        if msg["type"] != "message":
            continue
        try:
            data = json.loads(msg["data"])
            if data.get("action") == "kill_session":
                sid = data.get("session_id")
                await redis_client.delete(f"vpn:session:{sid}")
                await redis_client.delete(f"meta:{sid}")
                await _publish_session_event("session_closed", {
                    "session_id": sid, "timestamp": int(time.time()),
                })
        except Exception as e:
            log.error("admin_command_error", error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# LIFESPAN
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = get_settings()
    _setup_logging(cfg.log_level)
    _sync_handler_config(cfg)

    # ── SIGHUP: reload auth config when key_rotator rotates ADMIN_SECRET ──
    loop = asyncio.get_running_loop()

    def _handle_sighup():
        invalidate_auth_config()
        log.info("admin_secret_reloaded_via_sighup")

    loop.add_signal_handler(signal.SIGHUP, _handle_sighup)
    # ──────────────────────────────────────────────────────────────────────

    # ── PID file (so key_rotator can send SIGHUP to this process) ─────────
    pid_path = Path("/run/tornado/admin_panel.pid")
    try:
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(os.getpid()))
        log.info("pid_file_written", path=str(pid_path))
    except Exception as e:
        log.warning("pid_file_write_failed", error=str(e))
    # ──────────────────────────────────────────────────────────────────────

    try:
        await lsh.ping()
        log.info("log_service_connected", socket=cfg.log_socket)
    except LogServiceError as e:
        log.warning("log_service_unavailable", error=str(e))

    await build_initial_state()
    log.info("initial_state_built",
             total=STATE["total"], online=STATE["online"], offline=STATE["offline"])

    tasks = [
        asyncio.create_task(redis_event_listener(),    name="redis_event_listener"),
        asyncio.create_task(redis_to_ws_broadcaster(), name="redis_broadcaster"),
        asyncio.create_task(admin_command_listener(),  name="admin_cmd_listener"),
    ]
    log.info("background_tasks_started", count=len(tasks))

    yield

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await redis_client.aclose()

    # ── Cleanup PID file on shutdown ───────────────────────────────────────
    try:
        pid_path.unlink(missing_ok=True)
        log.info("pid_file_removed")
    except Exception as e:
        log.warning("pid_file_remove_failed", error=str(e))
    # ──────────────────────────────────────────────────────────────────────

    log.info("shutdown_complete")


# ══════════════════════════════════════════════════════════════════════════════
# APP FACTORY
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="VPN Admin Control Plane",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)

cfg_    = get_settings()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[cfg_.rate_limit],
    storage_uri="memory://",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

if cfg_.enable_metrics:
    try:
        from prometheus_fastapi_instrumentator import Instrumentator
        Instrumentator(excluded_handlers=["/health", "/ready", "/metrics"]) \
            .instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
    except ImportError:
        pass


# ── Middleware ────────────────────────────────────────────────────────────────

class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

class AccessLogMiddleware(BaseHTTPMiddleware):
    _SKIP = {"/health", "/ready", "/metrics", "/static"}
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self._SKIP or request.url.path.startswith("/static"):
            return await call_next(request)
        t0 = time.perf_counter()
        response = await call_next(request)
        log.info("http_request",
                 method=request.method,
                 path=request.url.path,
                 status=response.status_code,
                 ms=round((time.perf_counter() - t0) * 1000, 2),
                 rid=getattr(request.state, "request_id", None))
        return response

app.add_middleware(CorrelationMiddleware)
app.add_middleware(AccessLogMiddleware)


# ── Exception handlers ────────────────────────────────────────────────────────

def _rid(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)

def ok(data: Any, request_id: str | None = None) -> dict:
    return {"status": "ok", "request_id": request_id, "data": data}

def err(code: str, detail: str, request_id: str | None = None) -> dict:
    return {"status": "error", "request_id": request_id, "code": code, "detail": detail}

@app.exception_handler(RequestValidationError)
async def _validation_err(request: Request, exc: RequestValidationError):
    return JSONResponse(
        content=err("validation_error", str(exc.errors()), _rid(request)),
        status_code=422,
    )

@app.exception_handler(LogServiceNotFound)
async def _not_found_err(request: Request, exc: LogServiceNotFound):
    return JSONResponse(content=err("not_found", str(exc), _rid(request)), status_code=404)

@app.exception_handler(LogServiceValidationError)
async def _svc_validation_err(request: Request, exc: LogServiceValidationError):
    return JSONResponse(content=err("validation_error", str(exc), _rid(request)), status_code=422)

@app.exception_handler(LogServiceError)
async def _svc_err(request: Request, exc: LogServiceError):
    return JSONResponse(content=err("log_service_error", str(exc), _rid(request)), status_code=502)

@app.exception_handler(Exception)
async def _generic_err(request: Request, exc: Exception):
    log.exception("unhandled_error", path=request.url.path)
    return JSONResponse(
        content=err("internal_error", "An unexpected error occurred", _rid(request)),
        status_code=500,
    )


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _serve_html(filename: str, title: str = "") -> HTMLResponse:
    path = Path(__file__).parent / filename
    if not path.exists():
        return _error_html(f"{filename} not found")
    content = path.read_text()
    if title:
        content = content.replace('id="pageTitle">Page Title', f'id="pageTitle">{title}')
    return HTMLResponse(content)

def _error_html(message: str) -> HTMLResponse:
    return HTMLResponse(f"""<!DOCTYPE html><html><head><title>Error</title>
<style>body{{background:#0a0c10;color:#cdd6e0;font-family:monospace;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{text-align:center;border:1px solid #1e2530;padding:40px;border-radius:12px}}
h2{{color:#ff4757}}</style></head><body>
<div class="box"><h2>⚠ Error</h2><p>{message}</p></div></body></html>""", status_code=404)

async def _fetch_all_sessions() -> list:
    sessions = []
    async for key in redis_client.scan_iter("vpn:session:*"):
        if key.endswith(":hb"):
            continue
        data = await redis_client.hgetall(key)
        if data:
            data.setdefault("session_id", key.split(":")[-1])
            data.setdefault("state", "online")
            data.setdefault("timestamp", int(time.time()))
            sessions.append(data)
    return sessions

async def _publish_session_event(action: str, session_data: dict) -> None:
    event = {"action": action, **session_data}
    await redis_client.publish("vpn:live_events", json.dumps(event))

def _stats_snapshot() -> dict:
    return {
        "total":              STATE["total"],
        "online":             STATE["online"],
        "offline":            STATE["offline"],
        "active_users":       len(STATE["active_users"]),
        "active_devices":     len(STATE["active_devices"]),
        "session_recoveries": STATE["recoveries"],
    }

def _raise_if_error(result: dict) -> dict:
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    return result

_FATAL_ERRORS = {"invalid_action", "read timeout", "invalid JSON"}

def _raise_if_fatal(result: dict) -> dict:
    err_val = result.get("error")
    if err_val and err_val in _FATAL_ERRORS:
        raise HTTPException(status_code=500, detail=err_val)
    return result

def call_tor_service_sync(action: str, payload: dict = None) -> dict:
    import asyncio as _asyncio
    loop = _asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_tor_service(action, payload or {}))
    finally:
        loop.close()

async def require_admin_token(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    cfg: Annotated[Settings, Depends(get_settings)] = None,
) -> None:
    if not cfg.admin_token:
        return
    token = (authorization or "").removeprefix("Bearer ").strip()
    if token != cfg.admin_token:
        raise HTTPException(status_code=403, detail="Invalid or missing admin token")


# ══════════════════════════════════════════════════════════════════════════════
# ██████████████████████████████████████████████████████████████████████████
#  ROUTES
# ██████████████████████████████████████████████████████████████████████████
# ══════════════════════════════════════════════════════════════════════════════


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  AUTH                                                                   │
# └─────────────────────────────────────────────────────────────────────────┘

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/login", response_class=HTMLResponse, tags=["Auth"])
async def login_page(request: Request):
    """Show login page. If already authenticated, skip straight to /main."""
    user = get_current_user_optional(request)
    if user:
        return RedirectResponse(url="/main", status_code=302)
    path = Path(__file__).parent / "static/html/login.html"
    return HTMLResponse(path.read_text() if path.exists() else "<h1>Login page missing</h1>")

@app.post("/auth/login", tags=["Auth"])
async def login(body: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    result = verify_credentials(body.username, body.password, ip=client_ip)

    if not result["ok"]:
        if result["reason"] == "ip_banned":
            raise HTTPException(
                status_code=http_status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Try again in {result['retry_after']}s",
                headers={"Retry-After": str(result["retry_after"])}
            )
        # invalid_credentials
        attempts_left = result.get("attempts_left", "")
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid username or password. {attempts_left} attempts remaining before ban",
        )

    token = create_token(body.username)
    response = JSONResponse({"status": "ok", "redirect": "/main"})
    response.set_cookie(
        key="admin_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("HTTPS", "false").lower() == "true",
        max_age=int(os.getenv("ADMIN_TOKEN_TTL", "28800")),
    )
    log.info("admin_login", username=body.username, ip=client_ip)
    return response

@app.post("/auth/logout", tags=["Auth"])
async def logout():
    """Clear auth cookie and send back to login."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("admin_token")
    return response

@app.get("/auth/me", tags=["Auth"])
async def me(user: Annotated[dict, Depends(require_auth)]):
    """Return current authenticated user info (used by index.html user pill)."""
    return {"username": user.get("sub"), "exp": user.get("exp")}


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  ROOT / PAGE ROUTES  (all protected)                                    │
# └─────────────────────────────────────────────────────────────────────────┘

@app.get("/", response_class=HTMLResponse, tags=["Pages"])
async def root(request: Request):
    """
    Root redirect:
      • authenticated   → /main   (index shell with sidebar)
      • unauthenticated → /login
    """
    user = get_current_user_optional(request)
    return RedirectResponse(url="/main" if user else "/login", status_code=302)

@app.get("/main", response_class=HTMLResponse, tags=["Pages"])
async def main_shell(request: Request, _: dict = Depends(require_auth_page)):
    """
    The primary landing page after login.
    Serves index.html — the full shell with navbar, sidebar, and iframe content area.
    All sub-pages are loaded lazily inside iframes from here.
    """
    return _serve_html("static/html/index.html")

# ── iframe sub-pages — also protected so direct URL access still requires auth ─

@app.get("/dashboard-page", response_class=HTMLResponse, tags=["Pages"])
async def dashboard_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/dashboard.html")

@app.get("/analytics-page", response_class=HTMLResponse, tags=["Pages"])
async def analytics_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/microservices.html", "Analytics Dashboard")

@app.get("/sys-services-page", response_class=HTMLResponse, tags=["Pages"])
async def sys_services_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/os_services.html", "System Services")

@app.get("/sessions-page", response_class=HTMLResponse, tags=["Pages"])
async def sessions_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/sessions.html", "VPN Sessions Management")

@app.get("/users-page", response_class=HTMLResponse, tags=["Pages"])
async def users_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/user_manage.html", "User Management")

@app.get("/tor-manage", response_class=HTMLResponse, tags=["Pages"])
async def tor_manage_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/tor_manage.html", "Tor Relay Management")

@app.get("/logs-page", response_class=HTMLResponse, tags=["Pages"])
async def logs_page(request: Request, _: dict = Depends(require_auth_page)):
    return _serve_html("static/html/logservice.html", "System Logs")


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  HEALTH                                                                 │
# └─────────────────────────────────────────────────────────────────────────┘

@app.get("/health", tags=["Health"])
async def health(request: Request, cfg: Annotated[Settings, Depends(get_settings)]):
    svc = "ok"
    try:
        await lsh.ping(socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    except LogServiceError:
        svc = "unavailable"
    return ok({"healthy": True, "log_service": svc,
                "version": cfg.app_version, "env": cfg.app_env}, _rid(request))

@app.get("/ready", tags=["Health"])
async def ready(request: Request, cfg: Annotated[Settings, Depends(get_settings)]):
    svc = "ok"
    try:
        await lsh.ping(socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    except LogServiceError:
        svc = "unavailable"
    body = ok({"healthy": svc == "ok", "log_service": svc,
                "version": cfg.app_version, "env": cfg.app_env}, _rid(request))
    return JSONResponse(body, status_code=200 if svc == "ok" else 503)

@app.get("/status/log", tags=["Health"])
async def log_service_status(request: Request, cfg: Annotated[Settings, Depends(get_settings)]):
    result = await lsh.status(socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    return ok(result.raw, _rid(request))

@app.get("/metrics-summary", tags=["Health"])
async def metrics_summary(request: Request, cfg: Annotated[Settings, Depends(get_settings)]):
    result = await lsh.metrics(socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    return ok(result.raw, _rid(request))


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  DASHBOARD WEBSOCKET + METRICS                                          │
# └─────────────────────────────────────────────────────────────────────────┘

@app.websocket("/ws/dashboard")
async def dashboard_ws(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    await ws.send_json({"type": "init", "stats": _stats_snapshot()})
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_clients.discard(ws)

@app.get("/api/metrics/live", tags=["Metrics"])
async def live_metrics(_: dict = Depends(require_auth)):
    return get_live()

@app.websocket("/ws/metrics/live")
async def ws_live_metrics(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({"type": "live_metrics", "data": get_live()})
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass

@app.get("/api/metrics/last_1h", tags=["Metrics"])
async def last_1h_metrics(_: dict = Depends(require_auth)):
    return get_last_1h()

@app.get("/api/metrics/last_24h", tags=["Metrics"])
async def last_24h_metrics(_: dict = Depends(require_auth)):
    return get_last_24h()


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  MICROSERVICES CONTROL                                                  │
# └─────────────────────────────────────────────────────────────────────────┘

@app.post("/api/system/control", tags=["System"])
async def control_service(req: ServiceControl, _: dict = Depends(require_auth)):
    response = await master_uds_call(req.action, req.service_name)
    if response.get("status") == "error":
        raise HTTPException(status_code=500, detail=response.get("message"))
    return response

@app.get("/api/system/status", tags=["System"])
async def get_system_status(_: dict = Depends(require_auth)):
    response = await master_uds_call(command="status", target="all")
    if response.get("status") == "error":
        raise HTTPException(status_code=500, detail=response.get("message"))
    return response


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  SESSION MANAGEMENT                                                     │
# └─────────────────────────────────────────────────────────────────────────┘

@app.websocket("/ws/admin")
async def admin_ws(ws: WebSocket):
    await ws.accept()
    connected_admins.add(ws)
    try:
        await ws.send_json({"type": "snapshot", "sessions": await _fetch_all_sessions()})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        connected_admins.discard(ws)

@app.get("/api/admin/sessions", tags=["Sessions"])
async def get_active_sessions(_: dict = Depends(require_auth)):
    return {"type": "snapshot", "sessions": await _fetch_all_sessions()}

@app.post("/api/admin/kill_session/{session_id}", tags=["Sessions"])
async def admin_kill_session(session_id: str, _: dict = Depends(require_auth)):
    if not await redis_client.exists(f"vpn:session:{session_id}") \
       and not await redis_client.exists(f"meta:{session_id}"):
        raise HTTPException(status_code=404, detail="Session not found")
    await redis_client.publish("vpn:admin_commands", json.dumps({
        "action": "kill_session", "session_id": session_id, "timestamp": int(time.time()),
    }))
    await redis_client.publish("vpn:live_events", json.dumps({
        "action": "session_closed", "session_id": session_id, "timestamp": int(time.time()),
    }))
    return {"status": "requested", "session_id": session_id}

@app.post("/users/sessions/{session_id}/kill", tags=["Sessions"])
async def kill_user_session(session_id: str, _: dict = Depends(require_auth)):
    meta_raw = await redis_client.get(f"meta:{session_id}")
    if not meta_raw:
        raise HTTPException(status_code=404, detail="Session not found")
    meta = json.loads(meta_raw)
    await redis_client.expire(f"vpn:session:{session_id}", 1)
    await redis_client.delete(f"vpn:session:{session_id}:hb")
    await redis_client.publish("vpn:live_events", json.dumps({
        "action": "admin_session_killed",
        "session_id": session_id,
        "user_id": meta.get("user_id"),
        "device_id": meta.get("device_id"),
    }))
    return {"status": "killed", "session_id": session_id}


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  USER MANAGEMENT                                                        │
# └─────────────────────────────────────────────────────────────────────────┘

@app.post("/users", response_model=UserResponse, status_code=201, tags=["Users"])
async def create_user(user_in: UserCreate, _: dict = Depends(require_auth)):
    result = await uds_call(action="create_user", payload=user_in.model_dump())
    if "error" in result:
        if result["error"] == "user_exists": raise HTTPException(400, "User already exists")
        raise HTTPException(500, "User service error")
    return result["user"]

@app.get("/users", response_model=UsersListResponse, tags=["Users"])
async def get_all_users(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    include_deleted: bool = Query(False),
    _: dict = Depends(require_auth),
):
    result = await uds_call(action="list_users", payload={
        "limit": limit, "offset": offset,
        "is_active": is_active, "search": search,
        "include_deleted": include_deleted,
    })
    if "error" in result:
        raise HTTPException(500, "Internal User Service Error")
    return result

@app.put("/users/{user_id}", response_model=UserResponse, tags=["Users"])
async def update_user(user_id: UUID, user_in: UserUpdate, _: dict = Depends(require_auth)):
    result = await uds_call(action="update_user", payload={
        "user_id": str(user_id),
        "updates": user_in.model_dump(exclude_none=True),
    })
    ERROR_MAP = {
        "user_not_found": (404, "User not found"),
        "user_conflict":  (409, "Username or email already in use"),
        "no_updates":     (400, "No fields to update"),
    }
    if "error" in result:
        code, msg = ERROR_MAP.get(result["error"], (500, "User service error"))
        raise HTTPException(code, msg)
    return result["user"]

@app.post("/users/{user_id}/suspend", response_model=UserResponse, tags=["Users"])
async def suspend_user(user_id: UUID, _: dict = Depends(require_auth)):
    result = await uds_call("suspend_user", {"user_id": str(user_id)})
    if "error" in result:
        if result["error"] == "user_not_found": raise HTTPException(404, "User not found")
        if result["error"] == "user_already_inactive": raise HTTPException(409, "User already suspended")
        raise HTTPException(500, "User service error")
    return result["user"]

@app.post("/users/{user_id}/revoke", response_model=UserResponse, tags=["Users"])
async def revoke_user(user_id: UUID, _: dict = Depends(require_auth)):
    result = await uds_call("revoke_user", {"user_id": str(user_id)})
    if "error" in result:
        if result["error"] == "user_not_found": raise HTTPException(404, "User not found")
        if result["error"] == "user_already_active": raise HTTPException(409, "User already active")
        raise HTTPException(500, "User service error")
    return result["user"]

@app.delete("/users/{user_id}", status_code=200, tags=["Users"])
async def delete_user(user_id: UUID, _: dict = Depends(require_auth)):
    result = await uds_call("delete_user", {"user_id": str(user_id)})
    if "error" in result:
        raise HTTPException(404, "User not found")
    return {"status": "deleted"}

@app.get("/users/{user_id}/sessions", tags=["Users"])
async def get_user_sessions(
    user_id: UUID = fast_Path(...),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    active_only: bool = Query(False),
    device_id: Optional[str] = Query(None),
    _: dict = Depends(require_auth),
):
    result = await uds_call(action="get_user_sessions", payload={
        "user_id": str(user_id), "limit": limit, "offset": offset,
        "active_only": active_only, "device_id": device_id,
    })
    if "error" in result:
        if result["error"] == "user_not_found": raise HTTPException(404, "User not found")
        raise HTTPException(500, "Internal User Service Error")
    return result

@app.get("/users/{user_id}/sessions/recent", tags=["Users"])
async def get_user_recent_sessions(
    user_id: UUID = fast_Path(...),
    limit: int = Query(10, ge=1, le=50),
    _: dict = Depends(require_auth),
):
    result = await uds_call(action="get_user_sessions", payload={
        "user_id": str(user_id), "limit": limit, "offset": 0,
    })
    if "error" in result:
        if result["error"] == "user_not_found": raise HTTPException(404, "User not found")
        raise HTTPException(500, "Internal User Service Error")
    return result["sessions"]

@app.get("/users/{user_id}/sessions/active", tags=["Users"])
async def get_user_active_sessions(user_id: UUID = fast_Path(...), _: dict = Depends(require_auth)):
    result = await uds_call(action="get_user_sessions", payload={
        "user_id": str(user_id), "active_only": True, "limit": 100, "offset": 0,
    })
    if "error" in result:
        if result["error"] == "user_not_found": raise HTTPException(404, "User not found")
        raise HTTPException(500, "Internal User Service Error")
    return {"user": result["user"], "active_sessions": result["sessions"],
            "count": len(result["sessions"])}


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  LOG SERVICE                                                            │
# └─────────────────────────────────────────────────────────────────────────┘

LogLevel  = Literal["DEBUG","INFO","WARNING","WARN","ERROR","CRITICAL","FATAL"]
Interval  = Literal["1m","5m","15m","1h","1d"]
TopField  = Literal["event","service","user_id","request_id","device_id","level"]
ExportFmt = Literal["jsonl","csv"]
SortOrder = Literal["asc","desc"]

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 4 — main.py: add log_id / log_ids to LogFilters
# Replace the existing LogFilters class with this version.
# ─────────────────────────────────────────────────────────────────────────────

class LogFilters(BaseModel):
    service:        Optional[Union[str, List[str]]] = None
    level:          Optional[Union[LogLevel, List[LogLevel]]] = None
    level_gte:      Optional[LogLevel] = None
    ts_from:        Optional[datetime] = None
    ts_to:          Optional[datetime] = None
    request_id:     Optional[str] = None
    user_id:        Optional[str] = None
    device_id:      Optional[str] = None
    event_contains: Optional[str] = Field(default=None, min_length=2)

    # ── NEW: targeted deletion by primary key ──────────────────────────────
    log_id:  Optional[str]       = Field(default=None, description="Delete/query a single log by ID")
    log_ids: Optional[List[str]] = Field(default=None, description="Delete/query multiple logs by ID list")
    # ──────────────────────────────────────────────────────────────────────

    @model_validator(mode="after")
    def _cross_validate(self):
        if self.level is not None and self.level_gte is not None:
            raise ValueError("`level` and `level_gte` are mutually exclusive")
        if self.ts_from and self.ts_to and self.ts_from > self.ts_to:
            raise ValueError("`ts_from` must be before `ts_to`")
        if self.log_ids is not None and len(self.log_ids) == 0:
            raise ValueError("`log_ids` must contain at least one ID when provided")
        return self

    def to_dict(self) -> dict:
        out: dict = {}
        for f in ("service", "level", "level_gte", "request_id",
                  "user_id", "device_id", "event_contains",
                  "log_id", "log_ids"):          # ← log_id / log_ids included
            v = getattr(self, f)
            if v is not None:
                out[f] = v
        if self.ts_from: out["ts_from"] = self.ts_from.isoformat()
        if self.ts_to:   out["ts_to"]   = self.ts_to.isoformat()
        return out

    def analytics_dict(self) -> dict:
        d = self.to_dict()
        d.pop("event_contains", None)
        d.pop("log_id", None)       # IDs have no meaning in aggregate queries
        d.pop("log_ids", None)
        return d

        
class QueryRequest(BaseModel):
    filters: LogFilters = Field(default_factory=LogFilters)
    limit:   int        = Field(default=100, ge=1, le=1000)
    offset:  int        = Field(default=0, ge=0)
    order:   SortOrder  = "desc"

class CountRequest(BaseModel):
    filters: LogFilters = Field(default_factory=LogFilters)

class AggregateRequest(BaseModel):
    filters:  LogFilters        = Field(default_factory=LogFilters)
    interval: Interval          = "1h"
    ts_from:  Optional[datetime] = None
    ts_to:    Optional[datetime] = None
    @model_validator(mode="after")
    def _merge_ts(self):
        if self.ts_from and not self.filters.ts_from: self.filters.ts_from = self.ts_from
        if self.ts_to   and not self.filters.ts_to:   self.filters.ts_to   = self.ts_to
        return self

class HistogramRequest(BaseModel):
    filters:  LogFilters        = Field(default_factory=LogFilters)
    interval: Interval          = "1h"
    ts_from:  Optional[datetime] = None
    ts_to:    Optional[datetime] = None
    @model_validator(mode="after")
    def _merge_ts(self):
        if self.ts_from and not self.filters.ts_from: self.filters.ts_from = self.ts_from
        if self.ts_to   and not self.filters.ts_to:   self.filters.ts_to   = self.ts_to
        return self

class TopRequest(BaseModel):
    field:   TopField   = "event"
    filters: LogFilters = Field(default_factory=LogFilters)
    limit:   int        = Field(default=10, ge=1, le=500)

class SavedQueryBody(BaseModel):
    name:        str  = Field(min_length=1, max_length=128)
    query:       dict
    description: Optional[str] = Field(default=None, max_length=512)

class ExportRequest(BaseModel):
    filters: LogFilters = Field(default_factory=LogFilters)
    format:  ExportFmt  = "jsonl"
    limit:   int        = Field(default=10_000, ge=1, le=100_000)

class DeleteRequest(BaseModel):
    filters: LogFilters
    @model_validator(mode="after")
    def _require_filter(self):
        if not self.filters.to_dict():
            raise ValueError("At least one filter is required for delete")
        return self

class LogRecord(BaseModel):
    id: str; ingested_at: str; ts: Optional[str] = None
    service: str; level: str; event: Optional[str] = None
    request_id: Optional[str] = None; user_id: Optional[str] = None
    device_id: Optional[str] = None; source_file: Optional[str] = None
    extra: Optional[str] = None

class SavedQueryMeta(BaseModel):
    name: str; created_at: str; updated_at: str
    run_count: int; last_run_at: Optional[str] = None

@app.get("/logs/services", tags=["Logs"])
async def list_log_services(request: Request, cfg: Annotated[Settings, Depends(get_settings)],
                            _: dict = Depends(require_auth)):
    svc_list = await lsh.services(socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    return ok({"services": svc_list}, _rid(request))

@app.post("/logs/query", tags=["Logs"])
async def query_logs(body: QueryRequest, request: Request,
                     cfg: Annotated[Settings, Depends(get_settings)],
                     _: dict = Depends(require_auth)):
    result = await lsh.query_logs(
        filters=body.filters.to_dict(), limit=min(body.limit, cfg.log_max_limit),
        offset=body.offset, order=body.order,
        socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout,
    )
    rows = [LogRecord(**r).model_dump() for r in result.rows]
    return ok({"count": len(rows), "rows": rows}, _rid(request))

@app.post("/logs/count", tags=["Logs"])
async def count_logs(body: CountRequest, request: Request,
                     cfg: Annotated[Settings, Depends(get_settings)],
                     _: dict = Depends(require_auth)):
    result = await lsh.count_logs(filters=body.filters.to_dict(),
                                  socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    return ok({"count": result.count}, _rid(request))

@app.post("/logs/aggregate", tags=["Analytics"])
@limiter.limit(cfg_.analytics_rate_limit)
async def aggregate_logs(body: AggregateRequest, request: Request,
                         cfg: Annotated[Settings, Depends(get_settings)],
                         _: dict = Depends(require_auth)):
    result = await lsh.aggregate(
        interval=body.interval, filters=body.filters.analytics_dict(),
        ts_from=body.filters.ts_from, ts_to=body.filters.ts_to,
        socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout,
    )
    buckets = [{"bucket": b.bucket, "total": b.total, "errors": b.errors,
                "error_rate": b.error_rate, "by_service": b.by_service} for b in result.data]
    return ok({"interval": result.interval, "buckets": result.buckets, "data": buckets}, _rid(request))

@app.post("/logs/histogram", tags=["Analytics"])
@limiter.limit(cfg_.analytics_rate_limit)
async def histogram_logs(body: HistogramRequest, request: Request,
                         cfg: Annotated[Settings, Depends(get_settings)],
                         _: dict = Depends(require_auth)):
    result = await lsh.histogram(
        interval=body.interval, filters=body.filters.analytics_dict(),
        ts_from=body.filters.ts_from, ts_to=body.filters.ts_to,
        socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout,
    )
    buckets = [{"bucket": b.bucket, "total": b.total, "by_level": b.by_level} for b in result.data]
    return ok({"interval": result.interval, "buckets": result.buckets, "data": buckets}, _rid(request))

@app.post("/logs/top", tags=["Analytics"])
@limiter.limit(cfg_.analytics_rate_limit)
async def top_logs(body: TopRequest, request: Request,
                   cfg: Annotated[Settings, Depends(get_settings)],
                   _: dict = Depends(require_auth)):
    result = await lsh.top_n(field=body.field, filters=body.filters.analytics_dict(),
                             limit=body.limit, socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    entries = [{"value": e.value, "total": e.total, "errors": e.errors, "error_rate": e.error_rate}
               for e in result.data]
    return ok({"field": result.field, "count": result.count, "data": entries}, _rid(request))

@app.post("/logs/saved-queries", tags=["Saved Queries"], status_code=201)
async def save_query(body: SavedQueryBody, request: Request,
                     cfg: Annotated[Settings, Depends(get_settings)],
                     _: dict = Depends(require_auth)):
    result = await lsh.saved_query_save(name=body.name, query=body.query,
                                        socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    return ok({"saved": result.saved, "description": body.description}, _rid(request))

@app.get("/logs/saved-queries", tags=["Saved Queries"])
async def list_saved_queries(request: Request, cfg: Annotated[Settings, Depends(get_settings)],
                             _: dict = Depends(require_auth)):
    result = await lsh.saved_query_list(socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    items = [SavedQueryMeta(name=q.name, created_at=q.created_at, updated_at=q.updated_at,
                            run_count=q.run_count, last_run_at=q.last_run_at).model_dump()
             for q in result.queries]
    return ok({"count": len(items), "queries": items}, _rid(request))

@app.get("/logs/saved-queries/{name}", tags=["Saved Queries"])
async def get_saved_query(name: Annotated[str, FPath(min_length=1, max_length=128)],
                          request: Request, cfg: Annotated[Settings, Depends(get_settings)],
                          execute: bool = Query(default=True),
                          _: dict = Depends(require_auth)):
    loaded = await lsh.saved_query_load(name=name, socket_path=cfg.log_socket,
                                        timeout=cfg.log_uds_timeout)
    if not execute:
        return ok({"name": loaded.name, "query": loaded.query}, _rid(request))
    q = loaded.query
    exec_result = await lsh.query_logs(
        filters=q.get("filters", {}), limit=min(int(q.get("limit", 100)), cfg.log_max_limit),
        offset=int(q.get("offset", 0)), order=q.get("order", "desc"),
        socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout,
    )
    rows = [LogRecord(**r).model_dump() for r in exec_result.rows]
    return ok({"name": loaded.name, "query": loaded.query, "count": len(rows), "rows": rows},
              _rid(request))

@app.delete("/logs/saved-queries/{name}", tags=["Saved Queries"])
async def delete_saved_query(name: Annotated[str, FPath(min_length=1, max_length=128)],
                             request: Request, cfg: Annotated[Settings, Depends(get_settings)],
                             _: dict = Depends(require_auth)):
    result = await lsh.saved_query_delete(name=name, socket_path=cfg.log_socket,
                                          timeout=cfg.log_uds_timeout)
    if not result.deleted:
        raise HTTPException(status_code=404, detail=f"Saved query '{name}' not found")
    return ok({"deleted": name}, _rid(request))

# ─────────────────────────────────────────────────────────────────────────────
# PATCH — export_logs_route  (update cfg.export_serve_dir → cfg.log_export_dir)
# ─────────────────────────────────────────────────────────────────────────────
 
@app.post("/logs/export", tags=["Export"])
@limiter.limit(cfg_.analytics_rate_limit)
async def export_logs_route(body: ExportRequest, request: Request,
                            cfg: Annotated[Settings, Depends(get_settings)],
                            _: dict = Depends(require_auth)):
    result = await lsh.export_logs(
        filters=body.filters.to_dict(),
        fmt=body.format,
        limit=body.limit,
        socket_path=cfg.log_socket,
        timeout=cfg.log_uds_timeout,
    )
    filename     = Path(result.path).name
    download_url = f"{str(request.base_url).rstrip('/')}/logs/export/{filename}"
    return ok(
        {
            "download_url": download_url,
            "filename":     filename,
            "format":       result.format,
            "size_bytes":   result.size_bytes,
            "rows":         result.rows,
            "path":         result.path,
        },
        _rid(request),
    )

# ─────────────────────────────────────────────────────────────────────────────
# PATCH — download_export  (update cfg.export_serve_dir → cfg.log_export_dir)
# ─────────────────────────────────────────────────────────────────────────────
 
@app.get("/logs/export/{filename}", tags=["Export"], response_class=FileResponse)
async def download_export(
    filename: Annotated[str, FPath(pattern=r"^logexport_[A-Za-z0-9_\-]+\.(jsonl|csv)$")],
    request:  Request,
    cfg:      Annotated[Settings, Depends(get_settings)],
    _:        dict = Depends(require_auth),
):
    # FIX: was cfg.export_serve_dir — now cfg.log_export_dir
    export_dir = Path(cfg.log_export_dir).resolve()
    target     = (export_dir / filename).resolve()
 
    # Path-traversal guard (unchanged)
    if not str(target).startswith(str(export_dir)):
        raise HTTPException(status_code=400, detail="Invalid filename")
 
    if not target.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Export file '{filename}' not found. "
                f"The file may have been cleaned up or the export directory "
                f"may be misconfigured (expected: {export_dir})"
            ),
        )
 
    media_type = "application/jsonlines" if filename.endswith(".jsonl") else "text/csv"
    return FileResponse(
        path=str(target),
        filename=filename,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
 
 
@app.get("/logs/tail", tags=["Tail"], response_class=EventSourceResponse)
async def tail_logs_sse(
    request: Request, cfg: Annotated[Settings, Depends(get_settings)],
    service: Optional[str] = Query(default=None),
    level:   Optional[str] = Query(default=None),
    timeout: int           = Query(default=60, ge=5, le=300),
    _: dict = Depends(require_auth),
):
    async def _generate() -> AsyncIterator[dict]:
        try:
            async for record in lsh.tail_logs(service=service, level=level, timeout=timeout,
                                              socket_path=cfg.log_socket,
                                              uds_timeout=cfg.log_uds_timeout):
                if await request.is_disconnected(): break
                yield {"event": "log", "data": json.dumps(record)}
        except LogServiceError as e:
            yield {"event": "error", "data": json.dumps({"detail": str(e)})}
        finally:
            yield {"event": "close", "data": json.dumps({"reason": "stream_ended"})}
    return EventSourceResponse(_generate(), ping=1)

@app.delete("/admin/logs", tags=["Admin"], dependencies=[Depends(require_admin_token)])
async def delete_logs(body: DeleteRequest, request: Request,
                      cfg: Annotated[Settings, Depends(get_settings)],
                      _: dict = Depends(require_auth)):
    result = await lsh.delete_logs(filters=body.filters.to_dict(),
                                   socket_path=cfg.log_socket, timeout=cfg.log_uds_timeout)
    log.warning("admin_delete", deleted=result.deleted,
                filters=body.filters.to_dict(), rid=_rid(request))
    return ok({"deleted": result.deleted}, _rid(request))


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  OS SERVICES                                                            │
# └─────────────────────────────────────────────────────────────────────────┘

@app.get("/services", tags=["Services"])
async def list_services(_: dict = Depends(require_auth)):
    return await sh.list_services()

@app.get("/services/status", tags=["Services"])
async def status_all_services(_: dict = Depends(require_auth)):
    return await sh.get_status(target="all")

@app.get("/services/{service_name}/status", tags=["Services"])
async def status_one_service(service_name: str, _: dict = Depends(require_auth)):
    return await sh.get_status(target=service_name)

@app.post("/services/{service_name}/start", response_model=ActionResponse, tags=["Services"])
async def start_service(service_name: str, _: dict = Depends(require_auth)):
    return await sh.start_service(target=service_name)

@app.post("/services/{service_name}/stop", response_model=ActionResponse, tags=["Services"])
async def stop_service(service_name: str, _: dict = Depends(require_auth)):
    return await sh.stop_service(target=service_name)

@app.post("/services/{service_name}/restart", response_model=ActionResponse, tags=["Services"])
async def restart_service(service_name: str, _: dict = Depends(require_auth)):
    return await sh.restart_service(target=service_name)

@app.post("/config/reload", response_model=ActionResponse, tags=["Config"])
async def reload_config(_: dict = Depends(require_auth)):
    return await sh.reload_config()


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  API APPS                                                               │
# └─────────────────────────────────────────────────────────────────────────┘

@app.get("/apps", tags=["Apps"])
async def list_apps(_: dict = Depends(require_auth)):
    return await api_sh.list_apps()

@app.get("/apps/status", tags=["Apps"])
async def status_all_apps(_: dict = Depends(require_auth)):
    return await api_sh.get_status(target="all")

@app.get("/apps/{app_name}/status", tags=["Apps"])
async def status_one_app(app_name: str, _: dict = Depends(require_auth)):
    return await api_sh.get_status(target=app_name)

@app.post("/apps/{app_name}/start", response_model=ActionResponse, tags=["Apps"])
async def start_app(app_name: str, _: dict = Depends(require_auth)):
    return await api_sh.start_app(target=app_name)

@app.post("/apps/{app_name}/stop", response_model=ActionResponse, tags=["Apps"])
async def stop_app(app_name: str, _: dict = Depends(require_auth)):
    return await api_sh.stop_app(target=app_name)

@app.post("/apps/{app_name}/restart", response_model=ActionResponse, tags=["Apps"])
async def restart_app(app_name: str, _: dict = Depends(require_auth)):
    return await api_sh.restart_app(target=app_name)


# ┌─────────────────────────────────────────────────────────────────────────┐
# │  TOR RELAY MANAGEMENT                                                   │
# └─────────────────────────────────────────────────────────────────────────┘




@app.get("/status", tags=["Relay"])
async def status(_: dict = Depends(require_auth)):
    return _raise_if_error(await call_tor_service("status"))


@app.get("/bootstrap", tags=["Relay"])
async def bootstrap(_: dict = Depends(require_auth)):
    return _raise_if_error(await call_tor_service("bootstrap"))


@app.get("/network_state", tags=["Relay"])
async def network_state(_: dict = Depends(require_auth)):
    """
    Lightweight poll — reads only in-process state, never opens the control port.
    Returns: { network_enabled: bool, state: "up"|"down" }
    """
    return _raise_if_error(await call_tor_service("network_state"))


@app.post("/up", tags=["Relay"])
async def relay_up(_: dict = Depends(require_auth)):
    """
    Enable Tor network on an already-running relay.
    Use /start_service if the Tor process is not running at all.
    """
    d = await call_tor_service("up")
    if d.get("error") and d["error"] not in ("already_running", "already_up"):
        raise HTTPException(status_code=500, detail=d.get("detail", d["error"]))
    return d


@app.post("/down", tags=["Relay"])
async def relay_down(_: dict = Depends(require_auth)):
    """
    Disable Tor network. Tor process stays alive; WG traffic hits nftables:
      TCP → DNAT → maintenance page (:maint_port)
      UDP → DROP
    """
    return _raise_if_error(await call_tor_service("down"))


@app.post("/start_service", tags=["Service"])
async def start_service(_: dict = Depends(require_auth)):
    """
    Launch the Tor process from scratch and bring the TransPort up.
    Only valid when the relay is not running (after stop_service or first boot).
    If the relay is already running, returns an error — use /up instead.
    Long-running: may take up to tor.timeout_sec seconds to bootstrap.
    """
    d = await call_tor_service("start_service")
    if d.get("error") and d["error"] not in ("relay_already_running",):
        raise HTTPException(status_code=500, detail=d.get("detail", d["error"]))
    return d


@app.post("/stop_service", tags=["Service"])
async def stop_service(_: dict = Depends(require_auth)):
    """
    Gracefully stop the Tor process: calls /down first (installs nftables DROP
    rules), then terminates the Tor process. Use /start_service to bring it back.
    """
    return _raise_if_error(await call_tor_service("stop_service"))


@app.get("/circuits", tags=["Relay"])
async def circuits(_: dict = Depends(require_auth)):
    """
    Returns active 3-hop circuits.
 
    On success:
        { "circuits": [...], "count": N }
    When the control port is temporarily unreachable (e.g. Tor still bootstrapping):
        { "circuits": [], "count": 0, "fetch_error": "<reason>" }
 
    The frontend treats fetch_error as a soft warning — it preserves the
    previously cached circuit list and shows a banner instead of clearing the grid.
    """
    d = await call_tor_service("circuits")
    # fetch_error is a soft warning — do NOT raise HTTPException.
    # Raising would cause the frontend to catch it in the error path and
    # clear the circuit grid, which is exactly what we want to avoid.
    if d.get("error") and "fetch_error" not in d:
        raise HTTPException(status_code=500, detail=d.get("detail", d["error"]))
    return d


@app.get("/relay/health", tags=["Relay"])
async def relay_health_check(_: dict = Depends(require_auth)):
    return _raise_if_error(await call_tor_service("health"))


# ─── WebSocket bootstrap stream ─────────────────────────────────────────────

@app.websocket("/ws/bootstrap/relay-0")
async def ws_bootstrap(websocket: WebSocket):
    await websocket.accept()
    loop = asyncio.get_running_loop()
    interval = 3
    last_pct = None

    async def _send(payload: dict):
        payload["ts"] = time.time()
        await websocket.send_text(json.dumps(payload))

    async def _poll() -> bool:
        nonlocal last_pct
        result = await loop.run_in_executor(
            None, partial(call_tor_service_sync, "bootstrap")
        )

        if result.get("error") and result["error"] not in ("relay not running",):
            await _send({"type": "error", "error": result["error"]})
            return False

        if not result.get("running"):
            # Relay isn't up yet — heartbeat and keep polling
            await _send({"type": "heartbeat", "id": "relay-0"})
            return True

        pct   = result.get("bootstrap_pct")
        base  = {
            "id":                "relay-0",
            "running":           result.get("running"),
            "uptime":            result.get("uptime"),
            "bootstrap_pct":     pct,
            "bootstrap_tag":     result.get("bootstrap_tag"),
            "bootstrap_summary": result.get("bootstrap_summary"),
            "bootstrap_phase":   result.get("bootstrap_phase"),
            # Pass through bind addresses so frontend can display correctly
            "trans_bind":        result.get("trans_bind"),
            "dns_bind":          result.get("dns_bind"),
            "network_enabled":   result.get("network_enabled"),
        }

        if pct == 100:
            await _send({"type": "done", **base})
            return False

        if pct == last_pct:
            await _send({"type": "heartbeat", "id": "relay-0"})
        else:
            await _send({"type": "progress", **base})
            last_pct = pct

        return True

    try:
        if not await _poll():
            return
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=interval)
                try:
                    msg = json.loads(raw)
                    ni = msg.get("interval")
                    if isinstance(ni, (int, float)) and 1 <= ni <= 60:
                        interval = ni
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                pass
            if not await _poll():
                return
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await _send({"type": "error", "id": "relay-0", "error": f"internal: {e}"})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass



# ┌─────────────────────────────────────────────────────────────────────────┐
# │  KEY ROTATOR                                                            │
# └─────────────────────────────────────────────────────────────────────────┘



@app.get("/api/key-rotator/health", tags=["Key Rotator"])
async def key_rotator_health(request: Request, _: dict = Depends(require_auth)):
    data = await uds_call_keyrotator("ping")
    return ok({"status": data["status"]}, _rid(request))

@app.get("/api/key-rotator/status", tags=["Key Rotator"])
async def key_rotator_status(request: Request, _: dict = Depends(require_auth)):
    data = await uds_call_keyrotator("status")
    return ok(data, _rid(request))

@app.post("/api/key-rotator/rotate", tags=["Key Rotator"])
async def key_rotator_rotate(request: Request, _: dict = Depends(require_auth)):
    data = await uds_call_keyrotator("rotate_now")
    return ok(data, _rid(request))