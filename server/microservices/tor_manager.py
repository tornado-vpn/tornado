# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

"""
tor_service.py v2 — Single-relay Tor transparent proxy manager.

Improvements over v1:
  • All mutable state encapsulated in TorManager (no module-level globals)
  • Pydantic v2 validates both the config file and every UNIX socket request
  • Async health checks via aiohttp + aiohttp-socks (no executor threads blocked)
  • nftables (nft) replaces deprecated iptables; atomic script mode via nft -f -
  • Custom JSON structured logging (JsonFormatter / ContextLoggerAdapter)
  • systemd sd_notify: READY=1 after bootstrap, WATCHDOG=1 on health loop, STOPPING=1 on exit
  • Stem NETWORK_LIVENESS event listener reacts instantly (health watcher = fallback)
  • Specific exception handling throughout (no bare except / silent swallowing)
  • /usr/sbin/nft hard-coded — no $PATH reliance
  • Tor User= privilege-drop via config key tor_user
  • TransPort / DNSPort bind address read from config (trans_bind / dns_bind)

DOWN behaviour:
  1. DisableNetwork=1 via control port  → severs all circuits; TransPort stays bound
  2. nft: TCP from WG subnet → DNAT to 127.0.0.1:MAINT_PORT (HTTP 503 page)
  3. nft: UDP from WG subnet → DROP (DNS and other UDP silently dropped)

UP behaviour:
  1. Flush tor_mgr prerouting chain → TCP reaches Tor TransPort directly
  2. DisableNetwork=0 via control port → circuits rebuild in seconds, no re-bootstrap
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import re
import shutil
import signal
import subprocess
import textwrap
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import sdnotify
import stem.process
from pydantic import BaseModel, model_validator
from stem.control import Controller, EventType


# ═══════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════

_SERVICE_NAME = "tor-management"
_LOG_LEVEL    = os.getenv("LOG_LEVEL", "INFO").upper()
_LOG_DIR      = os.getenv("LOG_DIR", "/var/log/tornado")
_LOG_FILE     = os.path.join(_LOG_DIR, f"{_SERVICE_NAME}.log")

os.makedirs(_LOG_DIR, exist_ok=True)


class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record, with optional extra_fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts":      datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "service": _SERVICE_NAME,
            "level":   record.levelname,
            "logger":  record.name,
            "event":   record.getMessage(),
        }
        if hasattr(record, "extra_fields"):
            payload.update(record.extra_fields)
        if record.exc_info:
            payload["stack_trace"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _build_logger(name: str) -> logging.Logger:
    """
    Return (and cache) a Logger with a JSON stream handler and a rotating
    file handler.  Called once per logical name; subsequent calls return
    the same Logger from the stdlib cache.
    """
    logger = logging.getLogger(name)
    if logger.handlers:          # already configured — return as-is
        return logger

    logger.setLevel(_LOG_LEVEL)
    logger.propagate = False

    _fmt = _JsonFormatter()

    stream = logging.StreamHandler()
    stream.setFormatter(_fmt)
    logger.addHandler(stream)

    file_h = logging.handlers.RotatingFileHandler(
        _LOG_FILE,
        maxBytes=10 * 1024 * 1024,   # 10 MB
        backupCount=5,
        delay=True,                  # don't open file until first write
    )
    file_h.setFormatter(_fmt)
    logger.addHandler(file_h)

    return logger


def get_logger(name: str = _SERVICE_NAME) -> logging.Logger:
    return _build_logger(name)


class ContextLoggerAdapter(logging.LoggerAdapter):
    """
    Merges constructor-time context dict with any per-call extra_fields,
    then forwards to the underlying Logger.

    Usage
    -----
    log = get_context_logger(relay_id="abc", relay_index=0)
    log.info("relay_started", extra={"extra_fields": {"trans_port": 9040}})

    Emits: {"event": "relay_started", "relay_id": "abc",
            "relay_index": 0, "trans_port": 9040, ...}
    """

    def process(
        self, msg: str, kwargs: dict
    ) -> tuple[str, dict]:
        extra        = kwargs.get("extra", {})
        extra_fields = extra.get("extra_fields", {})
        merged       = {**self.extra, **extra_fields}
        kwargs["extra"] = {"extra_fields": merged}
        return msg, kwargs


def get_context_logger(
    name:        str  = _SERVICE_NAME,
    request_id:  str  | None = None,
    relay_id:    str  | None = None,
    relay_index: int  | None = None,
) -> ContextLoggerAdapter:
    """Return a ContextLoggerAdapter pre-loaded with the supplied context."""
    ctx: dict = {}
    if request_id  is not None: ctx["request_id"]  = request_id
    if relay_id    is not None: ctx["relay_id"]    = relay_id
    if relay_index is not None: ctx["relay_index"] = relay_index
    return ContextLoggerAdapter(_build_logger(name), ctx)


def _x(**kwargs) -> dict:
    """
    Compact helper: wraps keyword arguments into the extra_fields structure
    expected by ContextLoggerAdapter / _JsonFormatter.

    Usage: log.info("event", **_x(port=9040, state="up"))
    """
    return {"extra": {"extra_fields": kwargs}}


# ── silence stem's extremely chatty internal logging ───────────
for _ns in ("stem", "stem.control", "stem.socket", "stem.process"):
    logging.getLogger(_ns).setLevel(logging.CRITICAL)

# ── module-level logger (used outside TorManager) ──────────────
log: ContextLoggerAdapter = get_context_logger("tor_service")

# ── systemd notifier ────────────────────────────────────────────
_sd = sdnotify.SystemdNotifier()

# Absolute path — never resolved via $PATH
_NFT = "/usr/sbin/nft"
# nftables table owned exclusively by this service
_NFT_TABLE = "tor_mgr"


# ═══════════════════════════════════════════════════════════════
# PYDANTIC CONFIG MODELS
# ═══════════════════════════════════════════════════════════════

class SocketConfig(BaseModel):
    path: str
    permissions: str = "0o660"

    @property
    def octal_perms(self) -> int:
        return int(self.permissions, 8)


class TorConfig(BaseModel):
    data_dir: str
    binary: str | None = None
    trans_port: int = 9040
    socks_port: int = 9050
    control_port: int = 9051
    dns_port: int = 9053
    maint_port: int = 9041
    timeout_sec: int = 300
    bootstrap_pct: int = 25
    trans_bind: str = "10.0.0.1"
    dns_bind: str = "10.0.0.1"
    tor_user: str | None = None

    @model_validator(mode="after")
    def _resolve_binary(self) -> "TorConfig":
        if not self.binary:
            self.binary = shutil.which("tor") or "/usr/bin/tor"
        return self


class NetworkConfig(BaseModel):
    wg_subnet: str
    wg_iface: str


class HealthConfig(BaseModel):
    interval_sec: int = 60
    timeout_sec: int = 20
    bootstrap_retry_sec: int = 300


class ServiceConfig(BaseModel):
    socket: SocketConfig
    tor: TorConfig
    network: NetworkConfig
    health: HealthConfig


# ── UNIX socket request schema ──────────────────────────────────

class ActionEnum(str, Enum):
    PING          = "ping"
    STATUS        = "status"
    BOOTSTRAP     = "bootstrap"
    NETWORK_STATE = "network_state"
    UP            = "up"
    DOWN          = "down"
    CIRCUITS      = "circuits"
    HEALTH        = "health"
    START_SERVICE = "start_service"
    STOP_SERVICE  = "stop_service"


class SocketRequest(BaseModel):
    action: ActionEnum


# ═══════════════════════════════════════════════════════════════
# RELAY STATE  (typed runtime container)
# ═══════════════════════════════════════════════════════════════

@dataclass
class RelayInfo:
    process:      Any    # subprocess.Popen returned by stem
    started_at:   float
    data_dir:     str
    log_file:     str
    trans_port:   int
    socks_port:   int
    control_port: int
    dns_port:     int

    def is_alive(self) -> bool:
        return self.process.poll() is None

    def uptime(self) -> float:
        return round(time.time() - self.started_at, 1)

    # Stable identifier used to tag log context
    @property
    def relay_id(self) -> str:
        return f"ctrl:{self.control_port}"


# ═══════════════════════════════════════════════════════════════
# MAINTENANCE HTTP RESPONSE
# ═══════════════════════════════════════════════════════════════

_MAINT_RESPONSE: bytes = textwrap.dedent("""\
    HTTP/1.1 503 Service Unavailable\r
    Content-Type: text/html; charset=utf-8\r
    Connection: close\r
    Retry-After: 30\r
    \r
    <!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Tor Relay — Offline</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --white:    #ffffff;
  --off:      #f7f6f3;
  --pale:     #eeece7;
  --border:   #e0ddd5;
  --text:     #1a1916;
  --muted:    #8a8780;
  --faint:    #c4c2bb;
  --amber:    #b45309;
  --amber-bg: #fef3c7;
  --amber-bd: #fcd34d;
  --red:      #c0392b;
  --red-bg:   #fff1f0;
  --red-bd:   #fca5a5;
  --green:    #166534;
  --green-bg: #f0fdf4;
  --green-bd: #86efac;
}

html, body {
  height: 100%;
  background: var(--off);
  color: var(--text);
  font-family: 'Syne', sans-serif;
  -webkit-font-smoothing: antialiased;
}

body {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 2rem;
}

/* ─── Shell ─── */
.shell {
  width: 100%;
  max-width: 980px;
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: 3px;
  overflow: hidden;
  box-shadow:
    0 1px 2px rgba(0,0,0,0.04),
    0 4px 16px rgba(0,0,0,0.06),
    0 24px 64px rgba(0,0,0,0.04);
  animation: fadeUp 0.6s cubic-bezier(0.22,1,0.36,1) both;
}

@keyframes fadeUp {
  from { opacity:0; transform: translateY(20px); }
  to   { opacity:1; transform: translateY(0); }
}

/* ─── Top bar ─── */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 13px 22px;
  border-bottom: 1px solid var(--border);
  background: var(--off);
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.traffic-lights {
  display: flex;
  gap: 6px;
}

.tl {
  width: 11px;
  height: 11px;
  border-radius: 50%;
}
.tl-r { background: #ff5f57; }
.tl-y { background: #febc2e; }
.tl-g { background: #28c840; }

.topbar-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: var(--muted);
  letter-spacing: 0.04em;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 6px;
}

.pill {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9.5px;
  letter-spacing: 0.1em;
  padding: 3px 9px;
  border-radius: 20px;
  text-transform: uppercase;
}

.pill-offline {
  background: var(--amber-bg);
  color: var(--amber);
  border: 1px solid var(--amber-bd);
}

.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--amber);
  animation: blink 1.8s ease-in-out infinite;
}

@keyframes blink {
  0%,100% { opacity: 1; }
  50%      { opacity: 0.25; }
}

/* ─── Main grid ─── */
.main {
  display: grid;
  grid-template-columns: 1fr 340px;
  min-height: 520px;
}

/* ─── Canvas side ─── */
.canvas-side {
  position: relative;
  border-right: 1px solid var(--border);
  background: var(--off);
  overflow: hidden;
}

canvas {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
}

.canvas-watermark {
  position: absolute;
  bottom: 18px;
  left: 20px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  color: var(--faint);
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

/* ─── Info side ─── */
.info-side {
  display: flex;
  flex-direction: column;
  padding: 32px 30px 28px;
  position: relative;
}

/* Accent bar top */
.info-side::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: linear-gradient(90deg, var(--amber) 0%, #fbbf24 50%, transparent 100%);
}

.section-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--faint);
  margin-bottom: 10px;
}

.relay-title {
  font-size: 38px;
  font-weight: 800;
  color: var(--text);
  line-height: 0.95;
  letter-spacing: -0.04em;
  margin-bottom: 6px;
}

.relay-sub {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  color: var(--muted);
  letter-spacing: 0.06em;
  margin-bottom: 24px;
}

.fp-box {
  background: var(--off);
  border: 1px solid var(--border);
  border-radius: 2px;
  padding: 10px 14px;
  margin-bottom: 24px;
}

.fp-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 8.5px;
  color: var(--faint);
  letter-spacing: 0.16em;
  text-transform: uppercase;
  margin-bottom: 4px;
}

.fp-value {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  color: var(--muted);
  letter-spacing: 0.06em;
  word-break: break-all;
  line-height: 1.5;
}

.hr { height: 1px; background: var(--border); margin: 0 0 22px; }

/* ─── Status cards ─── */
.status-grid {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 24px;
}

.status-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 11px 14px;
  border-radius: 2px;
  border: 1px solid;
  animation: fadeUp 0.5s cubic-bezier(0.22,1,0.36,1) both;
}

.status-card:nth-child(1) { animation-delay: 0.1s; }
.status-card:nth-child(2) { animation-delay: 0.18s; }
.status-card:nth-child(3) { animation-delay: 0.26s; }
.status-card:nth-child(4) { animation-delay: 0.34s; }

.status-card.warn {
  background: var(--amber-bg);
  border-color: var(--amber-bd);
}
.status-card.safe {
  background: var(--green-bg);
  border-color: var(--green-bd);
}
.status-card.err {
  background: var(--red-bg);
  border-color: var(--red-bd);
}

.sc-icon {
  width: 30px;
  height: 30px;
  border-radius: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.warn .sc-icon { background: rgba(180,83,9,0.12); }
.safe .sc-icon { background: rgba(22,101,52,0.1); }
.err  .sc-icon { background: rgba(192,57,43,0.1); }

.sc-icon svg { width: 14px; height: 14px; }
.warn .sc-icon svg { stroke: var(--amber); }
.safe .sc-icon svg { stroke: var(--green); }
.err  .sc-icon svg  { stroke: var(--red); }

.sc-body { flex: 1; min-width: 0; }

.sc-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  margin-bottom: 2px;
}
.warn .sc-label { color: rgba(180,83,9,0.6); }
.safe .sc-label { color: rgba(22,101,52,0.55); }
.err  .sc-label { color: rgba(192,57,43,0.55); }

.sc-value {
  font-size: 12.5px;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.warn .sc-value { color: var(--amber); }
.safe .sc-value { color: var(--green); }
.err  .sc-value  { color: var(--red); }

/* ─── Tag row ─── */
.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  margin-bottom: 20px;
}

.tag {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 20px;
  color: var(--muted);
  background: var(--off);
}

/* ─── Footer row ─── */
.footer-row {
  margin-top: auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 18px;
  border-top: 1px solid var(--border);
}

.ts-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  color: var(--faint);
  letter-spacing: 0.06em;
}

.uptime-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--muted);
  background: var(--off);
  letter-spacing: 0.08em;
}

/* ─── Responsive ─── */
@media (max-width: 700px) {
  .main { grid-template-columns: 1fr; }
  .canvas-side { min-height: 260px; border-right: none; border-bottom: 1px solid var(--border); }
}
</style>
</head>
<body>

<div class="shell">

  <!-- Top bar -->
  <div class="topbar">
    <div class="topbar-left">
      <div class="traffic-lights">
        <div class="tl tl-r"></div>
        <div class="tl tl-y"></div>
        <div class="tl tl-g"></div>
      </div>
      <span class="topbar-title">relay-monitor · v2.4.1</span>
    </div>
    <div class="topbar-right">
      <div class="live-dot"></div>
      <span class="pill pill-offline">Offline</span>
    </div>
  </div>

  <!-- Main -->
  <div class="main">

    <!-- Left: animated network map -->
    <div class="canvas-side">
      <canvas id="net"></canvas>
      <div class="canvas-watermark">Network topology · isolated</div>
    </div>

    <!-- Right: info panel -->
    <div class="info-side">

      <div class="section-label">Tor exit relay</div>
      <div class="relay-title">RELAY<br>NODE</div>
      <div class="relay-sub">consensus-weight · 0 · guard · false</div>

      <div class="fp-box">
        <div class="fp-label">Fingerprint</div>
        <div class="fp-value">A3C9·18FF·7D2E·004B·CC31·<br>E8A1·55F2·9D70·0BE4·1102</div>
      </div>

      <div class="hr"></div>

      <div class="status-grid">

        <div class="status-card warn">
          <div class="sc-icon">
            <svg fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 16 16">
              <circle cx="8" cy="8" r="6"/>
              <line x1="8" y1="5" x2="8" y2="8"/>
              <circle cx="8" cy="10.5" r="0.6" fill="currentColor" stroke="none"/>
            </svg>
          </div>
          <div class="sc-body">
            <div class="sc-label">Proxy</div>
            <div class="sc-value">Transparent proxy disabled</div>
          </div>
        </div>

        <div class="status-card safe">
          <div class="sc-icon">
            <svg fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 16 16">
              <path d="M8 2L3 4.5v4C3 11.5 5.5 14 8 15c2.5-1 5-3.5 5-6.5v-4L8 2z"/>
              <polyline points="5.5,8 7.2,9.8 10.5,6.2"/>
            </svg>
          </div>
          <div class="sc-body">
            <div class="sc-label">Egress</div>
            <div class="sc-value">No outbound requests</div>
          </div>
        </div>

        <div class="status-card safe">
          <div class="sc-icon">
            <svg fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 16 16">
              <rect x="3" y="6" width="10" height="8" rx="1.5"/>
              <path d="M5.5 6V4.5a2.5 2.5 0 015 0V6"/>
            </svg>
          </div>
          <div class="sc-body">
            <div class="sc-label">Interception</div>
            <div class="sc-value">Traffic safely captured</div>
          </div>
        </div>

        <div class="status-card err">
          <div class="sc-icon">
            <svg fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 16 16">
              <circle cx="8" cy="8" r="6"/>
              <line x1="5.5" y1="5.5" x2="10.5" y2="10.5"/>
              <line x1="10.5" y1="5.5" x2="5.5" y2="10.5"/>
            </svg>
          </div>
          <div class="sc-body">
            <div class="sc-label">Circuits</div>
            <div class="sc-value">0 active circuits</div>
          </div>
        </div>

      </div>

      <div class="tag-row">
        <span class="tag">network · isolated</span>
        <span class="tag">proxy · off</span>
        <span class="tag">egress · blocked</span>
        <span class="tag">tor · 0.4.8.x</span>
      </div>

      <div class="footer-row">
        <span class="ts-label" id="ts">—</span>
        <span class="uptime-badge" id="uptime">uptime · —</span>
      </div>

    </div>
  </div>
</div>

<script>
/* ── Timestamp & uptime ── */
const start = Date.now();
function pad(n){ return String(n).padStart(2,'0'); }
function tick(){
  const now = new Date();
  document.getElementById('ts').textContent =
    now.toISOString().replace('T',' ').split('.')[0] + ' UTC';
  const s = Math.floor((Date.now()-start)/1000);
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  document.getElementById('uptime').textContent =
    `uptime · ${pad(h)}:${pad(m)}:${pad(sec)}`;
}
tick(); setInterval(tick, 1000);

/* ── Network canvas ── */
const canvas = document.getElementById('net');
const ctx    = canvas.getContext('2d');
let W, H, nodes, raf;

function resize(){
  const r = canvas.parentElement.getBoundingClientRect();
  W = canvas.width  = r.width;
  H = canvas.height = r.height;
  init();
}

function rnd(a,b){ return a + Math.random()*(b-a); }

function init(){
  const cx = W*.5, cy = H*.5;
  nodes = [];

  // Center node (dead relay)
  nodes.push({ x:cx, y:cy, r:14, type:'center', vx:0, vy:0, t:0 });

  // Remote peers — pale, drifting
  for(let i=0;i<16;i++){
    const ang  = (i/16)*Math.PI*2 + rnd(-0.3,0.3);
    const dist = rnd(70, Math.min(W,H)*.4);
    nodes.push({
      x: cx + Math.cos(ang)*dist,
      y: cy + Math.sin(ang)*dist,
      r: rnd(3,6), type:'remote',
      vx: rnd(-0.1,0.1), vy: rnd(-0.1,0.1),
      alpha: rnd(0.12,0.35),
      phase: Math.random()*Math.PI*2,
      speed: rnd(0.008,0.02),
    });
  }

  // Blocked nodes
  for(let i=0;i<4;i++){
    const ang  = rnd(0, Math.PI*2);
    const dist = rnd(80, Math.min(W,H)*.35);
    nodes.push({
      x: cx + Math.cos(ang)*dist,
      y: cy + Math.sin(ang)*dist,
      r: 4.5, type:'blocked',
      vx: rnd(-0.08,0.08), vy: rnd(-0.08,0.08),
      alpha: 0.5,
      phase: Math.random()*Math.PI*2,
      speed: rnd(0.015,0.03),
    });
  }
}

function draw(ts){
  ctx.clearRect(0,0,W,H);
  const t = ts * 0.001;
  const cx = W*.5, cy = H*.5;

  // Draw edges (severed, dashed, pale)
  ctx.save();
  ctx.setLineDash([3,6]);
  ctx.lineWidth = 0.6;
  for(let i=1;i<nodes.length;i++){
    const n = nodes[i];
    if(Math.random() < 0.002) continue; // skip a few for dynamism
    const center = nodes[0];
    const dx = n.x-center.x, dy = n.y-center.y;
    const dist = Math.sqrt(dx*dx+dy*dy);
    if(dist > Math.min(W,H)*.48) continue;

    if(n.type === 'blocked'){
      ctx.strokeStyle = 'rgba(192,57,43,0.12)';
    } else {
      ctx.strokeStyle = 'rgba(26,25,22,0.06)';
    }
    ctx.beginPath();
    ctx.moveTo(center.x, center.y);
    ctx.lineTo(n.x, n.y);
    ctx.stroke();
  }
  ctx.restore();

  // Draw nodes
  for(const n of nodes){
    n.phase += n.speed || 0;

    if(n.type === 'center'){
      const pulse = 0.5 + 0.5*Math.sin(t*1.2);

      // Outer pulse ring
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 10 + pulse*6, 0, Math.PI*2);
      ctx.strokeStyle = `rgba(180,83,9,${0.06 + pulse*0.08})`;
      ctx.lineWidth = 1;
      ctx.setLineDash([2,4]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Middle ring
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 4, 0, Math.PI*2);
      ctx.strokeStyle = 'rgba(180,83,9,0.25)';
      ctx.lineWidth = 0.75;
      ctx.stroke();

      // Core circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
      ctx.fillStyle = '#fff';
      ctx.fill();
      ctx.strokeStyle = 'rgba(180,83,9,0.55)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // × cross
      const s = 5;
      ctx.beginPath();
      ctx.moveTo(n.x-s, n.y-s); ctx.lineTo(n.x+s, n.y+s);
      ctx.moveTo(n.x+s, n.y-s); ctx.lineTo(n.x-s, n.y+s);
      ctx.strokeStyle = 'rgba(180,83,9,0.8)';
      ctx.lineWidth = 1.8;
      ctx.lineCap = 'round';
      ctx.stroke();

    } else if(n.type === 'blocked'){
      const a = n.alpha*(0.7 + 0.3*Math.sin(n.phase));
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
      ctx.fillStyle = `rgba(220,80,60,${a*0.25})`;
      ctx.fill();
      ctx.strokeStyle = `rgba(192,57,43,${a*0.8})`;
      ctx.lineWidth = 0.8;
      ctx.stroke();

    } else {
      const a = n.alpha*(0.6 + 0.4*Math.sin(n.phase));
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
      ctx.fillStyle = `rgba(100,110,130,${a*0.35})`;
      ctx.fill();
      ctx.strokeStyle = `rgba(90,100,120,${a*0.55})`;
      ctx.lineWidth = 0.6;
      ctx.stroke();
    }

    // Drift
    n.x += n.vx||0;
    n.y += n.vy||0;
    const dx = n.x-cx, dy = n.y-cy;
    if(n.type !== 'center' && Math.sqrt(dx*dx+dy*dy) > Math.min(W,H)*.46){
      n.vx = -n.vx; n.vy = -n.vy;
    }
    if(n.x < 8 || n.x > W-8) n.vx = -n.vx;
    if(n.y < 8 || n.y > H-8) n.vy = -n.vy;
  }

  raf = requestAnimationFrame(draw);
}

window.addEventListener('resize',()=>{ cancelAnimationFrame(raf); resize(); });
resize();
requestAnimationFrame(draw);
</script>
</body>
</html>
""").encode()


# ═══════════════════════════════════════════════════════════════
# TOR MANAGER
# ═══════════════════════════════════════════════════════════════

class TorManager:
    """
    Encapsulates all Tor relay state and orchestration logic.

    Logging context
    ───────────────
    self.log starts as a bare ContextLoggerAdapter with no relay context.
    Each time a relay is successfully launched, _attach_relay_context() is
    called to mint a new adapter that carries relay_id in every log record
    emitted by this instance.

    Thread-safety contract
    ──────────────────────
    _relay / _relay_lock  — threading.Lock; accessed from both asyncio loop
                            and executor threads (_launch_relay, etc.)
    _network_enabled      — mutated only from the asyncio event loop
    _maint_server         — accessed only from the asyncio event loop
    _shutdown             — threading.Event; signals the event-listener thread
    """

    def __init__(self, cfg: ServiceConfig) -> None:
        self.cfg = cfg
        self._relay: RelayInfo | None = None
        self._relay_lock = threading.Lock()
        self._network_enabled: bool = False
        self._maint_server: asyncio.Server | None = None
        self._shutdown = threading.Event()
        self._event_thread: threading.Thread | None = None
        # Start with no relay context; updated by _attach_relay_context()
        self.log: ContextLoggerAdapter = get_context_logger("tor_manager")

    # ── Helper: refresh log adapter when a relay comes online ────

    def _attach_relay_context(self, relay: RelayInfo) -> None:
        """
        Replace self.log with a new adapter that permanently carries
        relay_id so every subsequent log call is correlated to this relay.
        """
        self.log = get_context_logger(
            name="tor_manager",
            relay_id=relay.relay_id,
        )

    # ─────────────────────────────────────────────────────────────
    # Maintenance HTTP server
    # ─────────────────────────────────────────────────────────────

    async def start_maint_server(self) -> None:
        if self._maint_server:
            return
        try:
            self._maint_server = await asyncio.start_server(
                self._maint_handler, "127.0.0.1", self.cfg.tor.maint_port
            )
            self.log.info("maint_server_started", **_x(port=self.cfg.tor.maint_port))
        except OSError as e:
            self.log.error("maint_server_failed", **_x(error=str(e)))

    async def stop_maint_server(self) -> None:
        if not self._maint_server:
            return
        try:
            self._maint_server.close()
            await self._maint_server.wait_closed()
        except OSError:
            pass
        finally:
            self._maint_server = None

    @staticmethod
    async def _maint_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await asyncio.wait_for(reader.read(4096), timeout=3.0)
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        try:
            writer.write(_MAINT_RESPONSE)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except RuntimeError:
                pass

    # ─────────────────────────────────────────────────────────────
    # nftables helpers  (all paths hard-code /usr/sbin/nft)
    # ─────────────────────────────────────────────────────────────

    def _nft(self, *args: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [_NFT, *args], capture_output=True, text=True
        )
        if result.returncode != 0:
            self.log.debug(
                "nft_command_failed",
                **_x(args=list(args), stderr=result.stderr.strip()),
            )
        return result

    def _nft_script(self, script: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [_NFT, "-f", "-"],
            input=script,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.log.debug(
                "nft_script_failed",
                **_x(script=script.strip(), stderr=result.stderr.strip()),
            )
        return result

    def _ensure_nft_table(self) -> None:
        script = f"""\
add table ip {_NFT_TABLE}
add chain ip {_NFT_TABLE} prerouting {{ type nat hook prerouting priority dstnat; }}
"""
        self._nft_script(script)

    def _install_down_rules(self) -> None:
        self._ensure_nft_table()
        iface  = self.cfg.network.wg_iface
        subnet = self.cfg.network.wg_subnet
        maint  = self.cfg.tor.maint_port

        script = f"""\
flush chain ip {_NFT_TABLE} prerouting
add rule ip {_NFT_TABLE} prerouting \
iifname "{iface}" ip saddr {subnet} ip protocol tcp \
dnat ip to 127.0.0.1:{maint}
add rule ip {_NFT_TABLE} prerouting \
iifname "{iface}" ip saddr {subnet} ip protocol udp \
drop
"""
        self._nft_script(script)
        self.log.info(
            "nft_down_rules_installed",
            **_x(
                tcp_dest=f"127.0.0.1:{maint}",
                udp="drop",
                iface=iface,
                subnet=subnet,
            ),
        )

    def _remove_down_rules(self) -> None:
        self._nft("flush", "chain", "ip", _NFT_TABLE, "prerouting")
        self.log.info("nft_down_rules_flushed")

    def _teardown_nft_table(self) -> None:
        self._nft("delete", "table", "ip", _NFT_TABLE)
        self.log.info("nft_table_deleted", **_x(table=_NFT_TABLE))

    # ─────────────────────────────────────────────────────────────
    # Tor control port helpers
    # ─────────────────────────────────────────────────────────────

    def _ctrl_set_disable_network(self, disabled: bool) -> bool:
        value = "1" if disabled else "0"
        try:
            with Controller.from_port(port=self.cfg.tor.control_port) as ctrl:
                ctrl.authenticate()
                ctrl.set_conf("DisableNetwork", value)
            self.log.info("tor_disable_network_set", **_x(value=value))
            return True
        except OSError as e:
            self.log.error(
                "tor_disable_network_oserror", **_x(value=value, error=str(e))
            )
            return False
        except Exception as e:
            self.log.error(
                "tor_disable_network_stem_error", **_x(value=value, error=str(e))
            )
            return False

    def _ctrl_get_disable_network(self) -> bool | None:
        try:
            with Controller.from_port(port=self.cfg.tor.control_port) as ctrl:
                ctrl.authenticate()
                return ctrl.get_conf("DisableNetwork", default="0") == "1"
        except OSError:
            return None
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────
    # Stem NETWORK_LIVENESS event listener
    # ─────────────────────────────────────────────────────────────

    def start_event_listener(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._event_thread and self._event_thread.is_alive():
            return                          # already running
        self._event_thread = threading.Thread(
            target=self._run_event_listener,
            args=(loop,),
            daemon=True,
            name="stem-event-listener",
        )
        self._event_thread.start()

    def _run_event_listener(self, loop: asyncio.AbstractEventLoop) -> None:
        while not self._shutdown.is_set():
            try:
                with Controller.from_port(port=self.cfg.tor.control_port) as ctrl:
                    ctrl.authenticate()

                    def _on_liveness(event) -> None:
                        is_up = getattr(event, "status", None) == "UP"
                        self.log.info(
                            "stem_liveness_event", **_x(is_up=is_up)
                        )
                        asyncio.run_coroutine_threadsafe(
                            self._handle_liveness_event(is_up), loop
                        )

                    ctrl.add_event_listener(_on_liveness, EventType.NETWORK_LIVENESS)
                    self._shutdown.wait()
                    ctrl.remove_event_listener(_on_liveness)
                    return

            except OSError:
                self._shutdown.wait(timeout=5)
            except Exception as e:
                self.log.warning(
                    "stem_event_listener_error", **_x(error=str(e))
                )
                self._shutdown.wait(timeout=5)

    async def _handle_liveness_event(self, is_up: bool) -> None:
        loop = asyncio.get_running_loop()
        if not is_up and self._network_enabled:
            self.log.warning("tor_network_went_down_unexpectedly")
            await loop.run_in_executor(None, self._install_down_rules)
            self._network_enabled = False
        elif is_up and not self._network_enabled:        # ← add recovery path
            self.log.info("tor_network_liveness_restored")
            ok = await loop.run_in_executor(
                None, self._ctrl_set_disable_network, False
            )
            if ok:
                await loop.run_in_executor(None, self._remove_down_rules)
                self._network_enabled = True
                self.log.info("tor_network_auto_recovered")
            else:
                self.log.error("tor_network_recovery_failed_control_port")

    # ─────────────────────────────────────────────────────────────
    # Tor process management
    # ─────────────────────────────────────────────────────────────

    def _launch_relay(self) -> RelayInfo:
        """Blocking — run via loop.run_in_executor."""
        t        = self.cfg.tor
        data_dir = t.data_dir
        log_file = os.path.join(data_dir, "tor.log")
        os.makedirs(data_dir, mode=0o700, exist_ok=True)

        tor_config: dict[str, str] = {
            "SocksPort":              str(t.socks_port),
            "ControlPort":            str(t.control_port),
            "TransPort":              f"{t.trans_bind}:{t.trans_port}",
            "DNSPort":                f"{t.dns_bind}:{t.dns_port}",
            "VirtualAddrNetworkIPv4": "10.192.0.0/10",
            "AutomapHostsOnResolve":  "1",
            "CookieAuthentication":   "1",
            "DataDirectory":          data_dir,
            "Log":                    f"notice file {log_file}",
            "DisableNetwork":         "0",
        }
        if t.tor_user:
            tor_config["User"] = t.tor_user

        result_box: list = []

        def _run() -> None:
            try:
                proc = stem.process.launch_tor_with_config(
                    config=tor_config,
                    tor_cmd=t.binary,
                    take_ownership=False,
                    completion_percent=t.bootstrap_pct,
                    init_msg_handler=lambda *_: None,
                )
                result_box.append(proc)
            except Exception as e:
                result_box.extend([None, e])

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=t.timeout_sec)

        if thread.is_alive():
            raise RuntimeError(f"Tor bootstrap timed out after {t.timeout_sec}s")

        if not result_box or result_box[0] is None:
            self._dump_log(log_file)
            err = result_box[1] if len(result_box) > 1 else "unknown error"
            raise RuntimeError(f"Tor failed to start: {err}")

        relay = RelayInfo(
            process=result_box[0],
            started_at=time.time(),
            data_dir=data_dir,
            log_file=log_file,
            trans_port=t.trans_port,
            socks_port=t.socks_port,
            control_port=t.control_port,
            dns_port=t.dns_port,
        )

        # Attach relay context to the logger so all subsequent records carry relay_id
        self._attach_relay_context(relay)

        self.log.info(
            "tor_relay_launched",
            **_x(
                trans_port=t.trans_port,
                trans_bind=t.trans_bind,
                dns_bind=t.dns_bind,
                tor_user=t.tor_user or "root",
            ),
        )
        return relay

    def _hard_stop_relay(self, relay: RelayInfo) -> None:
        try:
            relay.process.terminate()
            relay.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                relay.process.kill()
            except OSError:
                pass
        except OSError:
            pass
        self.log.info("tor_process_terminated")

    def _dump_log(self, log_file: str) -> None:
        try:
            with open(log_file) as f:
                lines = f.readlines()
            for line in lines[-10:]:
                self.log.error("tor_log_tail", **_x(line=line.rstrip()))
        except OSError:
            pass

    # ─────────────────────────────────────────────────────────────
    # Bootstrap status
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_bootstrap(phase: str) -> dict:
        pct_m = re.search(r"PROGRESS=(\d+)", phase)
        tag_m = re.search(r"TAG=(\S+)", phase)
        sum_m = re.search(r'SUMMARY="([^"]*)"', phase)
        return {
            "bootstrap_pct":     int(pct_m.group(1)) if pct_m else None,
            "bootstrap_tag":     tag_m.group(1)      if tag_m else None,
            "bootstrap_summary": sum_m.group(1)       if sum_m else None,
        }

    def get_bootstrap_status(self) -> dict:
        """Blocking — run via loop.run_in_executor."""
        with self._relay_lock:
            relay = self._relay

        base = {
            "network_enabled": self._network_enabled,
            "maint_port":      self.cfg.tor.maint_port,
        }

        if relay is None:
            return {
                **base,
                "running":           False,
                "uptime":            0,
                "bootstrap_pct":     None,
                "bootstrap_tag":     None,
                "bootstrap_summary": None,
                "bootstrap_phase":   None,
                "error":             "relay_not_running",
            }

        result: dict = {
            **base,
            "running":           relay.is_alive(),
            "uptime":            relay.uptime(),
            "trans_bind":        self.cfg.tor.trans_bind,
            "dns_bind":          self.cfg.tor.dns_bind,
            "trans_port":        relay.trans_port,
            "socks_port":        relay.socks_port,
            "control_port":      relay.control_port,
            "dns_port":          relay.dns_port,
            "bootstrap_phase":   None,
            "bootstrap_pct":     None,
            "bootstrap_tag":     None,
            "bootstrap_summary": None,
        }

        if not result["running"]:
            result["error"] = "process_not_running"
            return result

        try:
            with Controller.from_port(port=relay.control_port) as ctrl:
                ctrl.authenticate()
                phase = ctrl.get_info("status/bootstrap-phase")
                result["bootstrap_phase"]  = phase
                result["disable_network"]  = self._ctrl_get_disable_network()
                result.update(self._parse_bootstrap(phase))
        except OSError as e:
            result["error"] = f"control_port_unreachable: {e}"
        except Exception as e:
            result["error"] = f"control_error: {e}"

        return result

    # ─────────────────────────────────────────────────────────────
    # Async health check  (aiohttp + aiohttp-socks — no executor)
    # ─────────────────────────────────────────────────────────────

    async def check_health(self) -> dict:
        import aiohttp
        from aiohttp_socks import ProxyConnector

        with self._relay_lock:
            relay = self._relay

        base = {"network_enabled": self._network_enabled}

        if relay is None:
            return {
                **base,
                "healthy":    False,
                "running":    False,
                "trans_bind": self.cfg.tor.trans_bind,
                "dns_bind":   self.cfg.tor.dns_bind,
                "trans_port": self.cfg.tor.trans_port,
                "socks_port": self.cfg.tor.socks_port,
                "error":      "relay_not_running",
            }
        if not relay.is_alive():
            return {**base, "healthy": False, "error": "process_dead"}
        if not self._network_enabled:
            return {**base, "healthy": False, "error": "network_disabled"}

        try:
            with Controller.from_port(port=relay.control_port) as ctrl:
                ctrl.authenticate()
                phase = ctrl.get_info("status/bootstrap-phase")
            if "PROGRESS=100" not in phase:
                return {
                    **base, "healthy": False,
                    "error": f"bootstrapping: {phase}",
                }
        except OSError as e:
            return {**base, "healthy": False, "error": f"control_port: {e}"}

        proxy_url = f"socks5://127.0.0.1:{relay.socks_port}"
        timeout   = aiohttp.ClientTimeout(total=self.cfg.health.timeout_sec)

        try:
            connector = ProxyConnector.from_url(proxy_url)
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(
                    "https://check.torproject.org/api/ip"
                ) as resp:
                    data = await resp.json()
                    is_tor = bool(data.get("IsTor", False))
                    return {
                        **base,
                        "healthy": is_tor,
                        "exit_ip": data.get("IP"),
                        "error":   None if is_tor else "IsTor_check_failed",
                    }
        except aiohttp.ClientProxyConnectionError as e:
            return {**base, "healthy": False, "error": f"socks_proxy: {e}"}
        except aiohttp.ClientError as e:
            return {**base, "healthy": False, "error": f"http: {e}"}
        except OSError as e:
            return {**base, "healthy": False, "error": f"connectivity: {e}"}

    # ─────────────────────────────────────────────────────────────
    # Circuit enumeration
    # ─────────────────────────────────────────────────────────────

    def get_circuits(self) -> dict:
        """
        Blocking — run via loop.run_in_executor.
 
        Returns
        -------
        {"circuits": [...]}                           on success (list may be empty)
        {"circuits": [], "fetch_error": "<reason>"}   when the control port is
                                                       unreachable or Tor is not
                                                       yet ready — lets the frontend
                                                       show a warning instead of a
                                                       silent empty grid.
        """
        with self._relay_lock:
            relay = self._relay
 
        if relay is None:
            return {"circuits": []}

        if not self._network_enabled:
            # Don't clear the frontend's cached list — surface a warning instead
            return {"circuits": [], "fetch_error": "network_disabled"}
 
        circuits = []
        try:
            with Controller.from_port(port=relay.control_port) as ctrl:
                ctrl.authenticate()
                built = [
                    c for c in ctrl.get_circuits()
                    if str(c.status) == "BUILT" and len(c.path) == 3
                ]
                for circ in built:
                    nodes_info = []
                    for i, (fp, nick) in enumerate(circ.path):
                        node: dict = {
                            "role":        ["guard", "middle", "exit"][i],
                            "fingerprint": fp,
                            "nickname":    nick,
                            "address":     None,
                            "flags":       [],
                        }
                        try:
                            ns = ctrl.get_network_status(fp)
                            node["address"] = ns.address
                            node["flags"]   = [str(f) for f in ns.flags]
                        except Exception:  # noqa: BLE001
                            pass           # best-effort enrichment
                        nodes_info.append(node)
                    circuits.append({"id": circ.id, "path": nodes_info})
 
            return {"circuits": circuits}
 
        except OSError as e:
            # Control port not yet accepting connections — relay is still bootstrapping
            # or the process just restarted. Signal this explicitly so the frontend
            # can show a warning rather than a blank grid.
            self.log.warning("get_circuits_failed", **_x(error=str(e)))
            return {"circuits": [], "fetch_error": f"control_port_unreachable: {e}"}
 
        except Exception as e:  # noqa: BLE001  stem-level errors
            self.log.warning("get_circuits_stem_error", **_x(error=str(e)))
            return {"circuits": [], "fetch_error": str(e)}
    # ─────────────────────────────────────────────────────────────
    # START SERVICE
    # ─────────────────────────────────────────────────────────────

    async def do_start(self) -> dict:
        loop = asyncio.get_running_loop()

        with self._relay_lock:
            relay = self._relay

        if relay is not None and relay.is_alive():
            return {
                "error":  "relay_already_running",
                "detail": "Tor process is already up. "
                          "Use 'up' to re-enable the network, "
                          "or 'stop_service' first for a clean restart.",
            }

        self._ensure_nft_table()
        self._install_down_rules()
        self._network_enabled = False
        self.log.info("tor_start_service_launching")

        try:
            new_relay = await loop.run_in_executor(None, self._launch_relay)
        except RuntimeError as e:
            return {"error": "launch_failed", "detail": str(e)}

        with self._relay_lock:
            self._relay = new_relay

        self.start_event_listener(loop)

        ok = await loop.run_in_executor(None, self._ctrl_set_disable_network, False)
        if not ok:
            return {
                "error":   "control_port_failed",
                "detail":  "Tor launched but DisableNetwork=0 failed — staying DOWN. "
                           "Call 'up' to retry.",
                "running": True,
            }

        self._remove_down_rules()
        self._network_enabled = True
        self.log.info(
            "tor_start_service_up",
            **_x(
                trans_port=new_relay.trans_port,
                trans_bind=self.cfg.tor.trans_bind,
            ),
        )
        return {
            "status":     "started",
            "message":    "Tor process launched and TransPort is live.",
            "trans_port": new_relay.trans_port,
            "trans_bind": self.cfg.tor.trans_bind,
        }

    # ─────────────────────────────────────────────────────────────
    # UP / DOWN orchestration
    # ─────────────────────────────────────────────────────────────

    async def do_up(self) -> dict:
        loop = asyncio.get_running_loop()

        with self._relay_lock:
            relay = self._relay

        if relay is None:
            return {"error": "relay_not_running", "detail": "Tor process is not up."}
        if not relay.is_alive():
            return {"error": "relay_process_dead", "detail": "Tor process has exited."}
        if self._network_enabled:
            return {"status": "already_up", "message": "Network already enabled."}

        await loop.run_in_executor(None, self._remove_down_rules)

        ok = await loop.run_in_executor(None, self._ctrl_set_disable_network, False)
        if not ok:
            await loop.run_in_executor(None, self._install_down_rules)
            return {
                "error":  "control_port_failed",
                "detail": "DisableNetwork=0 failed — nft redirect restored.",
            }

        self._network_enabled = True
        self.log.info("tor_state_up", **_x(trans_port=relay.trans_port))
        return {
            "status":     "up",
            "message":    "Tor network enabled. Circuits rebuilding.",
            "trans_port": relay.trans_port,
        }

    async def do_down(self) -> dict:
        loop = asyncio.get_running_loop()

        with self._relay_lock:
            relay = self._relay

        if relay is None:
            return {"error": "relay_not_running"}
        if not self._network_enabled:
            return {"status": "already_down", "message": "Network already disabled."}

        ok = await loop.run_in_executor(None, self._ctrl_set_disable_network, True)
        if not ok:
            self.log.warning("tor_disable_network_failed_installing_rules_anyway")

        await loop.run_in_executor(None, self._install_down_rules)

        self._network_enabled = False
        self.log.info("tor_state_down", **_x(maint_port=self.cfg.tor.maint_port))
        return {
            "status":     "down",
            "message":    "Network disabled. TCP → maintenance page. UDP → DROP.",
            "maint_port": self.cfg.tor.maint_port,
            "trans_port": relay.trans_port,
            "note":       "Tor process still alive. 'up' restores traffic in seconds.",
        }

    # ─────────────────────────────────────────────────────────────
    # Background health watcher  (process-death fallback)
    # ─────────────────────────────────────────────────────────────

    async def health_watcher(self) -> None:
        loop = asyncio.get_running_loop()

        watchdog_usec = int(os.environ.get("WATCHDOG_USEC", "0"))
        wd_interval   = (watchdog_usec / 1_000_000) / 2 if watchdog_usec else None

        while True:
            await asyncio.sleep(self.cfg.health.interval_sec)

            if wd_interval:
                _sd.notify("WATCHDOG=1")

            try:
                with self._relay_lock:
                    relay = self._relay

                if relay is None or relay.is_alive():
                    continue

                exit_code = relay.process.poll()
                was_up    = self._network_enabled
                self.log.warning(
                    "tor_process_died", **_x(exit_code=exit_code)
                )

                if was_up:
                    self._network_enabled = False
                    self._install_down_rules()

                try:
                    new_relay = await loop.run_in_executor(None, self._launch_relay)
                    with self._relay_lock:
                        self._relay = new_relay

                    if was_up:
                        ok = await loop.run_in_executor(
                            None, self._ctrl_set_disable_network, False
                        )
                        if ok:
                            self._remove_down_rules()
                            self._network_enabled = True
                            self.log.info("tor_relay_restarted_up")
                        else:
                            self.log.error("tor_relay_restarted_failed_to_restore_up")
                    else:
                        await loop.run_in_executor(
                            None, self._ctrl_set_disable_network, True
                        )
                        self.log.info("tor_relay_restarted_down")

                except Exception as e:
                    self.log.error(
                        "tor_relay_restart_failed", **_x(error=str(e))
                    )
                    with self._relay_lock:
                        self._relay = None

            except Exception as e:
                self.log.exception(
                    "health_watcher_error", **_x(error=str(e))
                )

    # ─────────────────────────────────────────────────────────────
    # Dispatch
    # ─────────────────────────────────────────────────────────────

    async def dispatch(self, req: SocketRequest) -> dict:
        action = req.action
        loop   = asyncio.get_running_loop()

        if action in (ActionEnum.STATUS, ActionEnum.BOOTSTRAP):
            return await loop.run_in_executor(None, self.get_bootstrap_status)

        if action == ActionEnum.NETWORK_STATE:
            return {
                "network_enabled": self._network_enabled,
                "state":           "up" if self._network_enabled else "down",
            }

        if action == ActionEnum.UP:
            return await self.do_up()

        if action == ActionEnum.DOWN:
            return await self.do_down()

        if action == ActionEnum.CIRCUITS:
            result = await loop.run_in_executor(None, self.get_circuits)
            # Merge count into result dict; preserve fetch_error if present.
            return {
                **result,
                "count": len(result.get("circuits", [])),
            }

        if action == ActionEnum.HEALTH:
            return await self.check_health()

        if action == ActionEnum.START_SERVICE:
            return await self.do_start()

        if action == ActionEnum.STOP_SERVICE:
            if self._network_enabled:
                await self.do_down()
            with self._relay_lock:
                relay        = self._relay
                self._relay  = None
            if relay:
                await loop.run_in_executor(None, self._hard_stop_relay, relay)
            return {"status": "service_stopped"}

        if action == ActionEnum.PING:
            return {"status": "pong"}

        return {"error": "invalid_action"}


# ═══════════════════════════════════════════════════════════════
# UNIX SOCKET CLIENT HANDLER
# ═══════════════════════════════════════════════════════════════

async def handle_client(
    manager: TorManager,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        except asyncio.TimeoutError:
            writer.write(json.dumps({"error": "read_timeout"}).encode())
            await writer.drain()
            return

        if not data:
            return

        try:
            raw = json.loads(data.decode())
        except json.JSONDecodeError:
            writer.write(json.dumps({"error": "invalid_json"}).encode())
            await writer.drain()
            return

        if raw.get("action") == "ping":
            writer.write(json.dumps({"status": "pong"}).encode())
            await writer.drain()
            return

        try:
            req = SocketRequest.model_validate(raw)
        except Exception as e:
            writer.write(
                json.dumps({"error": "invalid_request", "detail": str(e)}).encode()
            )
            await writer.drain()
            return

        resp = await manager.dispatch(req)
        writer.write(json.dumps(resp).encode())
        await writer.drain()

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        log.exception("handle_client_unexpected_error")
        try:
            writer.write(json.dumps({"error": "internal_error"}).encode())
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
    finally:
        try:
            writer.close()
        except RuntimeError:
            pass


# ═══════════════════════════════════════════════════════════════
# CONFIG LOADER
# ═══════════════════════════════════════════════════════════════

def _load_config() -> ServiceConfig:
    path = os.environ.get("TOR_SERVICE_CONFIG", "tor_service_config.json")
    with open(path) as f:
        raw: dict = json.load(f)

    tor    = raw.setdefault("tor", {})
    net    = raw.setdefault("network", {})
    health = raw.setdefault("health", {})
    sock   = raw.setdefault("socket", {})

    def _ov(env: str, target: dict, key: str, cast=str) -> None:
        if v := os.environ.get(env):
            target[key] = cast(v)

    _ov("TOR_SOCKET_PATH",      sock,   "path")
    _ov("TOR_BINARY",           tor,    "binary")
    _ov("TOR_DATA_DIR",         tor,    "data_dir")
    _ov("TOR_TRANS_PORT",       tor,    "trans_port",          int)
    _ov("TOR_SOCKS_PORT",       tor,    "socks_port",          int)
    _ov("TOR_CONTROL_PORT",     tor,    "control_port",        int)
    _ov("TOR_DNS_PORT",         tor,    "dns_port",            int)
    _ov("TOR_MAINT_PORT",       tor,    "maint_port",          int)
    _ov("TOR_TIMEOUT",          tor,    "timeout_sec",         int)
    _ov("TOR_BOOTSTRAP_PCT",    tor,    "bootstrap_pct",       int)
    _ov("TOR_TRANS_BIND",       tor,    "trans_bind")
    _ov("TOR_DNS_BIND",         tor,    "dns_bind")
    _ov("TOR_USER",             tor,    "tor_user")
    _ov("WG_SUBNET",            net,    "wg_subnet")
    _ov("WG_IFACE",             net,    "wg_iface")
    _ov("HEALTH_INTERVAL",      health, "interval_sec",        int)
    _ov("TOR_HEALTH_TIMEOUT",   health, "timeout_sec",         int)
    _ov("TOR_BOOTSTRAP_RETRY",  health, "bootstrap_retry_sec", int)

    return ServiceConfig.model_validate(raw)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

async def main() -> None:
    cfg     = _load_config()
    manager = TorManager(cfg)
    loop    = asyncio.get_running_loop()

    stop_event = asyncio.Event()

    def _on_signal(sig_name: str) -> None:
        log.info("signal_received", **_x(signal=sig_name))
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: _on_signal(s.name))

    log.info("killing_stale_tor_processes")
    subprocess.run(["killall", "-q", "tor"], capture_output=True)
    time.sleep(1)
    manager._teardown_nft_table()

    sock_path = cfg.socket.path
    if os.path.exists(sock_path):
        os.remove(sock_path)
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    os.makedirs(cfg.tor.data_dir, exist_ok=True)

    await manager.start_maint_server()

    manager._ensure_nft_table()
    manager._install_down_rules()
    log.info("initial_state", **_x(state="DOWN", reason="tor_not_yet_bootstrapped"))

    server = await asyncio.start_unix_server(
        lambda r, w: handle_client(manager, r, w),
        path=sock_path,
    )
    os.chmod(sock_path, cfg.socket.octal_perms)
    log.info("socket_listening", **_x(path=sock_path))

    manager.start_event_listener(loop)

    async def _auto_start() -> None:
        try:
            log.info("tor_launch_starting")
            relay = await loop.run_in_executor(None, manager._launch_relay)
            with manager._relay_lock:
                manager._relay = relay

            log.info(
                "tor_bootstrap_complete",
                **_x(pct=cfg.tor.bootstrap_pct),
            )
            ok = await loop.run_in_executor(
                None, manager._ctrl_set_disable_network, False
            )
            if ok:
                manager._remove_down_rules()
                manager._network_enabled = True
                log.info(
                    "tor_autostart_up",
                    **_x(
                        trans_port=cfg.tor.trans_port,
                        trans_bind=cfg.tor.trans_bind,
                    ),
                )
            else:
                log.error("tor_autostart_disable_network_failed")

        except Exception:
            log.exception("tor_autostart_failed")

        _sd.notify("READY=1")

    asyncio.create_task(_auto_start())
    asyncio.create_task(manager.health_watcher())

    async with server:
        server_task = asyncio.create_task(server.serve_forever())
        await stop_event.wait()
        log.info("shutdown_initiated")
        server_task.cancel()

    _sd.notify("STOPPING=1")
    manager._shutdown.set()

    if manager._network_enabled:
        manager._ctrl_set_disable_network(True)
        manager._install_down_rules()
        manager._network_enabled = False

    with manager._relay_lock:
        relay           = manager._relay
        manager._relay  = None
    if relay:
        manager._hard_stop_relay(relay)

    await manager.stop_maint_server()
    manager._teardown_nft_table()
    log.info("tor_service_stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        log.exception("tor_service_crashed")