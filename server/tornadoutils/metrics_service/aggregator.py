# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

# aggregator.py
import time
from collections import deque
import psutil

# ================= CONFIG =================
AGG_INTERVAL_SEC = 60  # Aggregate every 1 minute
COLL_INTERVAL_SEC = 5  # Collect every 5 seconds
HISTORY_1H = 60        # 1 hour of 1-minute points
HISTORY_24H = 24 * 60  # 24 hours of 1-minute points
# =========================================

SERVICE_START_TS = time.time()
# Stores aggregated points
history_1h = deque(maxlen=HISTORY_1H)
history_24h = deque(maxlen=HISTORY_24H)

# Temporary buffer for 5s metrics
buffer_5s = []

# Store last network counters for live delta
last_net = psutil.net_io_counters()
last_ts = time.time()

# Pre-fill buffer_5s with initial metric to avoid 0 spikes
buffer_5s.append({
    "ts": int(last_ts),
    "cpu": psutil.cpu_percent(interval=None),
    "mem": psutil.virtual_memory().percent,
    "disk": psutil.disk_usage("/").percent,
    "rx_kbps": 0.0,
    "tx_kbps": 0.0,
    "rx_bytes": last_net.bytes_recv,
    "tx_bytes": last_net.bytes_sent
})


def collect_live_metrics():
    """Collect a single 5-second metric snapshot."""
    global last_net, last_ts
    now = time.time()
    net = psutil.net_io_counters()
    rx_kbps = (net.bytes_recv - last_net.bytes_recv) / 1024 / max(now - last_ts, 1)
    tx_kbps = (net.bytes_sent - last_net.bytes_sent) / 1024 / max(now - last_ts, 1)
    last_net = net
    last_ts = now

    return {
        "ts": int(now),
        "cpu": psutil.cpu_percent(interval=None),
        "mem": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
        "rx_kbps": round(rx_kbps, 2),
        "tx_kbps": round(tx_kbps, 2),
        "rx_bytes": net.bytes_recv,
        "tx_bytes": net.bytes_sent
    }


def aggregate_buffer(buffer):
    """Aggregate multiple 5s metrics into a 1-minute point."""
    n = len(buffer)
    if n == 0:
        return None

    cpu_avg = sum(m['cpu'] for m in buffer) / n
    mem_avg = sum(m['mem'] for m in buffer) / n
    disk_avg = sum(m['disk'] for m in buffer) / n

    # Network delta in KBps over the minute
    rx_delta = (buffer[-1]['rx_bytes'] - buffer[0]['rx_bytes']) / 1024 / max(buffer[-1]['ts'] - buffer[0]['ts'], 1)
    tx_delta = (buffer[-1]['tx_bytes'] - buffer[0]['tx_bytes']) / 1024 / max(buffer[-1]['ts'] - buffer[0]['ts'], 1)

    return {
        "ts": buffer[-1]['ts'],
        "cpu": round(cpu_avg, 2),
        "mem": round(mem_avg, 2),
        "disk": round(disk_avg, 2),
        "rx_kbps": round(rx_delta, 2),
        "tx_kbps": round(tx_delta, 2)
    }


def run_aggregator():
    """Continuously collect 5s metrics and aggregate every minute."""
    global buffer_5s
    last_agg = time.time()

    while True:
        metric = collect_live_metrics()
        buffer_5s.append(metric)

        now = time.time()
        if now - last_agg >= AGG_INTERVAL_SEC:
            point = aggregate_buffer(buffer_5s)
            if point:
                history_1h.append(point)
                history_24h.append(point)
            buffer_5s = []
            last_agg = now

        time.sleep(COLL_INTERVAL_SEC)


# ===================== API GETTERS =====================
def get_last_1h():
    return {"resolution": "1m", "points": list(history_1h)}


def get_last_24h():
    return {"resolution": "1m", "points": list(history_24h)}


def get_live():
    """Return a smoothed live metric using recent 5s buffer."""
    global buffer_5s, last_net, last_ts
    now = time.time()

    if len(buffer_5s) >= 2:
        # Use last few metrics for smoothing (up to 12 = 1 min)
        recent = buffer_5s[-12:]
        n = len(recent)
        cpu_avg = sum(m['cpu'] for m in recent) / n
        mem_avg = sum(m['mem'] for m in recent) / n
        disk_avg = sum(m['disk'] for m in recent) / n
        rx_delta = (recent[-1]['rx_bytes'] - recent[0]['rx_bytes']) / 1024 / max(recent[-1]['ts'] - recent[0]['ts'], 1)
        tx_delta = (recent[-1]['tx_bytes'] - recent[0]['tx_bytes']) / 1024 / max(recent[-1]['ts'] - recent[0]['ts'], 1)
    else:
        # If buffer too short, calculate from last_net
        net = psutil.net_io_counters()
        rx_delta = (net.bytes_recv - last_net.bytes_recv) / 1024 / max(now - last_ts, 1)
        tx_delta = (net.bytes_sent - last_net.bytes_sent) / 1024 / max(now - last_ts, 1)
        last_net = net
        last_ts = now
        if buffer_5s:
            cpu_avg = buffer_5s[-1]['cpu']
            mem_avg = buffer_5s[-1]['mem']
            disk_avg = buffer_5s[-1]['disk']
        else:
            # fallback
            cpu_avg = psutil.cpu_percent(interval=None)
            mem_avg = psutil.virtual_memory().percent
            disk_avg = psutil.disk_usage("/").percent

    return {
        "status": "running",
        "uptime_sec": int(now - SERVICE_START_TS),
        "cpu_percent": round(cpu_avg, 2),
        "memory_percent": round(mem_avg, 2),
        "disk_percent": round(disk_avg, 2),
        "rx_kbps": round(rx_delta, 2),
        "tx_kbps": round(tx_delta, 2),
        "timestamp": int(now)
    }
