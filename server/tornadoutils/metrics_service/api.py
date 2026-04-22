# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

from fastapi import FastAPI
import time
import sqlite3
from cache import get_latest
from storage import DB_PATH

SERVICE_START_TS = int(time.time())
INTERVAL = 5  # collector interval in seconds

app = FastAPI()

# ----------------- Helper -----------------
def fetch_metrics(table: str, start: int, end: int):
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            f"""
            SELECT ts, cpu, mem, disk, rx, tx
            FROM {table}
            WHERE ts BETWEEN ? AND ?
            ORDER BY ts ASC
            """,
            (start, end)
        ).fetchall()

# ----------------- Live metrics -----------------
@app.get("/api/metrics/live")
def live_metrics():
    data = get_latest()
    if not data:
        return {"status": "initializing"}

    uptime = int(time.time()) - SERVICE_START_TS

    # Live metrics: convert raw 5s bytes → KB/s
    rx_kbps = round((data["rx"] / 1024) / INTERVAL, 2)
    tx_kbps = round((data["tx"] / 1024) / INTERVAL, 2)

    return {
        "status": "running",
        "uptime_sec": uptime,
        "cpu_percent": data["cpu"],
        "memory_percent": data["mem"],
        "disk_percent": data["disk"],
        "rx_kbps": rx_kbps,
        "tx_kbps": tx_kbps,
        "timestamp": data["ts"]
    }

# ----------------- Historical metrics -----------------
def format_points(rows):
    return [
        {
            "ts": ts,
            "cpu": round(cpu, 2),
            "mem": round(mem, 2),
            "disk": round(disk, 2),
            "rx_kbps": round(rx, 2),  # already normalized in aggregator
            "tx_kbps": round(tx, 2)
        }
        for ts, cpu, mem, disk, rx, tx in rows
    ]

@app.get("/api/metrics/last_1h")
def last_1h():
    end = int(time.time())
    start = end - 3600  # 1 hour
    rows = fetch_metrics("metrics_1m", start, end)
    return {"resolution": "1m", "points": format_points(rows)}

@app.get("/api/metrics/last_24h")
def last_24h():
    end = int(time.time())
    start = end - 86400  # 24 hours
    rows = fetch_metrics("metrics_1m", start, end)
    return {"resolution": "1m", "points": format_points(rows)}

# ----------------- Generic range endpoint -----------------
@app.get("/api/metrics/range")
def range_metrics(resolution: str, start: int, end: int):
    table = {
        "5s": "metrics_5s",
        "1m": "metrics_1m",
        "1h": "metrics_1h",
    }.get(resolution)

    if not table:
        return {"error": "invalid resolution"}

    rows = fetch_metrics(table, start, end)

    # For 5s resolution, raw RX/TX are bytes → keep as None or calculate if needed
    points = []
    for ts, cpu, mem, disk, rx, tx in rows:
        if resolution == "5s":
            rx_val = None
            tx_val = None
        else:
            rx_val = rx
            tx_val = tx

        points.append({
            "ts": ts,
            "cpu": round(cpu, 2),
            "mem": round(mem, 2),
            "disk": round(disk, 2),
            "rx_kbps": rx_val,
            "tx_kbps": tx_val
        })

    return {"resolution": resolution, "points": points}
