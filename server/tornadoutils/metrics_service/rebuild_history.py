# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

# rebuild_history.py
import sqlite3
import time
from storage import DB_PATH

def rebuild_1m(from_ts=None, to_ts=None):
    """Aggregate metrics_5s → metrics_1m over a given range."""
    now = int(time.time())
    from_ts = from_ts or (now - 24*3600)  # default last 24h
    to_ts = to_ts or now

    with sqlite3.connect(DB_PATH) as conn:
        ts = (from_ts // 60) * 60  # align to minute boundary
        while ts < to_ts:
            start = ts
            end = ts + 60
            rows = conn.execute(
                "SELECT cpu, mem, disk, rx, tx FROM metrics_5s WHERE ts >= ? AND ts < ?",
                (start, end)
            ).fetchall()

            if rows:
                cpu = sum(r[0] for r in rows) / len(rows)
                mem = sum(r[1] for r in rows) / len(rows)
                disk = sum(r[2] for r in rows)
                rx_bytes = sum(r[3] for r in rows)
                tx_bytes = sum(r[4] for r in rows)
                rx_kbps = (rx_bytes / 1024) / 60
                tx_kbps = (tx_bytes / 1024) / 60

                conn.execute(
                    """
                    INSERT OR REPLACE INTO metrics_1m
                    (ts, cpu, mem, disk, rx, tx)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ts, cpu, mem, disk, rx_kbps, tx_kbps)
                )
            ts += 60

    print("✅ Rebuilt 1m metrics from raw 5s data.")

if __name__ == "__main__":
    rebuild_1m()
