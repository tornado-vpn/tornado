# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

# storage.py
import sqlite3
from threading import Lock

DB_PATH = "metrics.db"
_lock = Lock()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")

        # 5s raw metrics
        conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics_5s (
            ts INTEGER,
            cpu REAL,
            mem REAL,
            disk REAL,
            rx INTEGER,   -- bytes per 5s
            tx INTEGER
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_5s_ts ON metrics_5s(ts)")

        # 1m rollups (KB/s)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics_1m (
            ts INTEGER PRIMARY KEY,
            cpu REAL,
            mem REAL,
            disk REAL,
            rx REAL,     -- KB/s
            tx REAL
        )
        """)

        # 1h rollups (future use, KB/s)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics_1h (
            ts INTEGER PRIMARY KEY,
            cpu REAL,
            mem REAL,
            disk REAL,
            rx REAL,
            tx REAL
        )
        """)

def insert_raw_metric(m: dict):
    with _lock, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO metrics_5s VALUES (?, ?, ?, ?, ?, ?)",
            (m["ts"], m["cpu"], m["mem"], m["disk"], m["rx"], m["tx"])
        )
