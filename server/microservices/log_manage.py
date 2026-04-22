# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Log Management Microservice
============================

"""

import asyncio
import csv
import io
import re
import tempfile
import json
import logging
import os
import signal
import sqlite3
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ==================== CONFIG ====================

_CONFIG_PATH = os.environ.get("LOG_SERVICE_CONFIG", "log_service_config.json")

def _load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

_cfg = _load_config(_CONFIG_PATH)

SOCKET_PATH         = _cfg["socket"]["path"]
SOCKET_PERMS        = int(_cfg["socket"]["permissions"], 8)

DB_PATH             = os.getenv("LOG_DB_PATH",          _cfg["database"]["path"])

LOG_DIRS            = [d.strip() for d in os.getenv(
                           "LOG_WATCH_DIRS",
                           ",".join(_cfg["watcher"]["log_dirs"])
                       ).split(",")]

WATCH_EXTENSIONS    = frozenset(_cfg["watcher"]["watch_extensions"])
IGNORE_SUFFIXES     = frozenset(_cfg["watcher"]["ignore_suffixes"])

RETENTION_DAYS      = int(os.getenv("LOG_RETENTION_DAYS",  str(_cfg["retention"]["days"])))

FLUSH_INTERVAL      = float(os.getenv("LOG_FLUSH_SEC",     str(_cfg["buffer"]["flush_interval_sec"])))
BUFFER_SIZE         = int(os.getenv("LOG_BUFFER_SIZE",     str(_cfg["buffer"]["flush_size"])))
MAX_BUFFER_HARD_CAP = int(os.getenv("LOG_MAX_BUFFER_CAP",  str(_cfg["buffer"]["hard_cap"])))

MAX_ROWS            = int(os.getenv("LOG_MAX_ROWS",        str(_cfg["query"]["max_rows"])))

MAX_CONNECTIONS     = int(os.getenv("LOG_MAX_CONNECTIONS", str(_cfg["connections"]["max"])))

EXPORT_TMP_DIR      = os.getenv("LOG_EXPORT_DIR",          _cfg["export"]["tmp_dir"])
EXPORT_MAX_ROWS     = int(os.getenv("LOG_EXPORT_MAX_ROWS", str(_cfg["export"]["max_rows"])))

LOG_LEVEL           = os.getenv("LOG_LEVEL",               _cfg["logging"]["level"]).upper()
_LOG_SERVICE_LOG_DIR = os.getenv("LOG_SERVICE_LOG_DIR",    _cfg["logging"]["service_log_dir"])

# FEAT #1/3 – valid aggregate intervals → SQLite strftime format strings
_INTERVAL_FMT: dict[str, str] = {
    "1m":  "%Y-%m-%dT%H:%M",
    "5m":  "%Y-%m-%dT%H:%M",   # bucketed in Python after query
    "15m": "%Y-%m-%dT%H:%M",   # bucketed in Python after query
    "1h":  "%Y-%m-%dT%H",
    "1d":  "%Y-%m-%d",
}

# ================================================

def _make_logger() -> logging.Logger:
    class _JsonFmt(logging.Formatter):
        def format(self, r):
            d = {"ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "service": "log-service", "level": r.levelname, "event": r.getMessage()}
            if r.exc_info:
                d["stack_trace"] = self.formatException(r.exc_info)
            return json.dumps(d)

    log = logging.getLogger("log-service")
    log.setLevel(LOG_LEVEL)
    log.propagate = False
    if not log.handlers:
        sh = logging.StreamHandler()
        sh.setFormatter(_JsonFmt())
        log.addHandler(sh)
        try:
            os.makedirs(_LOG_SERVICE_LOG_DIR, exist_ok=True)
            fh = RotatingFileHandler(
                f"{_LOG_SERVICE_LOG_DIR}/log-service.log",
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
            )
            fh.setFormatter(_JsonFmt())
            log.addHandler(fh)
        except OSError:
            pass
    return log

logger = _make_logger()

# ==================== DATABASE ====================

# FIX #F – INCREMENTAL auto_vacuum so deleted pages are reclaimed over time.
_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA cache_size   = -16000;
PRAGMA temp_store   = MEMORY;
PRAGMA auto_vacuum  = INCREMENTAL;

CREATE TABLE IF NOT EXISTS logs (
    id          TEXT PRIMARY KEY,
    ingested_at TEXT NOT NULL,
    ts          TEXT,
    service     TEXT NOT NULL DEFAULT 'unknown',
    level       TEXT NOT NULL DEFAULT 'INFO',
    event       TEXT,
    request_id  TEXT,
    user_id     TEXT,
    device_id   TEXT,
    source_file TEXT,
    extra       TEXT,
    raw         TEXT
);

CREATE INDEX IF NOT EXISTS idx_ts               ON logs (ts);
CREATE INDEX IF NOT EXISTS idx_service          ON logs (service);
CREATE INDEX IF NOT EXISTS idx_level            ON logs (level);
CREATE INDEX IF NOT EXISTS idx_user_id          ON logs (user_id);
CREATE INDEX IF NOT EXISTS idx_request_id       ON logs (request_id);
CREATE INDEX IF NOT EXISTS idx_service_ts       ON logs (service, ts);
CREATE INDEX IF NOT EXISTS idx_level_ts         ON logs (level, ts);
CREATE INDEX IF NOT EXISTS idx_service_level_ts ON logs (service, level, ts);

CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5 (
    id UNINDEXED,
    event,
    content='logs',
    content_rowid='rowid',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts (rowid, id, event) VALUES (new.rowid, new.id, new.event);
END;
CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts (logs_fts, rowid, id, event)
    VALUES ('delete', old.rowid, old.id, old.event);
END;
CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE OF event ON logs BEGIN
    INSERT INTO logs_fts (logs_fts, rowid, id, event)
    VALUES ('delete', old.rowid, old.id, old.event);
    INSERT INTO logs_fts (rowid, id, event) VALUES (new.rowid, new.id, new.event);
END;

-- FEAT #4 – named saved queries persisted across restarts.
CREATE TABLE IF NOT EXISTS saved_queries (
    name        TEXT PRIMARY KEY,
    query_json  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    run_count   INTEGER NOT NULL DEFAULT 0,
    last_run_at TEXT
);
"""

_LEVEL_SEVERITY = {
    "DEBUG": 10, "INFO": 20, "WARNING": 30, "WARN": 30,
    "ERROR": 40, "CRITICAL": 50, "FATAL": 50,
}


class DB:
    def __init__(self, path: str):
        self._path       = path
        self._write_lock = threading.Lock()
        self._write_conn: Optional[sqlite3.Connection] = None
        self._read_local = threading.local()

    def _ensure_dir(self):
        db_dir = Path(self._path).parent
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise RuntimeError(
                f"Cannot create DB directory '{db_dir}': {e}\n"
                f"Set LOG_DB_PATH env var to a writable path, e.g.:\n"
                f"  export LOG_DB_PATH=/tmp/logs.db"
            ) from e

    def _write_connection(self) -> sqlite3.Connection:
        if self._write_conn is None:
            self._ensure_dir()
            c = sqlite3.connect(
                self._path, check_same_thread=False,
                isolation_level=None, timeout=10,
            )
            c.row_factory = sqlite3.Row
            self._write_conn = c
        return self._write_conn

    def _read_connection(self) -> sqlite3.Connection:
        if not getattr(self._read_local, "conn", None):
            self._ensure_dir()
            uri = f"file:{self._path}?mode=ro"
            try:
                c = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=5)
            except sqlite3.OperationalError:
                c = sqlite3.connect(self._path, check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            self._read_local.conn = c
        return self._read_local.conn

    def init(self):
        with self._write_lock:
            self._write_connection().executescript(_DDL)

    def bulk_insert(self, rows: list[dict]):
        if not rows:
            return
        sql = (
            "INSERT OR IGNORE INTO logs "
            "(id,ingested_at,ts,service,level,event,request_id,user_id,"
            "device_id,source_file,extra,raw) "
            "VALUES (:id,:ingested_at,:ts,:service,:level,:event,:request_id,"
            ":user_id,:device_id,:source_file,:extra,:raw)"
        )
        with self._write_lock:
            conn = self._write_connection()
            conn.execute("BEGIN")
            try:
                conn.executemany(sql, rows)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, args: list) -> list[dict]:
        return [dict(r) for r in self._read_connection().execute(sql, args).fetchall()]

    def scalar(self, sql: str, args: list):
        row = self._read_connection().execute(sql, args).fetchone()
        return row[0] if row else 0

    def execute(self, sql: str, args: list) -> int:
        with self._write_lock:
            return self._write_connection().execute(sql, args).rowcount

    def stats(self) -> dict:
        c        = self._read_connection()
        total    = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        earliest = c.execute("SELECT MIN(ts) FROM logs").fetchone()[0]
        latest   = c.execute("SELECT MAX(ts) FROM logs").fetchone()[0]
        svcs     = c.execute("SELECT COUNT(DISTINCT service) FROM logs").fetchone()[0]
        lvls     = {r[0]: r[1] for r in c.execute("SELECT level, COUNT(*) FROM logs GROUP BY level")}
        db_size  = os.path.getsize(self._path) if os.path.exists(self._path) else 0
        return {
            "total_logs": total, "earliest": earliest, "latest": latest,
            "services": svcs, "levels": lvls, "db_size_bytes": db_size,
        }

        # ─────────────────────────────────────────────────────────────────────────────
    # PATCH 3 — delete_before: AND instead of OR to prevent premature purge
    # Replace the existing delete_before method in the DB class.
    # ─────────────────────────────────────────────────────────────────────────────
    
    # Inside class DB:
    def delete_before(self, cutoff: str) -> int:
        # Use AND so a record is only deleted when BOTH timestamps are old.
        # With OR, a log that has a recent ts but an old ingested_at is
        # incorrectly purged, and vice-versa.
        return self.execute(
            "DELETE FROM logs WHERE ts < ? AND ingested_at < ?", [cutoff, cutoff]
        )
 

    def rebuild_fts(self):
        with self._write_lock:
            self._write_connection().execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
        logger.info("FTS index rebuild complete.")

    def wal_checkpoint(self):
        with self._write_lock:
            self._write_connection().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        logger.info("WAL checkpoint (TRUNCATE) complete.")

    def saved_query_save(self, name: str, query: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            self._write_connection().execute(
                "INSERT INTO saved_queries (name, query_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET query_json=excluded.query_json, updated_at=excluded.updated_at",
                [name, json.dumps(query), now, now],
            )

    def saved_query_load(self, name: str) -> Optional[dict]:
        now = datetime.now(timezone.utc).isoformat()
        row = self._read_connection().execute(
            "SELECT query_json FROM saved_queries WHERE name = ?", [name]
        ).fetchone()
        if not row:
            return None
        with self._write_lock:
            self._write_connection().execute(
                "UPDATE saved_queries SET run_count = run_count + 1, last_run_at = ? WHERE name = ?",
                [now, name],
            )
        return json.loads(row[0])

    def saved_query_list(self) -> list[dict]:
        return [
            dict(r) for r in self._read_connection().execute(
                "SELECT name, created_at, updated_at, run_count, last_run_at "
                "FROM saved_queries ORDER BY updated_at DESC"
            ).fetchall()
        ]

    def saved_query_delete(self, name: str) -> bool:
        return self.execute("DELETE FROM saved_queries WHERE name = ?", [name]) > 0

    def aggregate(self, interval: str, filters: dict,
                  ts_from: Optional[str], ts_to: Optional[str]) -> list[dict]:
        fmt = _INTERVAL_FMT.get(interval, "%Y-%m-%dT%H")
        clauses, args = _base_where_clauses(filters)
        if ts_from:
            clauses.append("COALESCE(ts, ingested_at) >= ?"); args.append(ts_from)
        if ts_to:
            clauses.append("COALESCE(ts, ingested_at) <= ?"); args.append(ts_to)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT strftime('{fmt}', COALESCE(ts, ingested_at)) AS bucket, "
            f"COUNT(*) AS total, "
            f"SUM(CASE WHEN level IN ('ERROR','CRITICAL','FATAL') THEN 1 ELSE 0 END) AS errors, "
            f"service "
            f"FROM logs {where} GROUP BY bucket, service ORDER BY bucket ASC"
        )
        raw = [dict(r) for r in self._read_connection().execute(sql, args).fetchall()]
        if interval in ("5m", "15m"):
            raw = _rebucket(raw, 5 if interval == "5m" else 15)
        buckets: dict[str, dict] = {}
        for row in raw:
            b = row["bucket"]
            if b not in buckets:
                buckets[b] = {"bucket": b, "total": 0, "errors": 0, "by_service": {}}
            buckets[b]["total"]  += row["total"]
            buckets[b]["errors"] += row["errors"]
            svc = row["service"]
            buckets[b]["by_service"][svc] = buckets[b]["by_service"].get(svc, 0) + row["total"]
        result = []
        for b, d in sorted(buckets.items()):
            t = d["total"]; e = d["errors"]
            result.append({"bucket": b, "total": t, "errors": e,
                           "error_rate": round(e / t, 4) if t else 0.0,
                           "by_service": d["by_service"]})
        return result

    def top_n(self, field: str, filters: dict, limit: int) -> list[dict]:
        _ALLOWED = {"event", "service", "user_id", "request_id", "device_id", "level"}
        if field not in _ALLOWED:
            raise ValueError(f"field must be one of {sorted(_ALLOWED)}")
        clauses, args = _base_where_clauses(filters)
        clauses.append(f"{field} IS NOT NULL")
        where = "WHERE " + " AND ".join(clauses)
        sql = (
            f"SELECT {field} AS value, COUNT(*) AS total, "
            f"SUM(CASE WHEN level IN ('ERROR','CRITICAL','FATAL') THEN 1 ELSE 0 END) AS errors "
            f"FROM logs {where} GROUP BY {field} ORDER BY total DESC LIMIT ?"
        )
        rows = [dict(r) for r in self._read_connection().execute(sql, args + [limit]).fetchall()]
        for r in rows:
            r["error_rate"] = round(r["errors"] / r["total"], 4) if r["total"] else 0.0
        return rows

    def histogram(self, interval: str, filters: dict,
                  ts_from: Optional[str], ts_to: Optional[str]) -> list[dict]:
        fmt = _INTERVAL_FMT.get(interval, "%Y-%m-%dT%H")
        clauses, args = _base_where_clauses(filters)
        if ts_from:
            clauses.append("COALESCE(ts, ingested_at) >= ?"); args.append(ts_from)
        if ts_to:
            clauses.append("COALESCE(ts, ingested_at) <= ?"); args.append(ts_to)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT strftime('{fmt}', COALESCE(ts, ingested_at)) AS bucket, "
            f"level, COUNT(*) AS count "
            f"FROM logs {where} GROUP BY bucket, level ORDER BY bucket ASC"
        )
        raw = [dict(r) for r in self._read_connection().execute(sql, args).fetchall()]
        if interval in ("5m", "15m"):
            raw = _rebucket(raw, 5 if interval == "5m" else 15)
        buckets: dict[str, dict] = {}
        for row in raw:
            b = row["bucket"]
            if b not in buckets:
                buckets[b] = {"bucket": b, "total": 0, "by_level": {}}
            buckets[b]["by_level"][row["level"]] = (
                buckets[b]["by_level"].get(row["level"], 0) + row["count"]
            )
            buckets[b]["total"] += row["count"]
        return [{"bucket": b, "total": d["total"], "by_level": d["by_level"]}
                for b, d in sorted(buckets.items())]

    def export_to_file(self, filters: dict, fmt: str, limit: int) -> str:
        sql_q, args = build_sql(filters, limit=limit, offset=0, order="asc")
        rows = self.query(sql_q, args)
        os.makedirs(EXPORT_TMP_DIR, exist_ok=True)
        suffix = ".jsonl" if fmt == "jsonl" else ".csv"
        fd, path = tempfile.mkstemp(prefix="logexport_", suffix=suffix, dir=EXPORT_TMP_DIR)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                if fmt == "jsonl":
                    for row in rows:
                        fh.write(json.dumps(row) + "\n")
                else:
                    if rows:
                        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                        writer.writeheader()
                        writer.writerows(rows)
        except Exception:
            os.unlink(path)
            raise
        return path

    def incremental_vacuum(self, pages: int = 1000):
        with self._write_lock:
            self._write_connection().execute(f"PRAGMA incremental_vacuum({pages})")
        logger.info(f"Incremental vacuum ({pages} pages) complete.")

    def close(self):
        with self._write_lock:
            if self._write_conn:
                self._write_conn.close()
                self._write_conn = None
        if getattr(self._read_local, "conn", None):
            self._read_local.conn.close()
            self._read_local.conn = None


# ==================== TIMESTAMP NORMALISATION ====================

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 2 — _normalize_ts: handle millisecond Unix timestamps
# Replace the existing _normalize_ts function with this version.
# ─────────────────────────────────────────────────────────────────────────────
 
def _normalize_ts(value, fallback: str) -> str:
    if value is None:
        return fallback
    if isinstance(value, (int, float)):
        try:
            # Detect millisecond timestamps (> year 2001 in ms = 1e12)
            ts_sec = value / 1000.0 if value > 1e10 else value
            return datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return fallback
    if isinstance(value, str):
        return value
    return fallback


# ==================== ANALYTICS HELPERS ====================

def _base_where_clauses(filters: dict) -> tuple[list[str], list]:
    clauses, args = [], []
    if "service" in filters:
        v = filters["service"]
        if isinstance(v, list):
            clauses.append(f"service IN ({','.join('?' * len(v))})"); args.extend(v)
        else:
            clauses.append("service = ?"); args.append(v)
    if "level" in filters:
        v = filters["level"]
        if isinstance(v, list):
            v = [x.upper() for x in v]
            clauses.append(f"level IN ({','.join('?' * len(v))})"); args.extend(v)
        else:
            clauses.append("level = ?"); args.append(v.upper())
    elif "level_gte" in filters:
        threshold = _LEVEL_SEVERITY.get(filters["level_gte"].upper(), 0)
        lvls = [l for l, s in _LEVEL_SEVERITY.items() if s >= threshold]
        if lvls:
            clauses.append(f"level IN ({','.join('?' * len(lvls))})"); args.extend(lvls)
    for col in ("request_id", "user_id", "device_id"):
        if col in filters:
            clauses.append(f"{col} = ?"); args.append(filters[col])
    return clauses, args


def _rebucket(rows: list[dict], step_mins: int) -> list[dict]:
    out: dict[str, dict] = {}
    for row in rows:
        bucket_str = row.get("bucket") or ""
        try:
            dt = datetime.fromisoformat(bucket_str + ":00")
            floored_min = (dt.minute // step_mins) * step_mins
            key = dt.replace(minute=floored_min, second=0).strftime("%Y-%m-%dT%H:%M")
        except (ValueError, AttributeError):
            key = bucket_str

        if key not in out:
            out[key] = {k: v for k, v in row.items()}
            out[key]["bucket"] = key
        else:
            for k, v in row.items():
                if k == "bucket":
                    continue
                if isinstance(v, (int, float)):
                    out[key][k] = out[key].get(k, 0) + v
                else:
                    out[key].setdefault(k, v)
    return list(out.values())


# ==================== QUERY BUILDER ====================

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 1 — build_sql: add log_id / log_ids filter support
# Replace the existing build_sql function with this version.
# ─────────────────────────────────────────────────────────────────────────────
 
def build_sql(filters: dict, limit=100, offset=0, order="desc",
              count_only=False, delete=False):
    clauses, args = [], []
    use_fts  = False
    fts_term = None
 
    # ── NEW: single-ID and multi-ID targeting ──────────────────────────────
    if "log_id" in filters:
        clauses.append("id = ?")
        args.append(filters["log_id"])
 
    if "log_ids" in filters:
        ids = [i for i in filters["log_ids"] if i]   # drop empty strings
        if ids:
            clauses.append(f"id IN ({','.join('?' * len(ids))})")
            args.extend(ids)
    # ──────────────────────────────────────────────────────────────────────
 
    if "service" in filters:
        v = filters["service"]
        if isinstance(v, list):
            clauses.append(f"service IN ({','.join('?' * len(v))})"); args.extend(v)
        else:
            clauses.append("service = ?"); args.append(v)
 
    if "level" in filters:
        v = filters["level"]
        if isinstance(v, list):
            v = [x.upper() for x in v]
            clauses.append(f"level IN ({','.join('?' * len(v))})"); args.extend(v)
        else:
            clauses.append("level = ?"); args.append(v.upper())
    elif "level_gte" in filters:
        threshold = _LEVEL_SEVERITY.get(filters["level_gte"].upper(), 0)
        lvls = [l for l, s in _LEVEL_SEVERITY.items() if s >= threshold]
        if lvls:
            clauses.append(f"level IN ({','.join('?' * len(lvls))})"); args.extend(lvls)
 
    for col in ("ts_from", "ts_to"):
        if col in filters:
            op = ">=" if col == "ts_from" else "<="
            clauses.append(f"ts {op} ?"); args.append(filters[col])
 
    for col in ("request_id", "user_id", "device_id"):
        if col in filters:
            clauses.append(f"{col} = ?"); args.append(filters[col])
 
    if "event_contains" in filters:
        use_fts  = True
        fts_term = filters["event_contains"].replace('"', '""')
 
    dir_ = "ASC" if order.lower() == "asc" else "DESC"
    order_expr = f"COALESCE(ts, ingested_at) {dir_}"
 
    if delete:
        if use_fts:
            extra_and = ("AND " + " AND ".join(clauses)) if clauses else ""
            sql = (
                f"DELETE FROM logs WHERE rowid IN "
                f"(SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?) "
                f"{extra_and}"
            )
            return sql, [fts_term] + args
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return f"DELETE FROM logs {where}", args
 
    if use_fts:
        extra_and = ("AND " + " AND ".join(clauses)) if clauses else ""
        if count_only:
            sql = (
                f"SELECT COUNT(*) FROM logs "
                f"WHERE rowid IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?) "
                f"{extra_and}"
            )
            return sql, [fts_term] + args
        sql = (
            f"SELECT id,ingested_at,ts,service,level,event,request_id,"
            f"user_id,device_id,source_file,extra "
            f"FROM logs "
            f"WHERE rowid IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?) "
            f"{extra_and} ORDER BY {order_expr} LIMIT ? OFFSET ?"
        )
        return sql, [fts_term] + args + [limit, offset]
 
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    if count_only:
        return f"SELECT COUNT(*) FROM logs {where}", args
 
    sql = (
        f"SELECT id,ingested_at,ts,service,level,event,request_id,"
        f"user_id,device_id,source_file,extra "
        f"FROM logs {where} ORDER BY {order_expr} LIMIT ? OFFSET ?"
    )
    return sql, args + [limit, offset]
 

# ==================== WATCHER ====================

def _service_name(path: str) -> str:
    p      = Path(path)
    parent = p.parent.name
    if parent not in ("logs", "log", "."):
        return parent
    stem = p.name
    for sfx in (".log", ".jsonl", ".json", ".txt"):
        if stem.endswith(sfx):
            stem = stem[: -len(sfx)]
    return stem or "unknown"


class _FileTailer:
    def __init__(self, path: str, ingest_fn, read_existing: bool = True,
                 existing_tail_lines: int = 200):
        self.path    = path
        self.service = _service_name(path)
        self._ingest = ingest_fn
        self._lock   = threading.Lock()
        try:
            stat        = os.stat(path)
            self._inode = stat.st_ino
            if read_existing and stat.st_size > 0:
                self._pos = 0
                self._read_tail_lines(existing_tail_lines)
            else:
                self._pos = stat.st_size
        except OSError:
            self._pos = 0
            self._inode = None

    def _read_tail_lines(self, n: int):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                if size == 0:
                    self._pos = 0
                    return
                CHUNK = 65536
                newlines_found = 0
                scan_pos = size
                target_offset = 0
                while scan_pos > 0 and newlines_found <= n:
                    read_start = max(0, scan_pos - CHUNK)
                    fh.seek(read_start)
                    block    = fh.read(scan_pos - read_start)
                    scan_pos = read_start
                    for i in range(len(block) - 1, -1, -1):
                        if block[i] == ord(b"\n"):
                            newlines_found += 1
                            if newlines_found == n + 1:
                                target_offset = read_start + i + 1
                                break
                    else:
                        continue
                    break
                fh.seek(target_offset)
                raw = fh.read()
                self._pos = size
            lines = raw.decode("utf-8", errors="replace").splitlines()
            for line in lines[-n:]:
                line = line.strip()
                if line:
                    self._ingest(line, self.path, self.service)
        except OSError:
            pass

    def read_new(self):
        with self._lock:
            try:
                stat = os.stat(self.path)
            except OSError:
                return
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                self._pos   = 0
                self._inode = stat.st_ino
            if stat.st_size == self._pos:
                return
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(self._pos)
                    while True:
                        chunk = fh.read(10 * 1024 * 1024)
                        if not chunk:
                            break
                        self._pos = fh.tell()
                        for line in chunk.decode("utf-8", errors="replace").splitlines():
                            line = line.strip()
                            if line:
                                self._ingest(line, self.path, self.service)
            except OSError:
                return


def _is_trackable(path: str) -> bool:
    p = Path(path)
    if any(s in IGNORE_SUFFIXES for s in p.suffixes):
        return False
    return p.suffix.lower() in WATCH_EXTENSIONS


class LogWatcher(FileSystemEventHandler):
    def __init__(self, ingest_fn):
        super().__init__()
        self._ingest  = ingest_fn
        self._tailers: dict[str, _FileTailer] = {}
        self._lock    = threading.Lock()

    def _tailer(self, path: str) -> Optional[_FileTailer]:
        if not _is_trackable(path):
            return None
        with self._lock:
            if path not in self._tailers:
                self._tailers[path] = _FileTailer(path, self._ingest, read_existing=True)
                logger.info(f"Tracking: {path}")
            return self._tailers.get(path)

    def on_created(self, e):
        if not e.is_directory:
            t = self._tailer(e.src_path)
            if t:
                t.read_new()

    def on_modified(self, e):
        if not e.is_directory:
            t = self._tailer(e.src_path)
            if t:
                t.read_new()


# ==================== LOG SERVICE ====================

class LogService:
    def __init__(self):
        self.db = DB(DB_PATH)

        self._write_queue: asyncio.Queue
        self._buf_lock    = threading.Lock()
        self._buf: list[dict] = []
        self._dropped_count   = 0

        self._tail_subs: list[asyncio.Queue] = []
        self._tail_lock = asyncio.Lock()
        self._stop      = asyncio.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        self._conn_sem: asyncio.Semaphore

        self._metrics = {
            "ingest_total":         0,
            "flush_total":          0,
            "flush_rows_total":     0,
            "flush_errors":         0,
            "last_flush_size":      0,
            "last_flush_ts":        None,
            "connections_total":    0,
            "connections_rejected": 0,
        }
        self._ingest_window: deque = deque()

    def ingest(self, raw: str, source_file: str, service: str):
        rec = self._parse(raw, source_file, service)
        if rec is None:
            return
        with self._buf_lock:
            if len(self._buf) >= MAX_BUFFER_HARD_CAP:
                self._buf.pop(0)
                self._dropped_count += 1
                if self._dropped_count % 1000 == 1:
                    logger.warning(
                        f"ingest_buffer_overflow: dropped {self._dropped_count} records; "
                        f"DB may be unavailable."
                    )
            self._buf.append(rec)
            self._metrics["ingest_total"] += 1
            now_mono = time.monotonic()
            self._ingest_window.append(now_mono)
            cutoff = now_mono - 60.0
            while self._ingest_window and self._ingest_window[0] < cutoff:
                self._ingest_window.popleft()

        if self._loop:
            self._loop.call_soon_threadsafe(self._notify_writer)
            with self._buf_lock:
                buf_len = len(self._buf)
            if buf_len >= BUFFER_SIZE:
                self._loop.call_soon_threadsafe(self._trigger_immediate_flush)
            if self._tail_subs:
                self._loop.call_soon_threadsafe(self._broadcast, rec)

    def _notify_writer(self):
        try:
            self._write_queue.put_nowait(True)
        except asyncio.QueueFull:
            pass

    def _trigger_immediate_flush(self):
        with self._buf_lock:
            if not self._buf:
                return
            batch, self._buf = self._buf[:], []
        asyncio.ensure_future(self._flush_batch(batch))

    def _parse(self, line: str, source_file: str, service: str) -> Optional[dict]:
        now = datetime.now(timezone.utc).isoformat()
        rec = dict(
            id=str(uuid.uuid4()), ingested_at=now, ts=now,
            service=service, level="INFO", event=None,
            request_id=None, user_id=None, device_id=None,
            source_file=source_file, extra=None, raw=line,
        )
        if line and line[0] == "{":
            try:
                obj = json.loads(line)
                raw_ts    = obj.get("ts") or obj.get("timestamp") or obj.get("time")
                rec["ts"]     = _normalize_ts(raw_ts, now)
                rec["level"]  = (obj.get("level") or obj.get("severity") or "INFO").upper()
                rec["event"]  = obj.get("event") or obj.get("message") or obj.get("msg")
                rec["request_id"] = obj.get("request_id")
                rec["user_id"]    = obj.get("user_id")
                rec["device_id"]  = obj.get("device_id")
                if obj.get("service"):
                    rec["service"] = obj["service"]
                known = {
                    "ts", "timestamp", "time", "level", "severity",
                    "event", "message", "msg", "request_id",
                    "user_id", "device_id", "service",
                }
                extra        = {k: v for k, v in obj.items() if k not in known}
                rec["extra"] = json.dumps(extra) if extra else None
            except (json.JSONDecodeError, ValueError):
                rec["event"] = line
        else:
            rec["event"] = line
        return rec

    async def _flush_batch(self, batch: list[dict]):
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, self.db.bulk_insert, batch
            )
            now_iso = datetime.now(timezone.utc).isoformat()
            with self._buf_lock:
                self._metrics["flush_total"]     += 1
                self._metrics["flush_rows_total"] += len(batch)
                self._metrics["last_flush_size"]  = len(batch)
                self._metrics["last_flush_ts"]    = now_iso
        except Exception:
            logger.exception("flush_error")
            with self._buf_lock:
                self._metrics["flush_errors"] += 1
                combined = batch + self._buf
                overflow = max(0, len(combined) - MAX_BUFFER_HARD_CAP)
                if overflow:
                    combined             = combined[overflow:]
                    self._dropped_count += overflow
                    logger.warning(f"Re-queue overflow: dropped {overflow} records.")
                self._buf = combined

    async def _writer_loop(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._write_queue.get(), timeout=FLUSH_INTERVAL)
            except asyncio.TimeoutError:
                pass
            with self._buf_lock:
                if not self._buf:
                    continue
                batch, self._buf = self._buf[:], []
            await self._flush_batch(batch)

    async def _retention_loop(self):
        while not self._stop.is_set():
            await asyncio.sleep(6 * 3600)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
            n = await asyncio.get_running_loop().run_in_executor(
                None, self.db.delete_before, cutoff
            )
            logger.info(f"Retention purge: {n} rows deleted before {cutoff}")
            await asyncio.get_running_loop().run_in_executor(
                None, self.db.incremental_vacuum, 1000
            )

    async def _fts_rebuild_loop(self):
        while not self._stop.is_set():
            await asyncio.sleep(24 * 3600)
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, self.db.rebuild_fts
                )
            except Exception:
                logger.exception("fts_rebuild_error")

    async def _wal_checkpoint_loop(self):
        while not self._stop.is_set():
            await asyncio.sleep(4 * 3600)
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, self.db.wal_checkpoint
                )
            except Exception:
                logger.exception("wal_checkpoint_error")

    def _broadcast(self, rec: dict):
        dead = []
        for q in list(self._tail_subs):
            try:
                q.put_nowait(rec)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            try:
                self._tail_subs.remove(q)
                logger.warning("tail_subscriber_dropped: slow consumer ejected (queue full).")
            except ValueError:
                pass

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self._conn_sem._value == 0:
            with self._buf_lock:
                self._metrics["connections_rejected"] += 1
            try:
                writer.write(json.dumps({"error": "too_many_connections"}).encode())
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            return

        async with self._conn_sem:
            with self._buf_lock:
                self._metrics["connections_total"] += 1
            try:
                raw = await asyncio.wait_for(reader.read(65536), timeout=30)
                if not raw:
                    return
                req    = json.loads(raw.decode())
                action = req.get("action", "")
                resp   = await self._dispatch(action, req, writer)
                if resp is not None:
                    writer.write(json.dumps(resp).encode())
                    await writer.drain()
            except asyncio.TimeoutError:
                writer.write(json.dumps({"error": "timeout"}).encode())
                await writer.drain()
            except Exception:
                logger.exception("handler_error")
                try:
                    writer.write(json.dumps({"error": "internal_error"}).encode())
                    await writer.drain()
                except Exception:
                    pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
                except Exception:
                    logger.debug("writer_close_error", exc_info=True)

    async def _dispatch(self, action: str, req: dict, writer) -> Optional[dict]:
        loop = asyncio.get_running_loop()

        if action == "ping":
            return {"status": "pong", "ts": datetime.now(timezone.utc).isoformat()}

        if action == "status":
            s = await loop.run_in_executor(None, self.db.stats)
            s.update({
                "buffer_pending":   len(self._buf),
                "dropped_records":  self._dropped_count,
                "tail_subscribers": len(self._tail_subs),
                "retention_days":   RETENTION_DAYS,
            })
            return {"status": "ok", **s}

        if action == "metrics":
            return await self._build_metrics(loop)

        if action == "services":
            rows = await loop.run_in_executor(
                None, self.db.query,
                "SELECT DISTINCT service FROM logs ORDER BY service", []
            )
            return {"status": "ok", "services": [r["service"] for r in rows]}

        if action == "query":
            filters = req.get("filters", {})
            limit   = min(int(req.get("limit", 100)), MAX_ROWS)
            offset  = int(req.get("offset", 0))
            order   = req.get("order", "desc")
            sql, args = build_sql(filters, limit, offset, order)
            rows = await loop.run_in_executor(None, self.db.query, sql, args)
            return {"status": "ok", "count": len(rows), "rows": rows}

        if action == "count":
            filters   = req.get("filters", {})
            sql, args = build_sql(filters, count_only=True)
            count     = await loop.run_in_executor(None, self.db.scalar, sql, args)
            return {"status": "ok", "count": count}

        if action == "delete":
            filters = req.get("filters", {})
            if not filters:
                return {"error": "filters_required"}
            sql, args = build_sql(filters, delete=True)
            deleted   = await loop.run_in_executor(None, self.db.execute, sql, args)
            return {"status": "ok", "deleted": deleted}

        if action == "tail":
            await self._stream_tail(req, writer)
            return None

        if action == "aggregate":
            interval = req.get("interval", "1h")
            filters  = req.get("filters", {})
            ts_from  = req.get("ts_from")
            ts_to    = req.get("ts_to")
            if interval not in _INTERVAL_FMT:
                return {"error": f"interval must be one of {sorted(_INTERVAL_FMT)}"}
            rows = await loop.run_in_executor(
                None, self.db.aggregate, interval, filters, ts_from, ts_to
            )
            return {"status": "ok", "interval": interval, "buckets": len(rows), "data": rows}

        if action == "top":
            field   = req.get("field", "event")
            filters = req.get("filters", {})
            limit   = min(int(req.get("limit", 10)), 1000)
            try:
                rows = await loop.run_in_executor(
                    None, self.db.top_n, field, filters, limit
                )
            except ValueError as e:
                return {"error": str(e)}
            return {"status": "ok", "field": field, "count": len(rows), "data": rows}

        if action == "histogram":
            interval = req.get("interval", "1h")
            filters  = req.get("filters", {})
            ts_from  = req.get("ts_from")
            ts_to    = req.get("ts_to")
            if interval not in _INTERVAL_FMT:
                return {"error": f"interval must be one of {sorted(_INTERVAL_FMT)}"}
            rows = await loop.run_in_executor(
                None, self.db.histogram, interval, filters, ts_from, ts_to
            )
            return {"status": "ok", "interval": interval, "buckets": len(rows), "data": rows}

        if action == "saved_query":
            op   = req.get("op", "")
            name = req.get("name", "").strip()
            if op == "save":
                if not name:
                    return {"error": "name required"}
                query = req.get("query")
                if not isinstance(query, dict):
                    return {"error": "query (dict) required"}
                await loop.run_in_executor(None, self.db.saved_query_save, name, query)
                return {"status": "ok", "saved": name}
            if op == "load":
                if not name:
                    return {"error": "name required"}
                q = await loop.run_in_executor(None, self.db.saved_query_load, name)
                if q is None:
                    return {"error": "not_found"}
                return {"status": "ok", "name": name, "query": q}
            if op == "list":
                items = await loop.run_in_executor(None, self.db.saved_query_list)
                return {"status": "ok", "count": len(items), "queries": items}
            if op == "delete":
                if not name:
                    return {"error": "name required"}
                ok = await loop.run_in_executor(None, self.db.saved_query_delete, name)
                return {"status": "ok", "deleted": ok}
            return {"error": "op must be save|load|list|delete"}

        if action == "export":
            filters = req.get("filters", {})
            fmt     = req.get("format", "jsonl").lower()
            if fmt not in ("jsonl", "csv"):
                return {"error": "format must be jsonl or csv"}
            limit = min(int(req.get("limit", 10000)), EXPORT_MAX_ROWS)
            try:
                path = await loop.run_in_executor(
                    None, self.db.export_to_file, filters, fmt, limit
                )
            except Exception as e:
                logger.exception("export_error")
                return {"error": f"export_failed: {e}"}
            size = os.path.getsize(path)
            return {
                "status": "ready",
                "path":   path,
                "format": fmt,
                "rows":   limit,
                "size_bytes": size,
            }

        return {"error": "unknown_action"}

    async def _build_metrics(self, loop) -> dict:
        db_stats = await loop.run_in_executor(None, self.db.stats)
        with self._buf_lock:
            m          = dict(self._metrics)
            buf_depth  = len(self._buf)
            dropped    = self._dropped_count
            window_len = len(self._ingest_window)

        ingest_rate_per_sec = round(window_len / 60.0, 2)
        avg_flush_size = (
            round(m["flush_rows_total"] / m["flush_total"], 1)
            if m["flush_total"] > 0 else 0
        )
        return {
            "status":               "ok",
            "ingest_total":         m["ingest_total"],
            "ingest_rate_per_sec":  ingest_rate_per_sec,
            "buffer_depth":         buf_depth,
            "dropped_records":      dropped,
            "flush_total":          m["flush_total"],
            "flush_rows_total":     m["flush_rows_total"],
            "avg_flush_size":       avg_flush_size,
            "last_flush_size":      m["last_flush_size"],
            "last_flush_ts":        m["last_flush_ts"],
            "flush_errors":         m["flush_errors"],
            "connections_total":    m["connections_total"],
            "connections_rejected": m["connections_rejected"],
            "tail_subscribers":     len(self._tail_subs),
            "db_size_bytes":        db_stats.get("db_size_bytes", 0),
            "db_total_logs":        db_stats.get("total_logs", 0),
            "ts":                   datetime.now(timezone.utc).isoformat(),
        }

    async def _stream_tail(self, req: dict, writer):
        timeout = int(req.get("timeout", 60))
        service = req.get("service")
        level   = req.get("level")
        q: asyncio.Queue = asyncio.Queue(maxsize=500)

        async with self._tail_lock:
            self._tail_subs.append(q)

        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    rec = await asyncio.wait_for(q.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    writer.write(b"\n")
                    await writer.drain()
                    continue
                if service and rec.get("service") != service:
                    continue
                if level and rec.get("level") != level.upper():
                    continue
                writer.write((json.dumps(rec) + "\n").encode())
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            async with self._tail_lock:
                if q in self._tail_subs:
                    self._tail_subs.remove(q)

    async def run(self):
        self._loop        = asyncio.get_running_loop()
        self._write_queue = asyncio.Queue(maxsize=1)
        self._conn_sem    = asyncio.Semaphore(MAX_CONNECTIONS)

        self.db.init()

        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        n = self.db.delete_before(cutoff)
        if n:
            logger.info(f"Startup retention: purged {n} old rows")

        handler  = LogWatcher(ingest_fn=self.ingest)
        observer = Observer()
        for d in LOG_DIRS:
            p = Path(d.strip())
            p.mkdir(parents=True, exist_ok=True)
            observer.schedule(handler, str(p), recursive=True)
            logger.info(f"Watching: {p}")
            for existing in p.rglob("*"):
                if existing.is_file() and _is_trackable(str(existing)):
                    handler._tailer(str(existing))
        observer.start()

        asyncio.create_task(self._writer_loop())
        asyncio.create_task(self._retention_loop())
        asyncio.create_task(self._fts_rebuild_loop())
        asyncio.create_task(self._wal_checkpoint_loop())

        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)
        os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)

        server = await asyncio.start_unix_server(self.handle, path=SOCKET_PATH)
        os.chmod(SOCKET_PATH, SOCKET_PERMS)

        logger.info(f"Log service started | socket={SOCKET_PATH} | db={DB_PATH}")

        async with server:
            await self._stop.wait()

        logger.info("Shutting down…")
        observer.stop()
        observer.join()

        with self._buf_lock:
            remaining, self._buf = self._buf[:], []
        if remaining:
            self.db.bulk_insert(remaining)

        self.db.close()
        logger.info("Log service stopped.")

    def stop(self):
        self._stop.set()


# ==================== ENTRY POINT ====================

async def main():
    svc  = LogService()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig,
            lambda s=sig: (logger.info(f"Signal {s.name} received"), svc.stop()),
        )

    await svc.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        logger.exception("log_service_crash")
