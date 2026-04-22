# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations
import asyncio, json, logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional, Union

logger = logging.getLogger(__name__)


SOCKET_PATH: str   = "/run/tornado/log.sock"
UDS_TIMEOUT: float = 10.0
READ_BUFFER: int   = 131_072   # 128 KiB

LogLevel  = Literal["DEBUG","INFO","WARNING","WARN","ERROR","CRITICAL","FATAL"]
Interval  = Literal["1m","5m","15m","1h","1d"]
TopField  = Literal["event","service","user_id","request_id","device_id","level"]
ExportFmt = Literal["jsonl","csv"]
SortOrder = Literal["asc","desc"]


# ── Exceptions ────────────────────────────────────────────────────────────────

class LogServiceError(Exception):
    """Microservice unreachable or returned an error payload."""

class LogServiceNotFound(LogServiceError):
    """Microservice returned ``"error": "not_found"``."""

class LogServiceValidationError(LogServiceError):
    """Microservice rejected the request (bad filters, missing fields …)."""


# ── Response dataclasses ──────────────────────────────────────────────────────

@dataclass
class PingResponse:
    status: str
    ts: str

@dataclass
class StatusResponse:
    total_logs: int; earliest: Optional[str]; latest: Optional[str]
    services: int; levels: dict; db_size_bytes: int
    buffer_pending: int; dropped_records: int
    tail_subscribers: int; retention_days: int
    raw: dict = field(default_factory=dict, repr=False)

@dataclass
class MetricsResponse:
    ingest_total: int; ingest_rate_per_sec: float; buffer_depth: int
    dropped_records: int; flush_total: int; flush_rows_total: int
    avg_flush_size: float; last_flush_size: int; last_flush_ts: Optional[str]
    flush_errors: int; connections_total: int; connections_rejected: int
    tail_subscribers: int; db_size_bytes: int; db_total_logs: int; ts: str
    raw: dict = field(default_factory=dict, repr=False)

@dataclass
class QueryResponse:
    count: int; rows: list

@dataclass
class CountResponse:
    count: int

@dataclass
class DeleteResponse:
    deleted: int

@dataclass
class AggregateBucket:
    bucket: str; total: int; errors: int; error_rate: float; by_service: dict

@dataclass
class AggregateResponse:
    interval: str; buckets: int; data: list

@dataclass
class HistogramBucket:
    bucket: str; total: int; by_level: dict

@dataclass
class HistogramResponse:
    interval: str; buckets: int; data: list

@dataclass
class TopEntry:
    value: Optional[str]; total: int; errors: int; error_rate: float

@dataclass
class TopResponse:
    field: str; count: int; data: list

@dataclass
class SavedQueryMeta:
    name: str; created_at: str; updated_at: str
    run_count: int; last_run_at: Optional[str]

@dataclass
class SavedQuerySaveResponse:
    saved: str

@dataclass
class SavedQueryLoadResponse:
    name: str; query: dict

@dataclass
class SavedQueryListResponse:
    count: int; queries: list

@dataclass
class SavedQueryDeleteResponse:
    deleted: bool

@dataclass
class ExportResponse:
    status: str; path: str; format: str; rows: int; size_bytes: int


# ── Transport primitive ───────────────────────────────────────────────────────

_VALIDATION_SENTINEL = frozenset({
    "filters_required", "name required", "query (dict) required",
    "op must be save|load|list|delete", "format must be jsonl or csv",
})

async def _uds_call(
    payload: dict,
    socket_path: str = SOCKET_PATH,
    timeout: float = UDS_TIMEOUT,
    read_buffer: int = READ_BUFFER,
) -> dict:
    """Send one JSON request over the Unix socket, return the parsed response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path), timeout=timeout
        )
    except FileNotFoundError as exc:
        raise LogServiceError(f"Socket not found: '{socket_path}'") from exc
    except ConnectionRefusedError as exc:
        raise LogServiceError(f"Connection refused: '{socket_path}'") from exc
    except asyncio.TimeoutError:
        raise LogServiceError("Timed out connecting to log service")

    try:
        writer.write(json.dumps(payload).encode())
        await writer.drain()
        
        # FIX: Read until the server closes the connection (EOF)
        # instead of a fixed-size chunk.
        chunks = []
        while True:
            chunk = await asyncio.wait_for(reader.read(READ_BUFFER), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        
        if not data:
            raise LogServiceError("Empty response from log service")
            
        result: dict = json.loads(data.decode())
    except asyncio.TimeoutError:
        raise LogServiceError("Timed out reading from log service")
    except json.JSONDecodeError as exc:
        raise LogServiceError(f"Malformed JSON response: {exc}") from exc
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass

    if "error" in result:
        err = result["error"]
        if err == "not_found":
            raise LogServiceNotFound(err)
        if err in _VALIDATION_SENTINEL or str(err).startswith("field must be"):
            raise LogServiceValidationError(err)
        raise LogServiceError(err)

    return result


# ── Filter builder ────────────────────────────────────────────────────────────

def _build_filters(
    service=None, level=None, level_gte=None,
    ts_from=None, ts_to=None, request_id=None,
    user_id=None, device_id=None, event_contains=None,
) -> dict:
    f: dict = {}
    if service       is not None: f["service"]       = service
    if level         is not None: f["level"]         = [v.upper() for v in level] if isinstance(level, list) else level.upper()
    if level_gte     is not None: f["level_gte"]     = level_gte.upper()
    if ts_from       is not None: f["ts_from"]       = ts_from.isoformat() if isinstance(ts_from, datetime) else ts_from
    if ts_to         is not None: f["ts_to"]         = ts_to.isoformat()   if isinstance(ts_to,   datetime) else ts_to
    if request_id    is not None: f["request_id"]    = request_id
    if user_id       is not None: f["user_id"]       = user_id
    if device_id     is not None: f["device_id"]     = device_id
    if event_contains is not None: f["event_contains"] = event_contains
    return f


# ── Health / connection ───────────────────────────────────────────────────────

async def ping(socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> PingResponse:
    raw = await _uds_call({"action": "ping"}, socket_path, timeout)
    return PingResponse(status=raw["status"], ts=raw["ts"])

async def status(socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> StatusResponse:
    raw = await _uds_call({"action": "status"}, socket_path, timeout)
    return StatusResponse(
        total_logs=raw.get("total_logs",0), earliest=raw.get("earliest"),
        latest=raw.get("latest"), services=raw.get("services",0),
        levels=raw.get("levels",{}), db_size_bytes=raw.get("db_size_bytes",0),
        buffer_pending=raw.get("buffer_pending",0),
        dropped_records=raw.get("dropped_records",0),
        tail_subscribers=raw.get("tail_subscribers",0),
        retention_days=raw.get("retention_days",30), raw=raw,
    )

async def metrics(socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> MetricsResponse:
    """Exposes the ``metrics`` action added in FIX #H of log_service.py."""
    raw = await _uds_call({"action": "metrics"}, socket_path, timeout)
    return MetricsResponse(
        ingest_total=raw.get("ingest_total",0),
        ingest_rate_per_sec=raw.get("ingest_rate_per_sec",0.0),
        buffer_depth=raw.get("buffer_depth",0),
        dropped_records=raw.get("dropped_records",0),
        flush_total=raw.get("flush_total",0),
        flush_rows_total=raw.get("flush_rows_total",0),
        avg_flush_size=raw.get("avg_flush_size",0.0),
        last_flush_size=raw.get("last_flush_size",0),
        last_flush_ts=raw.get("last_flush_ts"),
        flush_errors=raw.get("flush_errors",0),
        connections_total=raw.get("connections_total",0),
        connections_rejected=raw.get("connections_rejected",0),
        tail_subscribers=raw.get("tail_subscribers",0),
        db_size_bytes=raw.get("db_size_bytes",0),
        db_total_logs=raw.get("db_total_logs",0),
        ts=raw.get("ts",""), raw=raw,
    )

async def services(socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> list:
    raw = await _uds_call({"action": "services"}, socket_path, timeout)
    return raw.get("services", [])


# ── Query / count / delete ────────────────────────────────────────────────────

async def query_logs(
    filters=None, *, service=None, level=None, level_gte=None,
    ts_from=None, ts_to=None, request_id=None, user_id=None,
    device_id=None, event_contains=None,
    limit=100, offset=0, order="desc",
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT,
) -> QueryResponse:
    f = filters if filters is not None else _build_filters(
        service=service, level=level, level_gte=level_gte, ts_from=ts_from,
        ts_to=ts_to, request_id=request_id, user_id=user_id,
        device_id=device_id, event_contains=event_contains,
    )
    raw = await _uds_call(
        {"action":"query","filters":f,"limit":limit,"offset":offset,"order":order},
        socket_path, timeout,
    )
    return QueryResponse(count=raw.get("count",0), rows=raw.get("rows",[]))

async def count_logs(
    filters=None, *, service=None, level=None, level_gte=None,
    ts_from=None, ts_to=None, request_id=None, user_id=None,
    device_id=None, event_contains=None,
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT,
) -> CountResponse:
    f = filters if filters is not None else _build_filters(
        service=service, level=level, level_gte=level_gte, ts_from=ts_from,
        ts_to=ts_to, request_id=request_id, user_id=user_id,
        device_id=device_id, event_contains=event_contains,
    )
    raw = await _uds_call({"action":"count","filters":f}, socket_path, timeout)
    return CountResponse(count=raw.get("count",0))

async def delete_logs(filters: dict, socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> DeleteResponse:
    if not filters:
        raise LogServiceValidationError("At least one filter is required for delete")
    raw = await _uds_call({"action":"delete","filters":filters}, socket_path, timeout)
    return DeleteResponse(deleted=raw.get("deleted",0))


# ── Analytics ─────────────────────────────────────────────────────────────────

async def aggregate(
    interval="1h", filters=None, ts_from=None, ts_to=None,
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT,
) -> AggregateResponse:
    """FEAT #1 – time-series volume + error-rate bucketed by interval."""
    ts_from_s = ts_from.isoformat() if isinstance(ts_from, datetime) else ts_from
    ts_to_s   = ts_to.isoformat()   if isinstance(ts_to,   datetime) else ts_to
    raw = await _uds_call(
        {"action":"aggregate","interval":interval,
         "filters":filters or {},"ts_from":ts_from_s,"ts_to":ts_to_s},
        socket_path, timeout,
    )
    buckets = [AggregateBucket(bucket=b["bucket"],total=b["total"],
        errors=b["errors"],error_rate=b["error_rate"],
        by_service=b.get("by_service",{})) for b in raw.get("data",[])]
    return AggregateResponse(interval=raw.get("interval",interval),
                             buckets=len(buckets), data=buckets)

async def histogram(
    interval="1h", filters=None, ts_from=None, ts_to=None,
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT,
) -> HistogramResponse:
    """FEAT #3 – per-level volume histogram bucketed by interval."""
    ts_from_s = ts_from.isoformat() if isinstance(ts_from, datetime) else ts_from
    ts_to_s   = ts_to.isoformat()   if isinstance(ts_to,   datetime) else ts_to
    raw = await _uds_call(
        {"action":"histogram","interval":interval,
         "filters":filters or {},"ts_from":ts_from_s,"ts_to":ts_to_s},
        socket_path, timeout,
    )
    buckets = [HistogramBucket(bucket=b["bucket"],total=b["total"],
        by_level=b.get("by_level",{})) for b in raw.get("data",[])]
    return HistogramResponse(interval=raw.get("interval",interval),
                             buckets=len(buckets), data=buckets)

async def top_n(
    field="event", filters=None, limit=10,
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT,
) -> TopResponse:
    """FEAT #2 – top-N most frequent non-null values for field."""
    raw = await _uds_call(
        {"action":"top","field":field,"filters":filters or {},"limit":limit},
        socket_path, timeout,
    )
    entries = [TopEntry(value=e.get("value"),total=e["total"],
        errors=e["errors"],error_rate=e["error_rate"]) for e in raw.get("data",[])]
    return TopResponse(field=raw.get("field",field), count=len(entries), data=entries)


# ── Saved queries ─────────────────────────────────────────────────────────────

async def saved_query_save(name: str, query: dict,
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> SavedQuerySaveResponse:
    """FEAT #4 – persist a named query preset (upsert on duplicate name)."""
    if not name or not name.strip():
        raise LogServiceValidationError("name must not be empty")
    if not isinstance(query, dict):
        raise LogServiceValidationError("query must be a dict")
    raw = await _uds_call(
        {"action":"saved_query","op":"save","name":name,"query":query},
        socket_path, timeout,
    )
    return SavedQuerySaveResponse(saved=raw.get("saved", name))

async def saved_query_load(name: str, socket_path=SOCKET_PATH,
    timeout=UDS_TIMEOUT) -> SavedQueryLoadResponse:
    """Load by name; increments run_count. Raises LogServiceNotFound if missing."""
    if not name or not name.strip():
        raise LogServiceValidationError("name must not be empty")
    raw = await _uds_call({"action":"saved_query","op":"load","name":name},
                          socket_path, timeout)
    return SavedQueryLoadResponse(name=raw.get("name",name), query=raw.get("query",{}))

async def saved_query_list(socket_path=SOCKET_PATH,
    timeout=UDS_TIMEOUT) -> SavedQueryListResponse:
    """Return all presets ordered by most recently updated."""
    raw = await _uds_call({"action":"saved_query","op":"list"}, socket_path, timeout)
    queries = [SavedQueryMeta(name=q["name"],created_at=q["created_at"],
        updated_at=q["updated_at"],run_count=q["run_count"],
        last_run_at=q.get("last_run_at")) for q in raw.get("queries",[])]
    return SavedQueryListResponse(count=len(queries), queries=queries)

async def saved_query_delete(name: str, socket_path=SOCKET_PATH,
    timeout=UDS_TIMEOUT) -> SavedQueryDeleteResponse:
    """Delete a preset. Returns deleted=False (not an error) when name not found."""
    if not name or not name.strip():
        raise LogServiceValidationError("name must not be empty")
    raw = await _uds_call({"action":"saved_query","op":"delete","name":name},
                          socket_path, timeout)
    return SavedQueryDeleteResponse(deleted=bool(raw.get("deleted", False)))


# ── Export ────────────────────────────────────────────────────────────────────

async def export_logs(filters=None, fmt="jsonl", limit=10_000,
    socket_path=SOCKET_PATH, timeout=UDS_TIMEOUT) -> ExportResponse:
    """FEAT #5 – write matching rows to a temp file; return path for FastAPI to serve."""
    if fmt not in ("jsonl", "csv"):
        raise LogServiceValidationError("format must be 'jsonl' or 'csv'")
    raw = await _uds_call(
        {"action":"export","filters":filters or {},"format":fmt,"limit":limit},
        socket_path, timeout,
    )
    return ExportResponse(status=raw.get("status","ready"), path=raw.get("path",""),
        format=raw.get("format",fmt), rows=raw.get("rows",0),
        size_bytes=raw.get("size_bytes",0))


# ── Live tail  (async generator) ──────────────────────────────────────────────

async def tail_logs(
    service=None, level=None, timeout=60,
    socket_path=SOCKET_PATH, uds_timeout=UDS_TIMEOUT,
) -> AsyncGenerator:
    """
    Async generator yielding live log records as they arrive.

        async for record in tail_logs(service="api", level="ERROR", timeout=30):
            print(record["level"], record["event"])
    """
    payload: dict = {"action": "tail", "timeout": timeout}
    if service: payload["service"] = service
    if level:   payload["level"]   = level.upper()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path), timeout=uds_timeout
        )
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raise LogServiceError(f"Cannot connect for tail: {exc}") from exc
    except asyncio.TimeoutError:
        raise LogServiceError("Timed out connecting for tail")

    try:
        writer.write(json.dumps(payload).encode())
        await writer.drain()
        read_deadline = timeout + 10
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=read_deadline)
            except asyncio.TimeoutError:
                return
            if not line:
                return
            stripped = line.strip()
            if not stripped:
                continue           # heartbeat keep-alive
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError:
                continue
    except (ConnectionResetError, BrokenPipeError):
        return
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass


# ── Convenience wrappers ──────────────────────────────────────────────────────

async def query_by_user(user_id: str, limit=100,
    socket_path=SOCKET_PATH) -> QueryResponse:
    return await query_logs(filters={"user_id": user_id}, limit=limit,
                            socket_path=socket_path)

async def query_by_request(request_id: str,
    socket_path=SOCKET_PATH) -> QueryResponse:
    return await query_logs(filters={"request_id": request_id}, limit=500,
                            socket_path=socket_path)

async def query_errors(service=None, limit=100,
    socket_path=SOCKET_PATH) -> QueryResponse:
    f: dict = {"level_gte": "ERROR"}
    if service: f["service"] = service
    return await query_logs(filters=f, limit=limit, socket_path=socket_path)

async def query_range(ts_from, ts_to, service=None, limit=500,
    socket_path=SOCKET_PATH) -> QueryResponse:
    f: dict = {
        "ts_from": ts_from.isoformat() if isinstance(ts_from, datetime) else ts_from,
        "ts_to":   ts_to.isoformat()   if isinstance(ts_to,   datetime) else ts_to,
    }
    if service: f["service"] = service
    return await query_logs(filters=f, limit=limit, socket_path=socket_path)
