# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

# main.py
from fastapi import FastAPI
from aggregator import get_live, get_last_1h, get_last_24h, run_aggregator
import threading
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="Tornado Metrics Service")

origins = [
    "*",  # Allow all origins (good for testing, can restrict later)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,      # Allow these origins
    allow_credentials=True,
    allow_methods=["*"],        # Allow all HTTP methods
    allow_headers=["*"],        # Allow all headers
)

# ================= Start Aggregator in Background =================
agg_thread = threading.Thread(target=run_aggregator, daemon=True)
agg_thread.start()
# ===================================================================

@app.get("/api/metrics/live")
async def live_metrics():
    """Return real-time metrics."""
    return get_live()


@app.get("/api/metrics/last_1h")
async def last_1h_metrics():
    """Return aggregated metrics for last 1 hour."""
    return get_last_1h()


@app.get("/api/metrics/last_24h")
async def last_24h_metrics():
    """Return aggregated metrics for last 24 hours."""
    return get_last_24h()
