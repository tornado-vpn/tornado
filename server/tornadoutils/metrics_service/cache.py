# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

# cache.py
import threading

_lock = threading.Lock()
_latest = {}

def set_latest(data: dict):
    with _lock:
        _latest.clear()
        _latest.update(data)

def get_latest() -> dict:
    with _lock:
        return dict(_latest)
