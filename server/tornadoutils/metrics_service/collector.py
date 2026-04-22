# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

# collector.py
import time
import psutil
from cache import set_latest
from storage import insert_raw_metric

INTERVAL = 5  # seconds
_prev_net = None

def collect_loop():
    global _prev_net

    while True:
        ts = int(time.time())  # ✅ exact timestamp (NOT minute-aligned)

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent

        net = psutil.net_io_counters()
        rx, tx = net.bytes_recv, net.bytes_sent

        # Convert counters → deltas
        if _prev_net:
            rx_delta = rx - _prev_net[0]
            tx_delta = tx - _prev_net[1]
        else:
            rx_delta = tx_delta = 0

        _prev_net = (rx, tx)

        metric = {
            "ts": ts,
            "cpu": cpu,
            "mem": mem,
            "disk": disk,
            "rx": rx_delta,  # bytes in last 5s
            "tx": tx_delta,
        }

        # Live cache
        set_latest(metric)

        # Persist raw metric
        insert_raw_metric(metric)

        time.sleep(INTERVAL)
