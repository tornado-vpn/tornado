# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# ================= CONFIG =================
SERVICE_NAME = "master"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_DIR = os.getenv("LOG_DIR", "/var/log/tornado")
LOG_FILE = os.path.join(LOG_DIR, f"{SERVICE_NAME}.log")
os.makedirs(LOG_DIR, exist_ok=True)


# ================= FORMATTER =================
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log = {
            "ts":      datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "service": SERVICE_NAME,
            "level":   record.levelname,
            "event":   record.getMessage(),
        }
        if hasattr(record, "extra_fields"):
            log.update(record.extra_fields)
        if record.exc_info:
            log["stack_trace"] = self.formatException(record.exc_info)
        return json.dumps(log)


# ================= LOGGER =================
def get_logger():
    logger = logging.getLogger(SERVICE_NAME)
    logger.setLevel(LOG_LEVEL)
    if not logger.handlers:
        stream = logging.StreamHandler()
        stream.setFormatter(JsonFormatter())
        logger.addHandler(stream)

        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)
    logger.propagate = False
    return logger


# ================= CONTEXT LOGGER =================
class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra        = kwargs.get("extra", {})
        extra_fields = extra.get("extra_fields", {})
        merged       = {**self.extra, **extra_fields}
        kwargs["extra"] = {"extra_fields": merged}
        return msg, kwargs


def get_context_logger(
    service_name: str = None,
    command:      str = None,
    target:       str = None,
    pid:          int = None,
):
    """
    Returns a ContextLoggerAdapter pre-seeded with master-relevant fields.

    Args:
        service_name: The child service being acted upon (e.g. "api", "worker").
        command:      Admin command being handled (e.g. "start", "stop", "restart").
        target:       Raw target string from the admin request (e.g. "all").
        pid:          PID of the child process, when known.
    """
    base_logger = get_logger()
    ctx = {}
    if service_name is not None:
        ctx["service_name"] = service_name
    if command is not None:
        ctx["command"] = command
    if target is not None:
        ctx["target"] = target
    if pid is not None:
        ctx["pid"] = pid
    return ContextLoggerAdapter(base_logger, ctx)