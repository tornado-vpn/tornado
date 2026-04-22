# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

SERVICE_NAME = "auth-service"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

LOG_DIR = os.getenv("LOG_DIR", "/var/log/tornado")
LOG_FILE = os.path.join(LOG_DIR, f"{SERVICE_NAME}.log")

os.makedirs(LOG_DIR, exist_ok=True)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "service": SERVICE_NAME,
            "level": record.levelname,
            "event": record.getMessage(),
        }
        # Merge extra fields if present
        if hasattr(record, "extra_fields"):
            log.update(record.extra_fields)
        
        # Handle exceptions automatically
        if record.exc_info:
            log["stack_trace"] = self.formatException(record.exc_info)
            
        return json.dumps(log)

def get_logger():
    logger = logging.getLogger(SERVICE_NAME)
    logger.setLevel(LOG_LEVEL)

    # Only add handlers if they don't exist to prevent duplicate logging
    if not logger.handlers:
        # Console handler
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(JsonFormatter())
        logger.addHandler(stream_handler)

        # File handler with rotation (10MB per file, 5 backups)
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger
# Logger Adapter for automatic context injection
class ContextLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})

    def process(self, msg, kwargs):
        # Merge any extra_fields from kwargs with the adapter's context
        extra = kwargs.get("extra", {})
        extra_fields = extra.get("extra_fields", {})
        merged_fields = {**self.extra, **extra_fields}
        kwargs["extra"] = {"extra_fields": merged_fields}
        return msg, kwargs

# Helper to create a context-aware logger
def get_context_logger(request_id=None, client_ip=None):
    base_logger = get_logger()
    context = {}
    if request_id:
        context["request_id"] = request_id
    if client_ip:
        context["client_ip"] = client_ip
    return ContextLoggerAdapter(base_logger, context)
