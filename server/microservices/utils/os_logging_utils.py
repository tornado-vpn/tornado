import logging
import json
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

SERVICE_NAME = "os-services"
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

        if hasattr(record, "extra_fields"):
            log.update(record.extra_fields)

        if record.exc_info:
            log["stack_trace"] = self.formatException(record.exc_info)

        return json.dumps(log)


def get_logger():
    logger = logging.getLogger(SERVICE_NAME)
    logger.setLevel(LOG_LEVEL)

    if not logger.handlers:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(JsonFormatter())
        logger.addHandler(stream_handler)

        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


class ContextLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra_fields = extra.get("extra_fields", {})
        merged_fields = {**self.extra, **extra_fields}
        kwargs["extra"] = {"extra_fields": merged_fields}
        return msg, kwargs


def get_context_logger(service_name: str = None, target: str = None):
    base_logger = get_logger()
    context = {}
    if service_name:
        context["os_service"] = service_name
    if target:
        context["target"] = target
    return ContextLoggerAdapter(base_logger, context)
