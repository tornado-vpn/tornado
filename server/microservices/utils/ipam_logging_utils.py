import logging
import json
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# ================= CONFIG =================
SERVICE_NAME = "ipam-service"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


LOG_DIR = os.getenv("LOG_DIR", "/var/log/tornado")
LOG_FILE = os.path.join(LOG_DIR, f"{SERVICE_NAME}.log")

os.makedirs(LOG_DIR, exist_ok=True)

# ================= FORMATTER =================
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "service": SERVICE_NAME,
            "level": record.levelname,
            "event": record.getMessage(),
        }

        # Include extra fields if provided
        if hasattr(record, "extra_fields"):
            log.update(record.extra_fields)

        # Include stack trace if exception exists
        if record.exc_info:
            log["stack_trace"] = self.formatException(record.exc_info)

        return json.dumps(log)

# ================= LOGGER =================
def get_logger():
    logger = logging.getLogger(SERVICE_NAME)
    logger.setLevel(LOG_LEVEL)

    if not logger.handlers:
        # Stream handler (console)
        stream = logging.StreamHandler()
        stream.setFormatter(JsonFormatter())
        logger.addHandler(stream)

        # Rotating file handler
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger

# ================= CONTEXT LOGGER =================
class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra_fields = extra.get("extra_fields", {})
        merged = {**self.extra, **extra_fields}
        kwargs["extra"] = {"extra_fields": merged}
        return msg, kwargs

def get_context_logger(request_id=None, user_id=None, device_id=None):
    base_logger = get_logger()
    ctx = {}
    if request_id:
        ctx["request_id"] = request_id
    if user_id:
        ctx["user_id"] = user_id
    if device_id:
        ctx["device_id"] = device_id
    return ContextLoggerAdapter(base_logger, ctx)
