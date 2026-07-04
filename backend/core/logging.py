"""
SentinelX AI — Enterprise Logging
===================================
Structured JSON logging with:
- Console handler (colored in dev, plain in prod)
- Rotating file handler → backend/logs/backend.log
- Request correlation via context vars
- stdlib logging integration
"""
from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Log directory
# ---------------------------------------------------------------------------
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "backend.log"

# ---------------------------------------------------------------------------
# Custom Formatter — JSON-structured output
# ---------------------------------------------------------------------------
class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON for log aggregation pipelines."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        import traceback

        log_obj: dict = {
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Attach extra fields injected via LoggerAdapter or log() kwargs
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                log_obj[key] = value

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        if record.stack_info:
            log_obj["stack"] = self.formatStack(record.stack_info)

        return json.dumps(log_obj, default=str)


# ---------------------------------------------------------------------------
# Pretty Formatter — human-readable for development console
# ---------------------------------------------------------------------------
class DevFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


# ---------------------------------------------------------------------------
# Logger Factory
# ---------------------------------------------------------------------------
def setup_logging(log_level: str = "INFO", app_env: str = "development") -> None:
    """
    Configure the root logger and all handlers.
    Call once at application startup.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove any default handlers
    root_logger.handlers.clear()

    # ── Console Handler ─────────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    if app_env == "development":
        dev_fmt = DevFormatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d | %(message)s",
            datefmt="%H:%M:%S",
        )
        console_handler.setFormatter(dev_fmt)
    else:
        console_handler.setFormatter(JSONFormatter())

    root_logger.addHandler(console_handler)

    # ── Rotating File Handler (JSON always) ─────────────────────────────────
    file_handler = logging.handlers.RotatingFileHandler(
        filename=LOG_FILE,
        maxBytes=50 * 1024 * 1024,  # 50 MB
        backupCount=10,
        encoding="utf-8",
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(file_handler)

    # ── Silence noisy third-party loggers ───────────────────────────────────
    for noisy in ("uvicorn.access", "httpx", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger("uvicorn.error").setLevel(numeric_level)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Use in every module: logger = get_logger(__name__)"""
    return logging.getLogger(name)
