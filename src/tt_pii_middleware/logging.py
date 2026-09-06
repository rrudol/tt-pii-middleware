"""JSON logging that never contains raw PII.

Log records carry structured fields (entity *types* and *counts*, timings,
status codes) -- never the analyzed text or matched values. Keep it that way:
the whole point of this service is that raw prompts stay inside the request
path and out of any log pipeline.
"""

import json
import logging
import sys
import time
from typing import Any

_RESERVED = {"event_fields"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "event_fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    # uvicorn loggers propagate to root; drop their own handlers so every
    # line on stdout is one JSON object.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a structured log line. Callers must pass metadata only, no text."""
    assert not _RESERVED & set(fields)
    logger.info(event, extra={"event_fields": fields})
