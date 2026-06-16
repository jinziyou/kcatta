"""Central logging configuration for the analyzer (E1).

Without this, the analyzer never called ``logging.basicConfig`` / ``dictConfig``,
so the root logger had no handler and uvicorn does not adopt arbitrary business
loggers. Every ``logger.warning(...)`` in the ingest pipeline (swallowed
"detection failed" / "correlation failed" exceptions) was therefore invisible in
production — failures vanished silently.

``configure_logging`` installs a single stream handler on the ``analyzer`` logger
(and the root, for libraries) with a JSON-friendly formatter, idempotently, at a
level taken from ``ANALYZER_LOG_LEVEL`` (default INFO). It is safe to call from
both the API app factory and the CLI entry points.
"""

from __future__ import annotations

import json
import logging
import os
import sys

DEFAULT_LEVEL = "INFO"
ENV_LEVEL = "ANALYZER_LOG_LEVEL"
ENV_FORMAT = "ANALYZER_LOG_FORMAT"  # "json" (default) | "text"

# Marker so configuration is applied at most once per handler set, even if the
# app factory and the CLI both call configure_logging in the same process.
_CONFIGURED_FLAG = "_analyzer_configured"

# LogRecord attributes that are intrinsic — everything else a caller attaches via
# ``extra=`` is surfaced in the JSON output.
_RESERVED_RECORD_KEYS = frozenset(
    logging.makeLogRecord({}).__dict__.keys() | {"message", "asctime"}
)


class JsonFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object (one event per line)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Surface request-id and any other structured `extra=` fields.
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_KEYS and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload, default=str)


def _level_from_env() -> int:
    name = os.getenv(ENV_LEVEL, DEFAULT_LEVEL).upper()
    return logging.getLevelNamesMapping().get(name, logging.INFO)


def _make_formatter() -> logging.Formatter:
    if os.getenv(ENV_FORMAT, "json").lower() == "text":
        return logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    return JsonFormatter()


def configure_logging(level: int | str | None = None) -> None:
    """Install the analyzer's stream handler + formatter, idempotently.

    Attaches a handler to BOTH the root logger (so third-party libs are visible)
    and the dedicated ``analyzer`` logger with ``propagate=True`` left intact, so
    business ``logger.warning`` calls are never silenced by uvicorn's logging
    setup (which only configures its own ``uvicorn.*`` loggers).
    """
    resolved = (
        logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        if isinstance(level, str)
        else (level if isinstance(level, int) else _level_from_env())
    )

    root = logging.getLogger()
    root.setLevel(resolved)
    if not getattr(root, _CONFIGURED_FLAG, False):
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(_make_formatter())
        root.addHandler(handler)
        setattr(root, _CONFIGURED_FLAG, True)

    # Pin the analyzer logger's level explicitly so it is never raised above the
    # configured level by an external library re-configuring the root.
    logging.getLogger("analyzer").setLevel(resolved)
