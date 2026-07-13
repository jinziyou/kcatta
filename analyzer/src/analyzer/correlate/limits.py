"""Hard limits for attacker-influenced correlation fan-out."""

from __future__ import annotations

import hashlib

MAX_ALERTS_PER_INGEST = 128
MAX_RELATED_IDS = 64
MAX_GROUP_LABELS = 8
MAX_ALERT_TEXT_CHARS = 4096
MAX_ALERT_ID_CHARS = 256


def append_unique_bounded(items: list[str], value: str, limit: int = MAX_RELATED_IDS) -> None:
    """Append one unique value while keeping attacker-controlled groups bounded."""
    if len(items) < limit and value not in items:
        items.append(value)


def bounded_text(value: str) -> str:
    """Truncate human-readable derived text at a deterministic character cap."""
    if len(value) <= MAX_ALERT_TEXT_CHARS:
        return value
    return value[: MAX_ALERT_TEXT_CHARS - 14] + "…[truncated]"


def bounded_id(value: str) -> str:
    """Keep normal stable ids unchanged; hash only an oversized suffix."""
    if len(value) <= MAX_ALERT_ID_CHARS:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    prefix = value[: MAX_ALERT_ID_CHARS - len(digest) - 1]
    return f"{prefix}-{digest}"
