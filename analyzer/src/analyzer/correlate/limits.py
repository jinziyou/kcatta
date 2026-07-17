"""Hard limits for attacker-influenced correlation fan-out."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MAX_ALERTS_PER_INGEST = 128
MAX_RELATED_IDS = 64
MAX_GROUP_LABELS = 8
MAX_ALERT_TEXT_CHARS = 4096
MAX_ALERT_ID_CHARS = 256


@dataclass
class CorrelationLimitState:
    """Optional explicit signal when correlation fan-out is capped."""

    truncated: bool = False
    reason: str | None = None

    def mark(self, reason: str) -> None:
        self.truncated = True
        if self.reason is None:
            self.reason = reason


def append_unique_bounded(items: list[str], value: str, limit: int = MAX_RELATED_IDS) -> bool:
    """Append one unique value, returning true only when a new value was omitted."""
    if value in items:
        return False
    if len(items) >= limit:
        return True
    items.append(value)
    return False


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
