"""Shared parsing for logical upload/chunk identifiers."""

from __future__ import annotations

import re
from typing import Literal

LineageKind = Literal["asset", "trace"]
LineageInfo = tuple[str, int, int | None]

_FORM_CHUNK = re.compile(
    r"^(?P<root>.+)::chunk-(?P<index>[1-9][0-9]*)-of-(?P<total>[1-9][0-9]*)$"
)
_AGENT_ASSET_CHUNK = re.compile(
    r"^(?P<root>.+)~report-part-(?P<index>0|[1-9][0-9]*)$"
)
_AGENT_TRACE_CHUNK = re.compile(
    r"^(?P<root>.+)~batch-part-(?P<index>0|[1-9][0-9]*)$"
)


def parse_lineage_id(value: str, kind: LineageKind) -> LineageInfo | None:
    """Return ``(root, index, expected_total)`` for a recognized chunk id."""
    patterns = (
        (_FORM_CHUNK, True),
        (_AGENT_ASSET_CHUNK if kind == "asset" else _AGENT_TRACE_CHUNK, False),
    )
    for pattern, has_total in patterns:
        if match := pattern.match(value):
            return (
                match.group("root"),
                int(match.group("index")),
                int(match.group("total")) if has_total else None,
            )
    return None


def lineage_root(value: str, kind: LineageKind) -> str:
    """Map a root or recognized chunk id to its stable logical root."""
    parsed = parse_lineage_id(value, kind)
    return parsed[0] if parsed is not None else value
