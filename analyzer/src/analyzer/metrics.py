"""Minimal in-process Prometheus text exposition (no third-party dependency).

Counters and gauges are process-local. Suitable for single-replica Analyzer
deployments; multi-replica scrapes each instance independently.
"""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[str, float] = defaultdict(float)
_gauges: dict[str, float] = defaultdict(float)


def inc(name: str, value: float = 1.0) -> None:
    """Increment a counter by ``value`` (default 1)."""
    if value < 0:
        raise ValueError("counter increments must be non-negative")
    with _lock:
        _counters[name] += value


def set_gauge(name: str, value: float) -> None:
    """Set a gauge to an absolute value."""
    with _lock:
        _gauges[name] = value


def snapshot() -> tuple[dict[str, float], dict[str, float]]:
    """Return copies of counters and gauges for tests."""
    with _lock:
        return dict(_counters), dict(_gauges)


def reset() -> None:
    """Clear all metrics (tests only)."""
    with _lock:
        _counters.clear()
        _gauges.clear()


def render_prometheus() -> str:
    """Render the Prometheus text exposition format."""
    lines: list[str] = []
    with _lock:
        for name in sorted(_counters):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {_counters[name]}")
        for name in sorted(_gauges):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {_gauges[name]}")
    if not lines:
        lines.append("# no metrics yet")
    lines.append("")
    return "\n".join(lines)
