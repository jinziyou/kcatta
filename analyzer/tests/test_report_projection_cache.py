"""Bounded report-detail projection cache behaviour."""

from analyzer import metrics as metrics_mod
from analyzer.api.report_projection_cache import ReportProjectionCache


def test_cache_is_lru_bounded_by_entries_and_bytes() -> None:
    metrics_mod.reset()
    cache = ReportProjectionCache[str](max_entries=2, max_bytes=10)
    fingerprint = ((2, 2), (3, 3))

    assert cache.put("a", fingerprint, "A", estimated_bytes=4)
    assert cache.put("b", fingerprint, "B", estimated_bytes=4)
    assert cache.get("a", fingerprint) == "A"
    assert cache.put("c", fingerprint, "C", estimated_bytes=4)

    assert cache.get("b", fingerprint) is None
    assert cache.snapshot() == (2, 8)
    counters, gauges = metrics_mod.snapshot()
    assert counters["kcatta_report_projection_cache_hits_total"] == 1
    assert counters["kcatta_report_projection_cache_misses_total"] == 1
    assert counters["kcatta_report_projection_cache_evictions_total"] == 1
    assert gauges["kcatta_report_projection_cache_entries"] == 2
    assert gauges["kcatta_report_projection_cache_bytes"] == 8
    assert gauges["kcatta_report_projection_cache_max_entries"] == 2
    assert gauges["kcatta_report_projection_cache_max_bytes"] == 10
    assert gauges["kcatta_report_projection_cache_enabled"] == 1


def test_cache_invalidates_only_changed_entry_and_skips_oversized_values() -> None:
    metrics_mod.reset()
    cache = ReportProjectionCache[str](max_entries=2, max_bytes=10)
    original = ((1, 1), (1, 1))
    changed = ((2, 2), (1, 1))
    other = ((5, 5), (6, 6))

    assert cache.put("report", original, "old", estimated_bytes=4)
    assert cache.put("other", other, "kept", estimated_bytes=4)
    assert cache.get("report", changed) is None
    assert cache.get("other", other) == "kept"
    assert cache.snapshot() == (1, 4)
    assert not cache.put("large", changed, "large", estimated_bytes=11)

    counters, gauges = metrics_mod.snapshot()
    assert counters["kcatta_report_projection_cache_invalidations_total"] == 1
    assert counters["kcatta_report_projection_cache_skipped_total"] == 1
    assert gauges["kcatta_report_projection_cache_entries"] == 1
    assert gauges["kcatta_report_projection_cache_bytes"] == 4


def test_cache_can_be_disabled_without_retaining_values() -> None:
    metrics_mod.reset()
    cache = ReportProjectionCache[str](max_entries=0, max_bytes=10)

    assert cache.enabled is False
    assert not cache.put("report", ((0, 0), (0, 0)), "value", estimated_bytes=1)
    assert cache.snapshot() == (0, 0)
    _, gauges = metrics_mod.snapshot()
    assert gauges["kcatta_report_projection_cache_max_entries"] == 0
    assert gauges["kcatta_report_projection_cache_max_bytes"] == 10
    assert gauges["kcatta_report_projection_cache_enabled"] == 0
