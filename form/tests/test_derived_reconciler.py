"""Async Analyzer outcome reconciliation into durable Form scan jobs."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from kcatta_form.derived_reconciler import DerivedStatusReconciler
from kcatta_form.job_store import ScanJobRepository
from kcatta_form.schemas import (
    DerivedState,
    ScanCapability,
    ScanJob,
    ScanJobState,
    ScanResult,
)

NOW = datetime(2026, 7, 15, 10, 0, tzinfo=UTC)


def _pending_job() -> ScanJob:
    return ScanJob(
        job_id="job-derived",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.HOST,
        state=ScanJobState.SUCCEEDED,
        created_at=NOW,
        finished_at=NOW,
        result=ScanResult(
            kind=ScanCapability.HOST,
            report_id="report-derived",
            derived_state=DerivedState.PENDING,
            detail="asset report stored; Analyzer detection is queued",
        ),
    )


class _Analyzer:
    async def derived_status(self, kind: str, envelope_id: str, *, source: str):
        assert (kind, envelope_id, source) == (
            "asset-report",
            "report-derived",
            "legacy",
        )
        return {
            "state": "partial",
            "attempts": 2,
            "derived_records": 7,
            "derived_truncated": True,
            "derived_reason": "max_records",
        }


def test_repository_lists_and_finalizes_derived_work(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_pending_job())

    assert [job.job_id for job in repository.list_derived_incomplete()] == ["job-derived"]
    updated = repository.update_derived_result(
        "job-derived",
        state=DerivedState.COMPLETE,
        records=7,
        truncated=False,
        reason=None,
        attempts=1,
        now=NOW,
    )

    assert updated is not None and updated.result is not None
    assert updated.result.derived_state == DerivedState.COMPLETE
    assert updated.result.derived_records == 7
    assert repository.list_derived_incomplete() == []


def test_reconciler_persists_partial_outcome(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_pending_job())
    reconciler = DerivedStatusReconciler(_Analyzer(), repository)

    asyncio.run(reconciler._reconcile(_pending_job()))

    updated = repository.get("job-derived")
    assert updated is not None and updated.result is not None
    assert updated.state == ScanJobState.SUCCEEDED
    assert updated.result.derived_state == DerivedState.PARTIAL
    assert updated.result.derived_records == 7
    assert updated.result.derived_truncated is True
    assert updated.result.derived_attempts == 2
    assert "max_records" in (updated.result.detail or "")
