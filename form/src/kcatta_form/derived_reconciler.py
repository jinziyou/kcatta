"""Reconcile Analyzer's asynchronous derived outcomes into durable scan jobs."""

from __future__ import annotations

import asyncio
import logging
import math
import os
from contextlib import suppress
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .analyzer_client import AnalyzerUpstreamError
from .job_store import ScanJobRepository
from .schemas import DerivedState, ScanCapability, ScanJob

logger = logging.getLogger("kcatta_form.derived_reconciler")

DEFAULT_POLL_SECONDS = 2.0
DEFAULT_BATCH_SIZE = 100


class _Status(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    state: Literal["pending", "processing", "complete", "partial"]
    attempts: int = Field(ge=0)
    derived_records: int = Field(ge=0)
    derived_truncated: bool
    derived_reason: str | None = Field(default=None, max_length=4096)


def _positive_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if math.isfinite(value) and value > 0 else default


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


class DerivedStatusReconciler:
    """Lifespan worker that closes pending → final state after ingest acceptance."""

    def __init__(self, analyzer_client, repository: ScanJobRepository) -> None:  # type: ignore[no-untyped-def]
        self.analyzer_client = analyzer_client
        self.repository = repository
        self.poll_seconds = _positive_float(
            "FORM_DERIVED_STATUS_POLL_SECONDS", DEFAULT_POLL_SECONDS
        )
        self.batch_size = _positive_int("FORM_DERIVED_STATUS_BATCH_SIZE", DEFAULT_BATCH_SIZE)
        self._wake = asyncio.Event()
        self._stopping = False
        self._task: asyncio.Task[None] | None = None

    @property
    def healthy(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="form-derived-status-reconciler")

    def notify(self) -> None:
        self._wake.set()

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._task is not None:
            await self._task
        self._task = None

    async def _run(self) -> None:
        while not self._stopping:
            try:
                jobs = await asyncio.to_thread(
                    self.repository.list_derived_incomplete, self.batch_size
                )
                for job in jobs:
                    if self._stopping:
                        break
                    await self._reconcile(job)
            except Exception:  # noqa: BLE001 - one poll must not kill reconciliation
                logger.exception("derived status reconciliation poll failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=self.poll_seconds)
            self._wake.clear()

    async def _reconcile(self, job: ScanJob) -> None:
        if job.result is None:
            return
        if job.capability == ScanCapability.HOST:
            kind = "asset-report"
            envelope_id = job.result.report_id
        elif job.capability == ScanCapability.TRACE:
            kind = "trace-batch"
            envelope_id = job.result.batch_id
        else:
            return
        if not envelope_id:
            return
        status_call = getattr(self.analyzer_client, "derived_status", None)
        if not callable(status_call):
            return
        try:
            raw = await status_call(kind, envelope_id, source="legacy")
            if raw is None:
                return
            status = _Status.model_validate(raw)
        except (AnalyzerUpstreamError, ValidationError):
            logger.warning("could not refresh derived status for scan job %s", job.job_id)
            return
        await asyncio.to_thread(
            self.repository.update_derived_result,
            job.job_id,
            state=DerivedState(status.state),
            records=status.derived_records,
            truncated=status.derived_truncated,
            reason=status.derived_reason,
            attempts=status.attempts,
            now=datetime.now(UTC),
        )
