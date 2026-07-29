"""Background ticker that materializes due ScanSchedules into ScanJobs."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

from .job_store import ScanJobRepository
from .schedule_store import ScheduleStore
from .schemas.scan import ScanJob, ScanJobState, mode_for_capability

logger = logging.getLogger("kcatta_form.schedule_worker")


class ScheduleWorker:
    """Poll schedules and enqueue durable scan jobs."""

    def __init__(
        self,
        state: Any,
        schedules: ScheduleStore,
        jobs: ScanJobRepository,
        *,
        poll_seconds: float = 15.0,
    ) -> None:
        self.state = state
        self.schedules = schedules
        self.jobs = jobs
        self.poll_seconds = max(1.0, float(poll_seconds))
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self._last_error: str | None = None

    @property
    def healthy(self) -> bool:
        return self._last_error is None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="form-schedule-worker")

    async def stop(self) -> None:
        self._stopping = True
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _run(self) -> None:
        while not self._stopping:
            try:
                await asyncio.to_thread(self.tick, datetime.now(UTC))
                self._last_error = None
            except Exception as exc:  # noqa: BLE001 - keep scheduling after transient errors
                self._last_error = str(exc)
                logger.exception("schedule worker tick failed")
            await asyncio.sleep(self.poll_seconds)

    def tick(self, now: datetime) -> int:
        """Enqueue all due schedules; return how many jobs were created."""
        created = 0
        for schedule in self.schedules.due(now):
            target = self.state.scan_target_store.find_one("target_id", schedule.target_id)
            if target is None:
                logger.warning(
                    "schedule %s skipped — target %s missing",
                    schedule.schedule_id,
                    schedule.target_id,
                )
                # Push next_run forward so a deleted target does not hot-loop.
                self.schedules.snooze(schedule, now)
                continue
            address = str(target.get("address") or schedule.target_id)
            job = ScanJob(
                job_id=f"job-{schedule.schedule_id}-{int(now.timestamp())}",
                target_id=schedule.target_id,
                address=address,
                capability=schedule.capability,
                mode=mode_for_capability(schedule.capability),
                state=ScanJobState.PENDING,
                options=schedule.options,
                created_at=now,
                updated_at=now,
                available_at=now,
            )
            try:
                self.jobs.create(job)
            except Exception:  # noqa: BLE001 - leave next_run so operator can fix
                logger.exception(
                    "schedule %s failed to enqueue job for target %s",
                    schedule.schedule_id,
                    schedule.target_id,
                )
                continue
            self.schedules.mark_enqueued(schedule, job.job_id, now)
            created += 1
            logger.info(
                "schedule %s enqueued job %s for target %s",
                schedule.schedule_id,
                job.job_id,
                schedule.target_id,
            )
        return created
