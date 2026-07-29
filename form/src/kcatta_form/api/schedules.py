"""Scan schedule CRUD — recurring jobs via Form's durable queue."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status

from ..schedule_store import ScanSchedule, ScanScheduleInput

router = APIRouter(tags=["schedules"])


def _now() -> datetime:
    return datetime.now(UTC)


@router.get("/schedules", response_model=list[ScanSchedule])
async def list_schedules(request: Request) -> list[ScanSchedule]:
    return await asyncio.to_thread(request.app.state.schedule_store.list)


@router.post(
    "/schedules",
    status_code=status.HTTP_201_CREATED,
    response_model=ScanSchedule,
)
async def create_schedule(body: ScanScheduleInput, request: Request) -> ScanSchedule:
    target = await asyncio.to_thread(
        request.app.state.scan_target_store.find_one,
        "target_id",
        body.target_id,
    )
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"scan target not found: {body.target_id}",
        )
    return await asyncio.to_thread(request.app.state.schedule_store.create, body, _now())


@router.get("/schedules/{schedule_id}", response_model=ScanSchedule)
async def get_schedule(schedule_id: str, request: Request) -> ScanSchedule:
    schedule = await asyncio.to_thread(request.app.state.schedule_store.get, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="schedule not found")
    return schedule


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(schedule_id: str, request: Request) -> None:
    deleted = await asyncio.to_thread(request.app.state.schedule_store.delete, schedule_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="schedule not found")
