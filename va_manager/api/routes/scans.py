
"""Scan orchestration API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from va_manager.api.deps import get_current_user, get_db
from va_manager.manager import get_scan_status, start_scan

router = APIRouter()


class StartScanRequest(BaseModel):
    """Payload for queueing a scan job."""

    asset_id: int
    scanner_type: str
    config: dict[str, object] = Field(default_factory=dict)


class StartScanResponse(BaseModel):
    """Minimal scan job creation response."""

    job_id: int
    status: str


@router.post("/start", response_model=StartScanResponse)
def start_scan_route(
    payload: StartScanRequest,
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
) -> StartScanResponse:
    """Queue a new scan job through the VA manager."""

    job = start_scan(db, payload.asset_id, payload.scanner_type, payload.config)
    return StartScanResponse(job_id=job.id, status=job.status)


@router.get("/{job_id}")
def get_scan_status_route(
    job_id: int,
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
) -> dict[str, object]:
    """Return scan job status, progress, and duration."""

    payload = get_scan_status(db, job_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found.")
    return payload
