"""Scan result API routes."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.auth.rbac import VAAccessContext
from va_manager.models.scan_result import ScanResult
from va_manager.services.result_sanitizer import sanitize_result_payload

router = APIRouter()


class ScanResultItem(BaseModel):
    """Sanitized scan result entry returned by the API."""

    id: int
    scanner: str
    created_at: datetime
    result_json: dict[str, object]


class ScanResultsResponse(BaseModel):
    """Collection of sanitized results for one scan job."""

    job_id: int
    results: list[ScanResultItem]


@router.get("/{job_id}")
def get_results(
    job_id: int,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return stored scanner output for a completed job."""

    results = (
        db.query(ScanResult)
        .filter(ScanResult.scan_job_id == job_id)
        .order_by(ScanResult.created_at.asc(), ScanResult.id.asc())
        .all()
    )
    if not results:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan results not found.")

    payload = ScanResultsResponse(
        job_id=job_id,
        results=[
            ScanResultItem(
                id=result.id,
                scanner=result.scanner,
                created_at=result.created_at,
                result_json=sanitize_result_payload(result.scanner, result.result_json),
            )
            for result in results
        ],
    )
    return {"success": True, "data": payload.model_dump()}
