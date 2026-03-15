"""Scan result API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from va_manager.api.deps import get_current_user, get_db
from va_manager.models.scan_result import ScanResult

router = APIRouter()


@router.get("/{job_id}")
def get_results(
    job_id: int,
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
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

    return {
        "job_id": job_id,
        "results": [
            {
                "id": result.id,
                "scanner": result.scanner,
                "created_at": result.created_at,
                "result_json": result.result_json,
            }
            for result in results
        ],
    }
