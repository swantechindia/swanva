"""Database services for scan job creation."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from va_manager.models.scan_job import ScanJob


def create_scan_job(
    db: Session,
    asset_id: int,
    scanner_type: str,
    config: dict[str, Any] | None,
) -> ScanJob:
    """Create and persist a queued scan job."""

    job = ScanJob(
        asset_id=asset_id,
        scanner_type=scanner_type,
        scan_config=config or {},
        status="queued",
        stage="queued",
        progress=0,
    )

    db.add(job)
    db.commit()
    db.refresh(job)
    return job
