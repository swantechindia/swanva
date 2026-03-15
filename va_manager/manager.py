"""Public entrypoints for the Swan VA manager."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from va_manager.models.scan_job import ScanJob
from va_manager.services.scan_service import create_scan_job


def start_scan(
    db: Session,
    asset_id: int,
    scanner_type: str,
    config: dict[str, Any] | None = None,
) -> ScanJob:
    """Queue a scan job for an existing asset."""

    return create_scan_job(db, asset_id, scanner_type, config or {})


def get_scan_status(db: Session, job_id: int) -> dict[str, object] | None:
    """Fetch a frontend-friendly status payload for a scan job."""

    job = db.get(ScanJob, job_id)
    if job is None:
        return None

    duration = 0
    if job.started_at is not None:
        end_time = job.finished_at or datetime.utcnow()
        duration = max(0, int((end_time - job.started_at).total_seconds()))

    return {
        "job_id": job.id,
        "status": job.status,
        "stage": job.stage,
        "progress": job.progress,
        "duration": duration,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


class VAManager:
    """Thin service wrapper around the manager entrypoints."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def start_scan(
        self,
        asset_id: int,
        scanner_type: str,
        config: dict[str, Any] | None = None,
    ) -> ScanJob:
        """Queue a scan for a specific asset."""

        return start_scan(self.db, asset_id, scanner_type, config or {})

    def get_scan_status(self, job_id: int) -> dict[str, object] | None:
        """Return the database state for a queued or completed job."""

        return get_scan_status(self.db, job_id)
