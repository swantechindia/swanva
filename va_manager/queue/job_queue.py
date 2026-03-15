"""Queue lookup helpers for pending scan jobs."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from va_manager.models.scan_job import ScanJob


def get_next_job(db: Session) -> ScanJob | None:
    """Return the next queued job using row locking for multi-worker safety."""

    stmt = (
        select(ScanJob)
        .where(ScanJob.status == "queued")
        .order_by(ScanJob.created_at.asc(), ScanJob.id.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    return db.execute(stmt).scalars().first()
