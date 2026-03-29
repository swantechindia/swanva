"""Frontend-oriented scan queries and batch actions."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session, joinedload

from va_manager.models.scan_job import ScanJob
from va_manager.services.asset_service import list_ready_assets
from va_manager.services.identifiers import format_scan_identifier
from va_manager.services.scan_service import create_scan_job


def start_scan_batch(
    db: Session,
    asset_ids: list[int],
    scan_type: str,
    config: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Queue one scan job per asset and return frontend-facing job summaries."""

    started_jobs: list[dict[str, object]] = []
    for asset_id in asset_ids:
        job = create_scan_job(db, asset_id, scan_type, config or {})
        started_jobs.append(
            {
                "scan_id": format_scan_identifier(job.id),
                "job_id": job.id,
                "asset_id": job.asset_id,
                "type": job.scanner_type,
                "status": job.status,
            }
        )
    return started_jobs


def get_ready_assets(db: Session) -> list[dict[str, object]]:
    """Return assets suitable for the run-scan frontend screen."""

    return list_ready_assets(db)


def list_scans(
    db: Session,
    asset_id: int | None = None,
    status: str | None = None,
    scan_type: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = 1,
    limit: int = 20,
) -> dict[str, object]:
    """Return paginated scan-job rows for the frontend scans page."""

    query = db.query(ScanJob).options(joinedload(ScanJob.asset))

    if asset_id is not None:
        query = query.filter(ScanJob.asset_id == asset_id)
    if status:
        query = query.filter(ScanJob.status == status.strip().lower())
    if scan_type:
        query = query.filter(ScanJob.scanner_type == scan_type.strip().lower())
    if date_from is not None:
        query = query.filter(ScanJob.created_at >= date_from)
    if date_to is not None:
        query = query.filter(ScanJob.created_at <= date_to)

    total = query.order_by(None).count()
    jobs = (
        query.order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    items = [
        {
            "scan_id": format_scan_identifier(job.id),
            "job_id": job.id,
            "asset_id": job.asset_id,
            "asset_name": job.asset.name if job.asset is not None else None,
            "type": job.scanner_type,
            "status": job.status,
            "date": job.created_at,
        }
        for job in jobs
    ]

    return {
        "items": items,
        "page": page,
        "limit": limit,
        "total": total,
    }


def get_scan_detail(db: Session, scan_id: int) -> dict[str, object] | None:
    """Return one scan detail payload with results summary."""

    job = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.asset), joinedload(ScanJob.report), joinedload(ScanJob.scan_results))
        .filter(ScanJob.id == scan_id)
        .one_or_none()
    )
    if job is None:
        return None

    report = job.report
    result_count = len(job.scan_results)
    result_types = sorted({result.scanner for result in job.scan_results})

    return {
        "scan_id": format_scan_identifier(job.id),
        "job_id": job.id,
        "asset": {
            "id": job.asset_id,
            "name": job.asset.name if job.asset is not None else None,
            "target": job.asset.target if job.asset is not None else None,
            "asset_type": job.asset.asset_type if job.asset is not None else None,
        },
        "type": job.scanner_type,
        "status": job.status,
        "stage": job.stage,
        "progress": job.progress,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "results_summary": {
            "result_count": result_count,
            "result_types": result_types,
            "report_status": "ready" if report is not None else "missing",
            "total_vulnerabilities": report.total_vulnerabilities if report is not None else 0,
            "severity_counts": report.severity_counts if report is not None else {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        },
    }
