"""Vulnerability report API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from va_manager.api.deps import get_current_user, get_db
from va_manager.models.report import Report

router = APIRouter()


@router.get("/{job_id}")
def get_report(
    job_id: int,
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
) -> dict[str, object]:
    """Return the structured vulnerability report for a completed scan job."""

    report = db.query(Report).filter(Report.scan_job_id == job_id).one_or_none()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")

    return {
        "id": report.id,
        "scan_job_id": report.scan_job_id,
        "created_at": report.created_at,
        "total_vulnerabilities": report.total_vulnerabilities,
        "severity_counts": report.severity_counts,
        "report": report.report_json,
        "version": report.version,
    }


@router.get("/{job_id}/summary")
def get_report_summary(
    job_id: int,
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
) -> dict[str, object]:
    """Return only the summary statistics for a report."""

    report = db.query(Report).filter(Report.scan_job_id == job_id).one_or_none()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")

    return {
        "scan_job_id": report.scan_job_id,
        "total_vulnerabilities": report.total_vulnerabilities,
        "severity_counts": report.severity_counts,
        "created_at": report.created_at,
    }
