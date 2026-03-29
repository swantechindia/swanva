"""Reporting API routes aligned with the frontend UI."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.auth.rbac import VAAccessContext
from va_manager.services.report_service import (
    generate_report_for_scan,
    get_report_download_payload,
    get_report_metadata,
    list_reports,
)

router = APIRouter()


class GenerateReportRequest(BaseModel):
    """Payload for on-demand report generation."""

    scan_id: str


@router.post("/generate")
def generate_report_route(
    payload: GenerateReportRequest,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Generate a report for a scan if one does not already exist."""

    try:
        report = generate_report_for_scan(db, payload.scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    metadata = get_report_metadata(db, report.id)
    if metadata is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Report generation failed.")
    return {"success": True, "data": metadata}


@router.get("")
def list_reports_route(
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return all generated report metadata."""

    return {"success": True, "data": list_reports(db)}


@router.get("/{report_id}")
def get_report_route(
    report_id: str,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return report metadata by report identifier."""

    payload = get_report_metadata(db, report_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    return {"success": True, "data": payload}


@router.get("/{report_id}/download")
def download_report_route(
    report_id: str,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> Response:
    """Download one report as a JSON attachment."""

    download = get_report_download_payload(db, report_id)
    if download is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")

    filename, payload = download
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
