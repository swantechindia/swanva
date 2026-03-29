"""Scan orchestration API routes."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.auth.rbac import VAAccessContext, VAAdminContext
from va_manager.manager import remove_scan
from va_manager.services.scan_config import ScanConfigurationError
from va_manager.services.identifiers import format_scan_identifier, parse_scan_identifier
from va_manager.services.scan_query_service import (
    get_ready_assets,
    get_scan_detail,
    list_scans,
    start_scan_batch,
)

router = APIRouter()


class StartScanRequest(BaseModel):
    """Payload for queueing one or more scan jobs."""

    asset_ids: list[int] = Field(default_factory=list)
    asset_id: int | None = None
    scan_type: str | None = None
    scanner_type: str | None = None
    config: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_payload(self) -> "StartScanRequest":
        """Allow both legacy single-asset and new multi-asset request shapes."""

        if self.asset_id is not None and self.asset_id not in self.asset_ids:
            self.asset_ids.append(self.asset_id)
        self.asset_ids = list(dict.fromkeys(self.asset_ids))

        normalized_scan_type = (self.scan_type or self.scanner_type or "").strip().lower()
        if not self.asset_ids:
            raise ValueError("At least one asset_id is required.")
        if not normalized_scan_type:
            raise ValueError("scan_type is required.")

        self.scan_type = normalized_scan_type
        self.scanner_type = normalized_scan_type
        return self


@router.get("/ready-assets")
def ready_assets_route(
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return assets that can be shown in the run-scan UI."""

    return {"success": True, "data": get_ready_assets(db)}


@router.post("/start")
def start_scan_route(
    payload: StartScanRequest,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Queue one scan per requested asset."""

    try:
        jobs = start_scan_batch(db, payload.asset_ids, payload.scan_type or "", payload.config)
    except ScanConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {"success": True, "data": jobs}


@router.get("")
def list_scans_route(
    _: VAAccessContext,
    asset_id: int | None = Query(default=None),
    status_value: str | None = Query(default=None, alias="status"),
    type: str | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return paginated scan rows for the frontend scans page."""

    payload = list_scans(
        db,
        asset_id=asset_id,
        status=status_value,
        scan_type=type,
        date_from=date_from,
        date_to=date_to,
        page=page,
        limit=limit,
    )
    return {"success": True, "data": payload}


@router.get("/{scan_id}")
def get_scan_route(
    scan_id: str,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return one scan with metadata plus result summary."""

    try:
        resolved_scan_id = parse_scan_identifier(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    payload = get_scan_detail(db, resolved_scan_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found.")
    return {"success": True, "data": payload}


@router.delete("/{scan_id}")
def delete_scan_route(
    scan_id: str,
    _: VAAdminContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Delete a queued or completed scan job."""

    try:
        resolved_scan_id = parse_scan_identifier(scan_id)
        deleted = remove_scan(db, resolved_scan_id)
    except ValueError as exc:
        if "Invalid scan identifier" in str(exc):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found.")

    return {"success": True, "data": {"scan_id": format_scan_identifier(resolved_scan_id), "deleted": True}}
