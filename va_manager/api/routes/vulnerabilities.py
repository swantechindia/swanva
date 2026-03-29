"""Vulnerability listing APIs aligned with the frontend UI."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.auth.rbac import VAAccessContext
from va_manager.services.vulnerability_service import (
    get_vulnerability_summary,
    list_vulnerabilities,
)

router = APIRouter()


@router.get("/summary")
def vulnerability_summary(
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return vulnerability counts by severity."""

    return {"success": True, "data": get_vulnerability_summary(db)}


@router.get("")
def vulnerabilities_list(
    _: VAAccessContext,
    severity: str | None = Query(default=None),
    asset_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return paginated vulnerability rows for the frontend table."""

    return {
        "success": True,
        "data": list_vulnerabilities(
            db,
            severity=severity,
            asset_id=asset_id,
            status=status,
            page=page,
            limit=limit,
        ),
    }
