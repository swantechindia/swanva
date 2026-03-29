"""Dashboard API routes aligned with the frontend UI."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.auth.rbac import VAAccessContext
from va_manager.services.dashboard_service import (
    get_asset_risk_distribution,
    get_dashboard_summary,
    get_dashboard_trends,
)

router = APIRouter()


@router.get("/summary")
def dashboard_summary(
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return the frontend dashboard summary payload."""

    return {"success": True, "data": get_dashboard_summary(db)}


@router.get("/trends")
def dashboard_trends(
    _: VAAccessContext,
    days: int = Query(7, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return the frontend dashboard trend-series payload."""

    return {"success": True, "data": get_dashboard_trends(db, days=days)}


@router.get("/asset-risk")
def dashboard_asset_risk(
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return per-asset severity distribution for the dashboard."""

    return {"success": True, "data": get_asset_risk_distribution(db)}
