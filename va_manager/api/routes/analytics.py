"""Analytics API routes for vulnerability dashboards."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.auth.rbac import VAAccessContext
from va_manager.services.analytics_service import (
    get_asset_details,
    get_cve_details,
    get_severity_distribution,
    get_top_assets,
    get_top_cves,
    get_vulnerability_trends,
)

router = APIRouter()


@router.get("/top-assets")
def top_assets(
    _: VAAccessContext,
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Get top assets by vulnerability count."""

    results = get_top_assets(db, limit=limit, days=days)
    return {"success": True, "data": {"limit": limit, "days": days, "results": results}}


@router.get("/top-cves")
def top_cves(
    _: VAAccessContext,
    limit: int = Query(20, ge=1, le=100),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Get top CVEs by occurrence frequency."""

    results = get_top_cves(db, limit=limit, days=days)
    return {"success": True, "data": {"limit": limit, "days": days, "results": results}}


@router.get("/severity-distribution")
def severity_distribution(
    _: VAAccessContext,
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Get distribution of vulnerabilities by severity level."""

    distribution = get_severity_distribution(db, days=days)
    return {"success": True, "data": {"days": days, "distribution": distribution}}


@router.get("/trends")
def trends(
    _: VAAccessContext,
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Get vulnerability discovery trends over time (daily aggregation)."""

    results = get_vulnerability_trends(db, days=days)
    return {"success": True, "data": {"days": days, "results": results}}


@router.get("/cves/{cve}")
def cve_details(
    cve: str,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Get detailed information about a specific CVE."""

    details = get_cve_details(db, cve)
    if details is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found.")

    return {"success": True, "data": details}


@router.get("/assets/{asset_id}")
def asset_details(
    asset_id: int,
    _: VAAccessContext,
    days: int = Query(90, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Get detailed vulnerability information for a specific asset."""

    details = get_asset_details(db, asset_id, days=days)
    if details is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")

    return {"success": True, "data": details}
