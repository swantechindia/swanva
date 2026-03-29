"""Frontend dashboard query service."""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from va_manager.models.asset import Asset
from va_manager.models.report import Report
from va_manager.models.scan_job import ScanJob
from va_manager.models.vulnerability import Vulnerability

SEVERITY_LEVELS = ("critical", "high", "medium", "low")


def get_dashboard_summary(db: Session) -> dict[str, object]:
    """Return top-line counts for the dashboard summary cards."""

    total_assets = db.query(func.count(Asset.id)).scalar() or 0
    total_scanned = db.query(func.count(func.distinct(ScanJob.asset_id))).filter(
        ScanJob.completed_at.is_not(None)
    ).scalar() or 0

    severity_counts = _empty_severity_counts()
    rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    for severity, count in rows:
        normalized = str(severity or "").lower()
        if normalized in severity_counts:
            severity_counts[normalized] = int(count)

    return {
        "total_assets": int(total_assets),
        "total_scanned": int(total_scanned),
        "vulnerabilities": severity_counts,
    }


def get_dashboard_trends(db: Session, days: int = 7) -> dict[str, list[object]]:
    """Return frontend-ready vulnerability trend arrays keyed by severity."""

    start_date = datetime.utcnow().date() - timedelta(days=days - 1)
    date_expr = func.date(Report.created_at)

    rows = (
        db.query(
            date_expr.label("report_date"),
            Vulnerability.severity,
            func.count(Vulnerability.id).label("count"),
        )
        .join(Report, Report.id == Vulnerability.report_id)
        .filter(Report.created_at >= datetime.combine(start_date, datetime.min.time()))
        .group_by(date_expr, Vulnerability.severity)
        .all()
    )

    severity_by_date: dict[str, dict[str, int]] = {
        severity: defaultdict(int) for severity in SEVERITY_LEVELS
    }
    for report_date, severity, count in rows:
        normalized_severity = str(severity or "").lower()
        if normalized_severity not in severity_by_date:
            continue
        severity_by_date[normalized_severity][_normalize_date_value(report_date)] = int(count)

    dates = [(start_date + timedelta(days=index)).isoformat() for index in range(days)]
    return {
        "dates": dates,
        "critical": [severity_by_date["critical"].get(day, 0) for day in dates],
        "high": [severity_by_date["high"].get(day, 0) for day in dates],
        "medium": [severity_by_date["medium"].get(day, 0) for day in dates],
        "low": [severity_by_date["low"].get(day, 0) for day in dates],
    }


def get_asset_risk_distribution(db: Session) -> list[dict[str, object]]:
    """Return per-asset severity counts for dashboard risk distribution."""

    rows = (
        db.query(
            Asset.id,
            Asset.name,
            Vulnerability.severity,
            func.count(Vulnerability.id).label("count"),
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .group_by(Asset.id, Asset.name, Vulnerability.severity)
        .order_by(Asset.name.asc(), Asset.id.asc())
        .all()
    )

    by_asset: dict[int, dict[str, object]] = {}
    for asset_id, asset_name, severity, count in rows:
        if asset_id not in by_asset:
            by_asset[asset_id] = {
                "asset_name": asset_name,
                **_empty_severity_counts(),
            }
        normalized_severity = str(severity or "").lower()
        if normalized_severity in SEVERITY_LEVELS:
            by_asset[asset_id][normalized_severity] = int(count)

    return list(by_asset.values())


def _empty_severity_counts() -> dict[str, int]:
    """Return a zeroed severity-count mapping."""

    return {severity: 0 for severity in SEVERITY_LEVELS}


def _normalize_date_value(value: object) -> str:
    """Normalize SQL date results into ISO date strings."""

    if isinstance(value, date):
        return value.isoformat()
    return str(value)
