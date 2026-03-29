"""Analytics service for vulnerability dashboard queries."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from va_manager.models.asset import Asset
from va_manager.models.report import Report
from va_manager.models.vulnerability import Vulnerability

def get_top_assets(
    db: Session,
    limit: int = 10,
    days: int = 30,
) -> list[dict[str, object]]:
    """Get assets with the most vulnerabilities in the past N days.

    Args:
        db: Database session.
        limit: Maximum number of assets to return.
        days: Look back period in days.

    Returns:
        List of assets with vulnerability counts, sorted by count descending.
    """

    since = datetime.utcnow() - timedelta(days=days)

    query = (
        db.query(
            Asset.id,
            Asset.target,
            func.count(Vulnerability.id).label("vulnerability_count"),
            func.count(
                func.distinct(Vulnerability.cve)
            ).label("unique_cve_count"),
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .join(Report, Report.id == Vulnerability.report_id)
        .filter(Report.created_at >= since)
        .group_by(Asset.id, Asset.target)
        .order_by(func.count(func.distinct(Vulnerability.cve)).desc())
        .limit(limit)
    )

    results = []
    for asset_id, asset_name, vuln_count, unique_count in query:
        results.append(
            {
                "asset_id": asset_id,
                "asset_name": asset_name,
                "total_findings": vuln_count,
                "unique_cves": unique_count,
            }
        )

    return results


def get_top_cves(
    db: Session,
    limit: int = 20,
    days: int = 30,
) -> list[dict[str, object]]:
    """Get most frequently discovered CVEs in the past N days.

    Args:
        db: Database session.
        limit: Maximum number of CVEs to return.
        days: Look back period in days.

    Returns:
        List of CVEs with occurrence counts and average CVSS.
    """

    since = datetime.utcnow() - timedelta(days=days)

    query = (
        db.query(
            Vulnerability.cve,
            func.count(Vulnerability.id).label("occurrence_count"),
            func.count(func.distinct(Vulnerability.asset_id)).label("affected_assets"),
            func.avg(Vulnerability.cvss).label("avg_cvss"),
            func.max(Vulnerability.severity).label("max_severity"),
        )
        .join(Report, Report.id == Vulnerability.report_id)
        .filter(Report.created_at >= since)
        .group_by(Vulnerability.cve)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(limit)
    )

    results = []
    for cve, count, affected_assets, avg_cvss, severity in query:
        results.append(
            {
                "cve": cve,
                "occurrences": count,
                "affected_assets": affected_assets,
                "avg_cvss": float(avg_cvss) if avg_cvss else None,
                "severity": severity,
            }
        )

    return results


def get_severity_distribution(
    db: Session,
    days: int = 30,
) -> dict[str, int]:
    """Get count of vulnerabilities by severity level in the past N days.

    Args:
        db: Database session.
        days: Look back period in days.

    Returns:
        Dictionary with counts for each severity level.
    """

    since = datetime.utcnow() - timedelta(days=days)

    query = (
        db.query(
            Vulnerability.severity,
            func.count(func.distinct(Vulnerability.cve)).label("count"),
        )
        .join(Report, Report.id == Vulnerability.report_id)
        .filter(Report.created_at >= since)
        .group_by(Vulnerability.severity)
    )

    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for severity, count in query:
        if severity and severity.lower() in distribution:
            distribution[severity.lower()] = count

    return distribution


def get_vulnerability_trends(
    db: Session,
    days: int = 30,
) -> list[dict[str, object]]:
    """Get vulnerability discovery trends over time (daily aggregation).

    Args:
        db: Database session.
        days: Look back period in days.

    Returns:
        List of daily vulnerability counts.
    """

    since = datetime.utcnow() - timedelta(days=days)

    # Use database-agnostic date comparison
    # Group by date without time component
    date_expr = func.date(Report.created_at)

    query = (
        db.query(
            date_expr.label("date"),
            func.count(Vulnerability.id).label("total_findings"),
            func.count(func.distinct(Vulnerability.cve)).label("unique_cves"),
            func.count(Vulnerability.id)
            .filter(Vulnerability.severity == "critical")
            .label("critical_count"),
            func.count(Vulnerability.id)
            .filter(Vulnerability.severity == "high")
            .label("high_count"),
        )
        .join(Report, Report.id == Vulnerability.report_id)
        .filter(Report.created_at >= since)
        .group_by(date_expr)
        .order_by(date_expr.desc())
    )

    results = []
    for date, total, unique, critical, high in query:
        results.append(
            {
                "date": date.isoformat() if hasattr(date, "isoformat") else str(date),
                "total_findings": total,
                "unique_cves": unique,
                "critical": critical,
                "high": high,
            }
        )

    return results


def get_cve_details(
    db: Session,
    cve: str,
) -> dict[str, object] | None:
    """Get detailed information about a specific CVE across all assets.

    Args:
        db: Database session.
        cve: CVE identifier.

    Returns:
        Dictionary with CVE details and affected assets, or None if not found.
    """

    vuln = db.query(Vulnerability).filter(Vulnerability.cve == cve).first()
    if vuln is None:
        return None

    # Get all occurrences of this CVE across assets
    affected_query = (
        db.query(
            Asset.id,
            Asset.target,
            Vulnerability.affected_ports,
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .filter(Vulnerability.cve == cve)
    )

    affected_assets_dict: dict[int, dict[str, object]] = {}
    for asset_id, asset_name, ports in affected_query:
        if asset_id not in affected_assets_dict:
            affected_assets_dict[asset_id] = {
                "asset_id": asset_id,
                "asset_name": asset_name,
                "occurrences": 0,
                "ports": set(),
            }
        affected_assets_dict[asset_id]["occurrences"] += 1
        if ports:
            affected_assets_dict[asset_id]["ports"].update(ports)

    affected_assets = [
        {
            "asset_id": a["asset_id"],
            "asset_name": a["asset_name"],
            "occurrences": a["occurrences"],
            "ports": sorted(list(a["ports"])),
        }
        for a in affected_assets_dict.values()
    ]

    return {
        "cve": cve,
        "severity": vuln.severity,
        "cvss": vuln.cvss,
        "description": vuln.description,
        "references": vuln.references,
        "source": vuln.source,
        "affected_assets": affected_assets,
        "total_occurrences": sum(a["occurrences"] for a in affected_assets),
    }


def get_asset_details(
    db: Session,
    asset_id: int,
    days: int = 90,
) -> dict[str, object] | None:
    """Get detailed vulnerability information for a specific asset.

    Args:
        db: Database session.
        asset_id: Asset ID.
        days: Look back period in days.

    Returns:
        Dictionary with asset vulnerability details, or None if asset not found.
    """

    asset = db.get(Asset, asset_id)
    if asset is None:
        return None

    since = datetime.utcnow() - timedelta(days=days)

    vuln_query = (
        db.query(Vulnerability)
        .join(Report, Report.id == Vulnerability.report_id)
        .filter(
            Vulnerability.asset_id == asset_id,
            Report.created_at >= since,
        )
        .order_by(Vulnerability.severity.desc(), Vulnerability.cvss.desc())
    )

    vulns_by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for vuln in vuln_query:
        severity = vuln.severity.lower()
        if severity in vulns_by_severity:
            vuln_dict = {
                "cve": vuln.cve,
                "cvss": vuln.cvss,
                "description": vuln.description,
                "affected_ports": vuln.affected_ports,
                "affected_services": vuln.affected_services,
                "source": vuln.source,
            }
            vulns_by_severity[severity].append(vuln_dict)
            severity_counts[severity] += 1

    return {
        "asset_id": asset.id,
        "asset_name": asset.target,
        "severity_counts": severity_counts,
        "total_vulnerabilities": sum(severity_counts.values()),
        "vulnerabilities_by_severity": vulns_by_severity,
    }
