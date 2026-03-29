"""Service for generating and storing structured vulnerability reports."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from sqlalchemy.orm import Session

from va_manager.models.asset import Asset
from va_manager.models.report import Report
from va_manager.models.scan_job import ScanJob
from va_manager.models.scan_result import ScanResult
from va_manager.models.vulnerability import Vulnerability
from va_manager.services.identifiers import (
    format_report_identifier,
    format_scan_identifier,
    parse_report_identifier,
    parse_scan_identifier,
)

LOGGER = logging.getLogger(__name__)
SeverityCounts = dict[str, int]
AggregatedVulnerability = dict[str, object]


def aggregate_vulnerabilities(findings: list[Mapping[str, object]]) -> dict[str, AggregatedVulnerability]:
    """Aggregate vulnerability findings by CVE, grouping affected ports and services.

    Args:
        findings: List of vulnerability findings from the vulnerability_engine.

    Returns:
        Dictionary keyed by CVE with aggregated vulnerability data.
    """

    aggregated: dict[str, AggregatedVulnerability] = {}

    for finding in findings:
        cve = finding.get("cve", "unknown")

        if cve not in aggregated:
            aggregated[cve] = {
                "cve": cve,
                "severity": finding.get("severity", "unknown"),
                "cvss": finding.get("cvss"),
                "description": finding.get("description", ""),
                "references": finding.get("references", []),
                "source": finding.get("source", ""),
                "affected_ports": [],
                "affected_services": [],
            }

        # Track affected ports and services while avoiding duplicates
        port = finding.get("port")
        if port is not None and port not in aggregated[cve]["affected_ports"]:
            aggregated[cve]["affected_ports"].append(port)

        service = finding.get("service")
        if service and service not in aggregated[cve]["affected_services"]:
            aggregated[cve]["affected_services"].append(service)

    return aggregated


def compute_severity_counts(findings: list[Mapping[str, object]]) -> SeverityCounts:
    """Compute count of vulnerabilities by severity level.

    Args:
        findings: List of vulnerability findings.

    Returns:
        Dictionary with counts for critical, high, medium, low severity levels.
    """

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    seen_cves = set()
    for finding in findings:
        cve = finding.get("cve", "unknown")
        # Count each CVE only once, even if it appears on multiple ports
        if cve not in seen_cves:
            severity = finding.get("severity", "low").lower()
            if severity in counts:
                counts[severity] += 1
            seen_cves.add(cve)

    return counts


def build_report_json(
    scan_id: str,
    asset: str,
    findings: list[Mapping[str, object]],
) -> dict[str, object]:
    """Build the final structured report JSON.

    Args:
        scan_id: Unique identifier for the scan.
        asset: Asset being scanned.
        findings: List of vulnerability findings from the vulnerability_engine.

    Returns:
        Structured report dictionary.
    """

    aggregated = aggregate_vulnerabilities(findings)
    severity_counts = compute_severity_counts(findings)

    # Count unique CVEs for total vulnerabilities
    total_vulnerabilities = len(aggregated)

    report = {
        "scan_id": scan_id,
        "asset": asset,
        "summary": severity_counts,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities": aggregated,
    }

    return report


def generate_report(
    db: Session,
    scan_job_id: int,
    asset_id: int,
    asset: str,
    findings: list[Mapping[str, object]],
) -> Report:
    """Generate and persist a structured vulnerability report.

    Creates both:
    - Report (JSON snapshot for API responses)
    - Vulnerability records (normalized for analytics queries)

    Args:
        db: Database session.
        scan_job_id: ID of the associated scan job.
        asset_id: ID of the asset being scanned.
        asset: Asset name/identifier.
        findings: Vulnerability findings from the vulnerability_engine.

    Returns:
        Persisted Report object with related vulnerabilities.

    Raises:
        ValueError: If the scan job cannot be found.
    """

    job = db.get(ScanJob, scan_job_id)
    if job is None:
        raise ValueError(f"Scan job {scan_job_id} not found.")

    scan_id = f"scan_{scan_job_id}"
    report_json = build_report_json(scan_id, asset, findings)
    severity_counts = report_json["summary"]
    total_vulnerabilities = report_json["total_vulnerabilities"]

    # Create report record
    report = Report(
        scan_job_id=scan_job_id,
        total_vulnerabilities=total_vulnerabilities,
        severity_counts=severity_counts,
        report_json=report_json,
        version=1,
    )
    db.add(report)
    db.flush()  # Get the report ID without committing

    # Create normalized vulnerability records for analytics
    seen_cves: dict[str, Vulnerability] = {}
    for finding in findings:
        cve = finding.get("cve", "unknown")

        # Only store first occurrence of each CVE in normalized table
        # (all ports/services are captured in affected_ports/affected_services)
        if cve not in seen_cves:
            vulnerability = Vulnerability(
                report_id=report.id,
                asset_id=asset_id,
                cve=cve,
                severity=finding.get("severity", "unknown"),
                cvss=finding.get("cvss"),
                description=finding.get("description", ""),
                references=finding.get("references", []),
                source=finding.get("source", ""),
                affected_ports=[finding.get("port")] if finding.get("port") else [],
                affected_services=[finding.get("service")] if finding.get("service") else [],
            )
            db.add(vulnerability)
            seen_cves[cve] = vulnerability
        else:
            # Append ports/services to existing CVE record in memory
            vuln = seen_cves[cve]

            port = finding.get("port")
            if port is not None and port not in vuln.affected_ports:
                vuln.affected_ports.append(port)

            service = finding.get("service")
            if service and service not in vuln.affected_services:
                vuln.affected_services.append(service)

    db.refresh(report)

    LOGGER.info(
        "Generated report for job %s on asset %s with %d unique vulnerabilities",
        scan_job_id,
        asset,
        total_vulnerabilities,
    )

    return report


def generate_report_for_scan(db: Session, scan_identifier: str | int) -> Report:
    """Generate a report for a scan if one does not already exist."""

    scan_job_id = parse_scan_identifier(scan_identifier)
    job = db.get(ScanJob, scan_job_id)
    if job is None:
        raise ValueError(f"Scan {scan_identifier} not found.")

    existing_report = db.query(Report).filter(Report.scan_job_id == scan_job_id).one_or_none()
    if existing_report is not None:
        return existing_report

    asset = db.get(Asset, job.asset_id)
    if asset is None:
        raise ValueError(f"Asset {job.asset_id} not found for scan {scan_identifier}.")

    vulnerability_result = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_job_id == scan_job_id,
            ScanResult.scanner == "vulnerability_engine",
        )
        .order_by(ScanResult.created_at.desc(), ScanResult.id.desc())
        .one_or_none()
    )
    if vulnerability_result is None:
        raise ValueError(f"Scan {scan_identifier} does not have vulnerability analysis results.")

    findings = vulnerability_result.result_json.get("vulnerabilities", [])
    if not isinstance(findings, list):
        raise ValueError(f"Scan {scan_identifier} returned an invalid vulnerability payload.")

    report = generate_report(db, scan_job_id, asset.id, asset.name, findings)
    db.commit()
    db.refresh(report)
    return report


def list_reports(db: Session) -> list[dict[str, object]]:
    """Return frontend-facing report metadata rows."""

    reports = db.query(Report).order_by(Report.created_at.desc(), Report.id.desc()).all()
    return [_serialize_report_metadata(report) for report in reports]


def get_report_metadata(db: Session, report_identifier: str | int) -> dict[str, object] | None:
    """Return one report metadata payload by report identifier."""

    report = _get_report(db, report_identifier)
    if report is None:
        return None
    return _serialize_report_metadata(report)


def get_report_download_payload(db: Session, report_identifier: str | int) -> tuple[str, dict[str, Any]] | None:
    """Return filename and JSON payload for a report download."""

    report = _get_report(db, report_identifier)
    if report is None:
        return None

    filename = f"{format_report_identifier(report.id).lower()}.json"
    payload = {
        "report_id": format_report_identifier(report.id),
        "scan_id": format_scan_identifier(report.scan_job_id),
        "created_at": report.created_at.isoformat(),
        "status": "ready",
        "version": report.version,
        "report": report.report_json,
    }
    return filename, payload


def _get_report(db: Session, report_identifier: str | int) -> Report | None:
    """Resolve one report by report identifier."""

    report_id = parse_report_identifier(report_identifier)
    return db.get(Report, report_id)


def _serialize_report_metadata(report: Report) -> dict[str, object]:
    """Build frontend-facing report metadata."""

    return {
        "report_id": format_report_identifier(report.id),
        "scan_id": format_scan_identifier(report.scan_job_id),
        "created_at": report.created_at,
        "status": "ready",
        "total_vulnerabilities": report.total_vulnerabilities,
        "severity_counts": report.severity_counts,
        "version": report.version,
    }
