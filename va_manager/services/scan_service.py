"""Database services for scan job lifecycle operations."""

from __future__ import annotations

from sqlalchemy.orm import Session

from va_manager.models.scan_job import ScanJob
from va_manager.services.asset_service import AssetExecutionView, get_asset, get_asset_with_secrets
from va_manager.services.scan_config import normalize_scan_request


def create_scan_job(
    db: Session,
    asset_id: int,
    scanner_type: str,
    config: dict[str, object] | None,
) -> ScanJob:
    """Create and persist a queued scan job with validated config."""

    asset = get_asset(db, asset_id)
    target = asset.target
    _validate_asset_supports_scanner(asset.asset_type, scanner_type)

    normalized_scanner_type, normalized_config = normalize_scan_request(scanner_type, config)
    if not target:
        raise ValueError(f"Asset {asset_id} is missing a scan target.")

    job = ScanJob(
        asset_id=asset_id,
        scanner_type=normalized_scanner_type,
        scan_config=normalized_config,
        status="queued",
        stage="queued",
        progress=0,
    )

    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan_asset(db: Session, asset_id: int, scanner_type: str) -> AssetExecutionView:
    """Load one asset for execution with decrypted credentials when applicable."""

    asset = get_asset_with_secrets(db, asset_id)
    _validate_asset_supports_scanner(asset.asset_type.value, scanner_type)
    return asset


def delete_scan_job(db: Session, job_id: int) -> bool:
    """Delete a non-running scan job and its related records."""

    job = db.get(ScanJob, job_id)
    if job is None:
        return False

    if job.status == "running":
        raise ValueError("Running scan jobs cannot be deleted.")

    db.delete(job)
    db.commit()
    return True


def _validate_asset_supports_scanner(asset_type: str, scanner_type: str) -> None:
    """Ensure one scanner type is valid for the selected asset category."""

    normalized_asset_type = asset_type.strip().lower()
    normalized_scanner_type = scanner_type.strip().lower()

    if normalized_scanner_type == "os" and normalized_asset_type != "endpoint":
        raise ValueError("OS scans require an endpoint asset.")
    if normalized_scanner_type == "db" and normalized_asset_type != "database":
        raise ValueError("Database scans require a database asset.")
    if normalized_scanner_type == "web" and normalized_asset_type != "web":
        raise ValueError("Web scans require a web asset.")
