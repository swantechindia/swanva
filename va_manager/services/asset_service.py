"""Asset CRUD service layer."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from va_manager.api.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetType,
    AssetUpdate,
    normalize_asset_config,
    sanitize_asset_config,
)
from va_manager.models.asset import Asset
from va_manager.models.scan_job import ScanJob
from va_manager.security.secrets import decrypt_secret, encrypt_secret


class AssetNotFoundError(ValueError):
    """Raised when an asset does not exist."""


class DuplicateAssetTargetError(ValueError):
    """Raised when an asset target already exists."""


@dataclass(frozen=True)
class AssetExecutionView:
    """Short-lived asset projection used only during scan execution."""

    id: int
    name: str
    target: str
    asset_type: AssetType
    config: dict[str, Any]
    description: str | None


def create_asset(db: Session, payload: AssetCreate) -> Asset:
    """Create and persist a new asset with encrypted credentials."""

    normalized = normalize_asset_config(payload.asset_type, payload.config)
    encrypted_config = _encrypt_config_credentials(normalized.config)
    _ensure_unique_target(db, normalized.target)

    asset = Asset(
        name=payload.name,
        target=normalized.target,
        asset_type=payload.asset_type.value,
        config=encrypted_config,
        description=payload.description,
    )
    db.add(asset)
    _commit_and_refresh(db, asset)
    return asset


def list_assets(db: Session) -> list[Asset]:
    """Return all assets ordered for stable API presentation."""

    statement = select(Asset).order_by(Asset.created_at.asc(), Asset.id.asc())
    return list(db.scalars(statement).all())


def get_asset(db: Session, asset_id: int) -> Asset:
    """Return one asset or raise when it does not exist."""

    asset = db.get(Asset, asset_id)
    if asset is None:
        raise AssetNotFoundError(f"Asset {asset_id} not found.")
    return asset


def update_asset(db: Session, asset_id: int, payload: AssetUpdate) -> Asset:
    """Update one asset and re-encrypt credentials when needed."""

    asset = get_asset(db, asset_id)
    updates = payload.model_dump(exclude_unset=True)

    if "name" in updates:
        asset.name = updates["name"]
    if "description" in updates:
        asset.description = updates["description"]

    current_asset_type = AssetType(asset.asset_type)
    current_config = _decrypt_config_credentials(asset.config or {})
    merged_config = _deep_merge_dicts(current_config, updates.get("config"))
    effective_asset_type = updates.get("asset_type", current_asset_type)

    normalized = normalize_asset_config(effective_asset_type, merged_config)
    if normalized.target != asset.target:
        _ensure_unique_target(db, normalized.target, exclude_asset_id=asset.id)

    asset.asset_type = effective_asset_type.value
    asset.target = normalized.target
    asset.config = _encrypt_config_credentials(normalized.config)

    _commit_and_refresh(db, asset)
    return asset


def delete_asset(db: Session, asset_id: int) -> None:
    """Delete one asset or raise when it does not exist."""

    asset = get_asset(db, asset_id)
    db.delete(asset)
    db.commit()


def get_asset_with_secrets(db: Session, asset_id: int) -> AssetExecutionView:
    """Return a short-lived execution view with decrypted credentials."""

    asset = get_asset(db, asset_id)
    decrypted_config = _decrypt_config_credentials(asset.config or {})
    return AssetExecutionView(
        id=asset.id,
        name=asset.name,
        target=asset.target,
        asset_type=AssetType(asset.asset_type),
        config=decrypted_config,
        description=asset.description,
    )


def build_asset_response(asset: Asset) -> AssetResponse:
    """Serialize an asset for API responses without exposing passwords."""

    return AssetResponse(
        id=asset.id,
        name=asset.name,
        target=asset.target,
        asset_type=AssetType(asset.asset_type),
        config=sanitize_asset_config(asset.config or {}),
        description=asset.description,
        last_connection_status=asset.last_connection_status,
        last_checked_at=asset.last_checked_at,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def list_assets_page(
    db: Session,
    page: int = 1,
    limit: int = 20,
    asset_type: str | None = None,
    search: str | None = None,
) -> dict[str, object]:
    """Return paginated asset summaries for the frontend assets page."""

    last_scan_subquery = (
        db.query(
            ScanJob.asset_id.label("asset_id"),
            func.max(ScanJob.completed_at).label("last_scanned_at"),
        )
        .filter(ScanJob.completed_at.is_not(None))
        .group_by(ScanJob.asset_id)
        .subquery()
    )

    query = (
        db.query(Asset, last_scan_subquery.c.last_scanned_at)
        .outerjoin(last_scan_subquery, last_scan_subquery.c.asset_id == Asset.id)
    )

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type.strip().lower())

    if search:
        search_term = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                func.lower(Asset.name).like(search_term),
                func.lower(Asset.target).like(search_term),
            )
        )

    total = query.order_by(None).count()
    rows = (
        query.order_by(Asset.created_at.desc(), Asset.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    items = [
        _build_asset_list_item(asset, last_scanned_at)
        for asset, last_scanned_at in rows
    ]

    return {
        "items": items,
        "page": page,
        "limit": limit,
        "total": total,
    }


def list_ready_assets(db: Session) -> list[dict[str, object]]:
    """Return assets that can be shown in the run-scan UI."""

    last_scan_subquery = (
        db.query(
            ScanJob.asset_id.label("asset_id"),
            func.max(ScanJob.completed_at).label("last_scanned_at"),
        )
        .filter(ScanJob.completed_at.is_not(None))
        .group_by(ScanJob.asset_id)
        .subquery()
    )

    rows = (
        db.query(Asset, last_scan_subquery.c.last_scanned_at)
        .outerjoin(last_scan_subquery, last_scan_subquery.c.asset_id == Asset.id)
        .order_by(Asset.name.asc(), Asset.id.asc())
        .all()
    )

    return [
        {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "asset_type": asset.asset_type,
            "target": asset.target,
            "last_scanned_at": last_scanned_at,
            "status": "ready",
        }
        for asset, last_scanned_at in rows
    ]


def _encrypt_config_credentials(config: dict[str, Any]) -> dict[str, Any]:
    """Encrypt credential passwords before persistence."""

    encrypted = deepcopy(config)
    credentials = encrypted.get("credentials")
    if isinstance(credentials, dict):
        password = str(credentials.get("password") or "").strip()
        if password:
            credentials["password"] = encrypt_secret(password)
    return encrypted


def _decrypt_config_credentials(config: dict[str, Any]) -> dict[str, Any]:
    """Decrypt credential passwords only for the runtime execution path."""

    decrypted = deepcopy(config)
    credentials = decrypted.get("credentials")
    if isinstance(credentials, dict):
        password = str(credentials.get("password") or "").strip()
        if password:
            credentials["password"] = decrypt_secret(password)
    return decrypted


def _deep_merge_dicts(base: dict[str, Any], updates: dict[str, Any] | None) -> dict[str, Any]:
    """Merge nested config updates without dropping existing keys."""

    if updates is None:
        return deepcopy(base)

    merged = deepcopy(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _ensure_unique_target(db: Session, target: str, exclude_asset_id: int | None = None) -> None:
    """Reject duplicate asset targets before writing."""

    statement = select(Asset).where(Asset.target == target)
    if exclude_asset_id is not None:
        statement = statement.where(Asset.id != exclude_asset_id)

    existing = db.scalar(statement)
    if existing is not None:
        raise DuplicateAssetTargetError(f"Asset target '{target}' already exists.")


def _commit_and_refresh(db: Session, asset: Asset) -> None:
    """Persist an asset and translate DB uniqueness failures."""

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateAssetTargetError(f"Asset target '{asset.target}' already exists.") from exc
    db.refresh(asset)


def _build_asset_list_item(asset: Asset, last_scanned_at: datetime | None) -> dict[str, object]:
    """Serialize the frontend assets-list view."""

    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "target": asset.target,
        "created_at": asset.created_at,
        "last_scanned_at": last_scanned_at,
        "last_connection_status": asset.last_connection_status,
    }
