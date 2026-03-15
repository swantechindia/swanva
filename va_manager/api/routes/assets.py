"""Asset management API routes."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from va_manager.api.deps import get_current_user, get_db
from va_manager.models.asset import Asset
from va_manager.security.secrets import secret_manager

router = APIRouter()


class AssetCreateRequest(BaseModel):
    """Payload for creating a managed asset."""

    target: str
    asset_type: str | None = None
    protocol: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    db_type: str | None = None


class AssetResponse(BaseModel):
    """Serialized asset response.

    Passwords are intentionally never returned. Callers only learn whether
    stored credentials exist so the UI can indicate scan readiness without
    exposing reusable secrets.
    """

    id: int
    target: str
    asset_type: str | None = None
    protocol: str | None = None
    port: int | None = None
    username: str | None = None
    credential_stored: bool
    os_type: str | None = None
    os_version: str | None = None
    db_type: str | None = None
    created_at: datetime
    last_scanned: datetime | None = None


@router.post("", response_model=AssetResponse)
def create_asset(
    payload: AssetCreateRequest,
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
) -> AssetResponse:
    """Create and persist a new asset record with encrypted credentials."""

    payload_data = payload.model_dump()
    password = payload_data.pop("password", None)
    asset = Asset(**payload_data)
    if password:
        asset.password = secret_manager.encrypt(password)

    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_to_response(asset)


@router.get("", response_model=list[AssetResponse])
def list_assets(
    db: Session = Depends(get_db),
    _: dict[str, object] = Depends(get_current_user),
) -> list[AssetResponse]:
    """Return all known assets ordered by creation without exposing passwords."""

    assets = db.query(Asset).order_by(Asset.created_at.asc(), Asset.id.asc()).all()
    return [_asset_to_response(asset) for asset in assets]


def _asset_to_response(asset: Asset) -> AssetResponse:
    """Serialize asset metadata while suppressing password disclosure."""

    return AssetResponse(
        id=asset.id,
        target=asset.target,
        asset_type=asset.asset_type,
        protocol=asset.protocol,
        port=asset.port,
        username=asset.username,
        credential_stored=asset.credential_stored,
        os_type=asset.os_type,
        os_version=asset.os_version,
        db_type=asset.db_type,
        created_at=asset.created_at,
        last_scanned=asset.last_scanned,
    )
