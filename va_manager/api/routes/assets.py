"""Asset management API routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from va_manager.api.deps import get_db
from va_manager.api.schemas.asset import (
    AssetConnectionTestRequest,
    AssetCreate,
    AssetDeleteEnvelope,
    AssetDeleteResult,
    AssetEnvelope,
    AssetUpdate,
    ConnectionTestEnvelope,
)
from va_manager.auth.rbac import VAAccessContext, VAAdminContext
from va_manager.services.connection_service import test_asset_connection, test_unsaved_asset_connection
from va_manager.services.asset_service import (
    AssetNotFoundError,
    DuplicateAssetTargetError,
    build_asset_response,
    create_asset,
    delete_asset,
    get_asset,
    list_assets_page,
    update_asset,
)

router = APIRouter()
LOGGER = logging.getLogger(__name__)


@router.post("", response_model=AssetEnvelope)
def create_asset_route(
    payload: AssetCreate,
    _: VAAdminContext,
    db: Session = Depends(get_db),
) -> AssetEnvelope:
    """Create a new managed asset."""

    try:
        asset = create_asset(db, payload)
    except DuplicateAssetTargetError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AssetEnvelope(data=build_asset_response(asset))


@router.get("")
def list_assets_route(
    _: VAAccessContext,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=500),
    type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return all managed assets."""

    payload = list_assets_page(db, page=page, limit=limit, asset_type=type, search=search)
    return {"success": True, "data": payload}


@router.post("/test-connection", response_model=ConnectionTestEnvelope)
def test_unsaved_connection_route(
    payload: AssetConnectionTestRequest,
    _: VAAdminContext,
) -> ConnectionTestEnvelope | JSONResponse:
    """Test one draft asset connection without saving it."""

    try:
        return test_unsaved_asset_connection(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        LOGGER.exception("Unexpected error while testing unsaved asset connection.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "error": "Unexpected error while testing asset connection."},
        )


@router.get("/{asset_id}", response_model=AssetEnvelope)
def get_asset_route(
    asset_id: int,
    _: VAAccessContext,
    db: Session = Depends(get_db),
) -> AssetEnvelope:
    """Return one asset by identifier."""

    try:
        asset = get_asset(db, asset_id)
    except AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return AssetEnvelope(data=build_asset_response(asset))


@router.put("/{asset_id}", response_model=AssetEnvelope)
def update_asset_route(
    asset_id: int,
    payload: AssetUpdate,
    _: VAAdminContext,
    db: Session = Depends(get_db),
) -> AssetEnvelope:
    """Update an existing asset."""

    try:
        asset = update_asset(db, asset_id, payload)
    except AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except DuplicateAssetTargetError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AssetEnvelope(data=build_asset_response(asset))


@router.post("/{asset_id}/test-connection", response_model=ConnectionTestEnvelope)
def test_connection_route(
    asset_id: int,
    _: VAAdminContext,
    db: Session = Depends(get_db),
) -> ConnectionTestEnvelope | JSONResponse:
    """Test one asset connection and persist the latest health status."""

    try:
        return test_asset_connection(db, asset_id)
    except AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        LOGGER.exception("Unexpected error while testing saved asset connection. asset_id=%s", asset_id)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "error": "Unexpected error while testing asset connection."},
        )


@router.delete("/{asset_id}", response_model=AssetDeleteEnvelope)
def delete_asset_route(
    asset_id: int,
    _: VAAdminContext,
    db: Session = Depends(get_db),
) -> AssetDeleteEnvelope:
    """Delete one asset."""

    try:
        delete_asset(db, asset_id)
    except AssetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return AssetDeleteEnvelope(data=AssetDeleteResult(id=asset_id))
