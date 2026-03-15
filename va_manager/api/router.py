"""Top-level API router for Swan VA."""

from fastapi import APIRouter

from va_manager.api.routes import assets, results, scans

router = APIRouter(prefix="/api/v1")

router.include_router(assets.router, prefix="/assets", tags=["assets"])
router.include_router(scans.router, prefix="/scans", tags=["scans"])
router.include_router(results.router, prefix="/results", tags=["results"])
