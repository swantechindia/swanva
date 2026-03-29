"""Top-level API router for Swan VA."""

from fastapi import APIRouter

from va_manager.api.routes import analytics, assets, reports, results, scans

router = APIRouter(prefix="/api/v1")

router.include_router(assets.router, prefix="/assets", tags=["assets"])
router.include_router(scans.router, prefix="/scans", tags=["scans"])
router.include_router(results.router, prefix="/results", tags=["results"])
router.include_router(reports.router, prefix="/reports", tags=["reports"])
router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
