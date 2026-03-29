"""Top-level API router for Swan VA."""

from fastapi import APIRouter

from va_manager.api.routes import analytics, assets, dashboard, reports, results, scans, vulnerabilities

router = APIRouter(prefix="/api/v1")

router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
router.include_router(assets.router, prefix="/assets", tags=["assets"])
router.include_router(scans.router, prefix="/scans", tags=["scans"])
router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
router.include_router(results.router, prefix="/results", tags=["results"])
router.include_router(reports.router, prefix="/reports", tags=["reports"])
router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
