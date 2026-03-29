"""SQLAlchemy models for the VA manager."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for VA manager tables."""


from va_manager.models.asset import Asset  # noqa: E402
from va_manager.models.report import Report  # noqa: E402
from va_manager.models.scan_job import ScanJob  # noqa: E402
from va_manager.models.scan_result import ScanResult  # noqa: E402
from va_manager.models.vulnerability import Vulnerability  # noqa: E402
from va_manager.vulnerability_engine.database.models import (  # noqa: E402
    CPEEntry,
    CPEDictionaryEntry,
    CVSSScore,
    FeedMetadata,
    Vulnerability as EnginedVulnerability,
    VulnerabilityReference,
)

__all__ = [
    "Asset",
    "Base",
    "CPEEntry",
    "CPEDictionaryEntry",
    "CVSSScore",
    "FeedMetadata",
    "Report",
    "ScanJob",
    "ScanResult",
    "Vulnerability",
    "VulnerabilityReference",
]
