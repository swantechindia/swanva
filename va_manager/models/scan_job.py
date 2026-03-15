"""Scan job queue model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from va_manager.models import Base


class ScanJob(Base):
    """Queued scanner execution request.

    Status values distinguish the raw scan lifecycle from optional
    post-processing:
    - queued
    - running
    - scan_completed
    - analysis_completed
    - failed
    """

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_scan_jobs_progress_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    scanner_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False, index=True)
    stage: Mapped[str | None] = mapped_column(String(100), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    asset = relationship("Asset", back_populates="scan_jobs")
    scan_results = relationship("ScanResult", back_populates="scan_job", cascade="all, delete-orphan")

    @property
    def finished_at(self) -> datetime | None:
        """Compatibility alias for the job completion timestamp."""

        return self.completed_at

    @finished_at.setter
    def finished_at(self, value: datetime | None) -> None:
        """Store finished timestamps in the existing completion column."""

        self.completed_at = value
