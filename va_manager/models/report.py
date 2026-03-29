"""Structured vulnerability report model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from va_manager.models import Base


class Report(Base):
    """First-class structured vulnerability report for a completed scan."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_report_scan_job_id", "scan_job_id"),
        Index("ix_report_created_at", "created_at"),
        Index("ix_report_total_vuls", "total_vulnerabilities"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    severity_counts: Mapped[dict[str, int]] = mapped_column(
        JSON,
        default={"critical": 0, "high": 0, "medium": 0, "low": 0},
        nullable=False,
    )
    report_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    scan_job = relationship("ScanJob", back_populates="report")
    vulnerabilities = relationship("Vulnerability", back_populates="report", cascade="all, delete-orphan")
