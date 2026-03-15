"""Asset database model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from va_manager.models import Base


class Asset(Base):
    """Target system metadata used to drive scanner execution.

    Credentials remain stored on the asset because some scanners need them at
    execution time, but callers must never serialize the encrypted password
    back to API clients.
    """

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    db_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scan_jobs = relationship("ScanJob", back_populates="asset", cascade="all, delete-orphan")

    @property
    def credential_stored(self) -> bool:
        """Return whether encrypted credentials are stored for this asset."""

        return bool((self.username or "").strip() or (self.password or "").strip())
