"""Shared FastAPI dependencies for database access."""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from va_manager.config import DATABASE_URL


@lru_cache(maxsize=1)
def get_engine():
    """Create and cache the SQLAlchemy engine from environment configuration."""

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured.")

    database_url = DATABASE_URL
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, future=True, connect_args=connect_args)


@lru_cache(maxsize=1)
def get_session_factory():
    """Create and cache the SQLAlchemy session factory."""

    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session for the duration of the request."""

    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
