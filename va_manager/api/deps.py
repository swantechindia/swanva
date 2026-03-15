"""Shared FastAPI dependencies for database access and auth."""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from va_manager.config import DATABASE_URL, JWT_ALGORITHM, SECRET_KEY


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


def get_current_user(authorization: str = Header(..., alias="Authorization")) -> dict[str, Any]:
    """Validate a SwanCore-issued bearer token and return its claims."""

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header.",
        )

    if not SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server authentication configuration is missing.",
        )

    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        ) from exc


CurrentUser = Depends(get_current_user)
DatabaseSession = Depends(get_db)
