"""Centralized runtime configuration for the VA manager."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

load_dotenv(ENV_PATH)


def _get_bool_env(name: str, default: bool) -> bool:
    """Parse a boolean environment variable with a safe default."""

    value = os.getenv(name)
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}

DATABASE_URL = os.getenv("DATABASE_URL")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

SSL_CERT_PATH = os.getenv("SSL_CERT_PATH")
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH")

VA_BACKEND_HOST = os.getenv("VA_BACKEND_HOST", "0.0.0.0")
VA_BACKEND_PORT = int(os.getenv("VA_BACKEND_PORT", "9000"))

VA_BACKEND_URL = os.getenv("VA_BACKEND_URL")
VA_FRONTEND_URL = os.getenv("VA_FRONTEND_URL")

PLATFORM_API_BASE_URL = os.getenv("PLATFORM_API_BASE_URL") or os.getenv("SWAN_PLATFORM_URL")
PLATFORM_ACCESS_CONTEXT_PATH = os.getenv("PLATFORM_ACCESS_CONTEXT_PATH", "/api/v1/auth/access-context")
PLATFORM_AUTH_TIMEOUT_SECONDS = float(os.getenv("PLATFORM_AUTH_TIMEOUT_SECONDS", "5"))
PLATFORM_AUTH_VERIFY_SSL = _get_bool_env("PLATFORM_AUTH_VERIFY_SSL", True)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY") or os.getenv("SECRET_KEY")
