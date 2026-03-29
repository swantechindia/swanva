"""Platform access-context client and request-scoped dependency helpers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

import requests
from fastapi import Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from va_manager.config import (
    PLATFORM_ACCESS_CONTEXT_PATH,
    PLATFORM_API_BASE_URL,
    PLATFORM_AUTH_TIMEOUT_SECONDS,
    PLATFORM_AUTH_VERIFY_SSL,
)

INVALID_TOKEN_DETAIL = "Invalid or expired token."
PLATFORM_AUTH_UNAVAILABLE_DETAIL = "Platform auth unavailable."


class ModuleAccess(BaseModel):
    """Module-scoped role assignment returned by the platform."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    module: str
    role: str


class PlatformModuleAccess(BaseModel):
    """Module entry returned by the Swan Platform access-context API."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    name: str
    enabled: bool = True
    role: str


class PlatformUserAccess(BaseModel):
    """User payload returned by the Swan Platform access-context API."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    id: int
    email: str
    username: str | None = None
    platform_role: str | None = None


class PlatformAccessContext(BaseModel):
    """Access context returned by the Swan Platform auth service."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    id: int
    email: str
    platform_role: str | None = None
    modules: tuple[ModuleAccess, ...] = ()


class AccessContextEnvelope(BaseModel):
    """Platform access-context response envelope."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    data: dict[str, object]


@dataclass(slots=True)
class AccessContextFetchError(Exception):
    """Structured platform auth fetch failure."""

    status_code: int
    detail: str


@lru_cache(maxsize=1)
def get_platform_auth_session() -> requests.Session:
    """Create a reusable HTTP session for platform auth lookups."""

    return requests.Session()


def fetch_access_context(authorization: str) -> PlatformAccessContext:
    """Call the platform access-context endpoint and return parsed context."""

    normalized_authorization = authorization.strip()
    if not normalized_authorization:
        raise AccessContextFetchError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_TOKEN_DETAIL,
        )

    platform_url = _build_access_context_url()
    headers = {"Authorization": normalized_authorization}

    try:
        response = get_platform_auth_session().get(
            platform_url,
            headers=headers,
            timeout=PLATFORM_AUTH_TIMEOUT_SECONDS,
            verify=PLATFORM_AUTH_VERIFY_SSL,
        )
    except requests.RequestException as exc:
        raise AccessContextFetchError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=PLATFORM_AUTH_UNAVAILABLE_DETAIL,
        ) from exc

    if response.status_code == status.HTTP_401_UNAUTHORIZED:
        raise AccessContextFetchError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_TOKEN_DETAIL,
        )

    if response.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        raise AccessContextFetchError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=PLATFORM_AUTH_UNAVAILABLE_DETAIL,
        )

    if response.status_code >= status.HTTP_400_BAD_REQUEST:
        raise AccessContextFetchError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_TOKEN_DETAIL,
        )

    try:
        envelope = AccessContextEnvelope.model_validate(response.json())
    except (ValueError, TypeError) as exc:
        raise AccessContextFetchError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=PLATFORM_AUTH_UNAVAILABLE_DETAIL,
        ) from exc

    if not envelope.success:
        raise AccessContextFetchError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=PLATFORM_AUTH_UNAVAILABLE_DETAIL,
        )

    try:
        user_payload = PlatformUserAccess.model_validate(envelope.data["user"])
        module_payloads = tuple(
            ModuleAccess(module=module.name, role=module.role)
            for module in (
                PlatformModuleAccess.model_validate(item)
                for item in envelope.data.get("modules", [])
            )
            if module.enabled
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AccessContextFetchError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=PLATFORM_AUTH_UNAVAILABLE_DETAIL,
        ) from exc

    return PlatformAccessContext(
        id=user_payload.id,
        email=user_payload.email,
        platform_role=user_payload.platform_role,
        modules=module_payloads,
    )


async def get_access_context(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> PlatformAccessContext:
    """Return the request-scoped platform access context."""

    cached_context = getattr(request.state, "access_context", None)
    if isinstance(cached_context, PlatformAccessContext):
        return cached_context

    cached_error = getattr(request.state, "access_context_error", None)
    if isinstance(cached_error, AccessContextFetchError):
        raise HTTPException(status_code=cached_error.status_code, detail=cached_error.detail)

    if authorization is None or not authorization.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_TOKEN_DETAIL,
        )

    try:
        context = await run_in_threadpool(fetch_access_context, authorization)
    except AccessContextFetchError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    request.state.access_context = context
    return context


def _build_access_context_url() -> str:
    """Build the fully-qualified platform access-context URL."""

    base_url = (PLATFORM_API_BASE_URL or "").strip().rstrip("/")
    if not base_url:
        raise AccessContextFetchError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=PLATFORM_AUTH_UNAVAILABLE_DETAIL,
        )

    path = PLATFORM_ACCESS_CONTEXT_PATH if PLATFORM_ACCESS_CONTEXT_PATH.startswith("/") else f"/{PLATFORM_ACCESS_CONTEXT_PATH}"
    return f"{base_url}{path}"
