"""Request-scoped platform auth context caching middleware."""

from __future__ import annotations

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from va_manager.auth.context import AccessContextFetchError, fetch_access_context


class AuthContextMiddleware(BaseHTTPMiddleware):
    """Prefetch and cache the platform access context once per request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        authorization = request.headers.get("Authorization")
        if authorization and authorization.strip():
            try:
                request.state.access_context = await run_in_threadpool(fetch_access_context, authorization)
            except AccessContextFetchError as exc:
                request.state.access_context_error = exc

        return await call_next(request)
