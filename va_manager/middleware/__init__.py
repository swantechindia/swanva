"""Middleware for the VA manager."""

from va_manager.middleware.auth_middleware import AuthContextMiddleware

__all__ = ["AuthContextMiddleware"]
