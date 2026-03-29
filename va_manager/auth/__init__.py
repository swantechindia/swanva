"""Platform access-context auth helpers for the VA manager."""

from va_manager.auth.context import PlatformAccessContext, get_access_context
from va_manager.auth.rbac import (
    VA_ADMIN_ROLE,
    VA_MODULE_NAME,
    VA_USER_ROLE,
    VAAccessContext,
    VAAdminContext,
    get_va_role,
    require_va_access,
    require_va_admin,
)

__all__ = [
    "PlatformAccessContext",
    "VA_ADMIN_ROLE",
    "VA_MODULE_NAME",
    "VA_USER_ROLE",
    "VAAccessContext",
    "VAAdminContext",
    "get_access_context",
    "get_va_role",
    "require_va_access",
    "require_va_admin",
]
