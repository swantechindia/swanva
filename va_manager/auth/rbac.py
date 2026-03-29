"""Centralized VA module RBAC dependencies."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import Depends, HTTPException, status

from va_manager.auth.context import PlatformAccessContext, get_access_context

VA_MODULE_NAME = "VA"
VA_ADMIN_ROLE = "admin"
VA_USER_ROLE = "user"

NO_VA_ACCESS_DETAIL = "No VA access."
INSUFFICIENT_VA_ROLE_DETAIL = "Insufficient VA role."

VARole = Literal["admin", "user"]


def get_va_role(context: PlatformAccessContext) -> VARole:
    """Return the effective VA role from the platform access context."""

    roles = {
        module.role.strip().lower()
        for module in context.modules
        if module.module.strip().upper() == VA_MODULE_NAME
    }

    if not roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=NO_VA_ACCESS_DETAIL,
        )

    if VA_ADMIN_ROLE in roles:
        return VA_ADMIN_ROLE
    if VA_USER_ROLE in roles:
        return VA_USER_ROLE

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=NO_VA_ACCESS_DETAIL,
    )


async def require_va_access(
    context: Annotated[PlatformAccessContext, Depends(get_access_context)],
) -> PlatformAccessContext:
    """Allow any caller with a VA user or admin role."""

    get_va_role(context)
    return context


async def require_va_admin(
    context: Annotated[PlatformAccessContext, Depends(get_access_context)],
) -> PlatformAccessContext:
    """Allow only VA admins."""

    role = get_va_role(context)
    if role != VA_ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=INSUFFICIENT_VA_ROLE_DETAIL,
        )

    return context


VAAccessContext = Annotated[PlatformAccessContext, Depends(require_va_access)]
VAAdminContext = Annotated[PlatformAccessContext, Depends(require_va_admin)]
