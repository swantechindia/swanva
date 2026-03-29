"""Vulnerability assessment manager package for SwanVA."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = ["VAManager", "get_scan_status", "start_scan"]

if TYPE_CHECKING:
    from va_manager.manager import VAManager


def __getattr__(name: str) -> Any:
    """Lazily expose manager entry points without eager runtime imports."""

    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from va_manager.manager import VAManager, get_scan_status, start_scan

    exports = {
        "VAManager": VAManager,
        "get_scan_status": get_scan_status,
        "start_scan": start_scan,
    }
    return exports[name]
