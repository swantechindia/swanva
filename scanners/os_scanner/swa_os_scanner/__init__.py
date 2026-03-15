"""SSH-based system information scanner for SwanVA."""

from __future__ import annotations

from typing import Any

__all__ = ["scan_host"]


def scan_host(*args: Any, **kwargs: Any):
    """Lazily dispatch to the scanner entrypoint."""

    from swa_os_scanner.scanner import scan_host as _scan_host

    return _scan_host(*args, **kwargs)
