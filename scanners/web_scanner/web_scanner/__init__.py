"""Plugin-based web scanner package for SwanVA."""

from __future__ import annotations

from typing import Any

__all__ = ["start_scan", "stream_scan"]


def start_scan(*args: Any, **kwargs: Any):
    """Lazily dispatch to the web scanner entrypoint."""

    from .scanner import start_scan as _start_scan

    return _start_scan(*args, **kwargs)


def stream_scan(*args: Any, **kwargs: Any):
    """Lazily dispatch to the streaming scanner entrypoint."""

    from .scanner import stream_scan as _stream_scan

    return _stream_scan(*args, **kwargs)
