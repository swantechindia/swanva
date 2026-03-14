"""Public interface for the Swan web scanner."""

from __future__ import annotations

from collections.abc import Generator

from .engine import run_plugins, scan_stream


def start_scan(target: str, tools: list[str] | None = None) -> dict[str, object]:
    """Run the selected scanners and return a normalized scan report."""

    report = run_plugins(target, tools)
    return report.model_dump()


def stream_scan(target: str, tools: list[str] | None = None) -> Generator[dict[str, str], None, None]:
    """Yield normalized findings in real time."""

    for finding in scan_stream(target, tools):
        yield finding.model_dump()
