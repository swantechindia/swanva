"""OS metadata collector."""

from __future__ import annotations

from swan_os_scanner.system_detector import detect_os


def collect_os_info(ssh) -> dict[str, str]:
    """Collect operating system metadata."""

    return detect_os(ssh)
