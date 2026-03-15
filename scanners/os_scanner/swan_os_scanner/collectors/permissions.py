"""Sensitive file permission collector."""

from __future__ import annotations

from swan_os_scanner.ssh import run_command

SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
]


def collect_permissions(ssh) -> dict[str, dict[str, str]]:
    """Collect `ls -l` permission data for important files."""

    file_permissions: dict[str, str] = {}

    for path in SENSITIVE_PATHS:
        file_permissions[path] = run_command(ssh, f"ls -l {path} 2>/dev/null")

    return {
        "file_permissions": file_permissions,
    }
