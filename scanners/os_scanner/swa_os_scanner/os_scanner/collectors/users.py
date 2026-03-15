"""System user collector."""

from __future__ import annotations

from os_scanner.ssh import run_command


def collect_users(ssh) -> list[str]:
    """Collect local system account names."""

    raw_output = run_command(ssh, "cut -d: -f1 /etc/passwd", check=True)
    return [line for line in raw_output.splitlines() if line]
