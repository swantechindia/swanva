"""Scheduled task collector."""

from __future__ import annotations

from os_scanner.ssh import run_command


def collect_cron(ssh) -> dict[str, object]:
    """Collect user and system cron configuration."""

    user_cron = run_command(ssh, "crontab -l 2>/dev/null")
    raw_files = run_command(ssh, "sh -lc 'ls -1d /etc/cron* 2>/dev/null'")

    system_cron_files = [line.strip() for line in raw_files.splitlines() if line.strip()]

    return {
        "user_cron": user_cron,
        "system_cron_files": system_cron_files,
    }
