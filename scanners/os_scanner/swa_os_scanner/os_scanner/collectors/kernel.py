"""Kernel version collector."""

from __future__ import annotations

from os_scanner.ssh import run_command


def collect_kernel(ssh) -> str:
    """Collect the running kernel version."""

    return run_command(ssh, "uname -r", check=True)
