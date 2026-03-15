"""Installed package collector."""

from __future__ import annotations

from swa_os_scanner.parsers.dpkg_parser import parse_dpkg_output
from swa_os_scanner.parsers.rpm_parser import parse_rpm_output
from swa_os_scanner.ssh import run_command


def collect_packages(ssh) -> list[dict[str, str]]:
    """Collect installed packages from Debian or RPM-based systems."""

    if not run_command(ssh, "which dpkg"):
        if not run_command(ssh, "which rpm"):
            return []

        raw_output = run_command(ssh, r"rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'")
        if not raw_output:
            return []

        return parse_rpm_output(raw_output)

    raw_output = run_command(ssh, "dpkg -l")
    if not raw_output:
        return []

    return parse_dpkg_output(raw_output)
