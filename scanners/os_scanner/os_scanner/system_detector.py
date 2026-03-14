"""System detection helpers for remote Linux hosts."""

from __future__ import annotations

from os_scanner.ssh import run_command


def detect_os(ssh) -> dict[str, str]:
    """Detect operating system details from /etc/os-release."""

    raw_output = run_command(ssh, "cat /etc/os-release", check=True)
    return _parse_os_release(raw_output)


def _parse_os_release(raw_output: str) -> dict[str, str]:
    """Parse /etc/os-release content into a compact structured record."""

    values: dict[str, str] = {}
    for line in raw_output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        values[key.strip()] = value.strip().strip('"')

    return {
        "name": values.get("NAME", ""),
        "version": values.get("VERSION_ID", values.get("VERSION", "")),
        "id": values.get("ID", ""),
    }
