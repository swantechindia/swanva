"""Installed software binary collector."""

from __future__ import annotations

from swa_os_scanner.ssh import run_command

SOFTWARE_COMMANDS = {
    "docker": ("docker", "docker --version"),
    "python": ("python3", "python3 --version"),
    "java": ("java", "java -version 2>&1"),
    "node": ("node", "node --version"),
    "nginx": ("nginx", "nginx -v 2>&1"),
}


def collect_software(ssh) -> dict[str, str]:
    """Collect versions for common installed software binaries."""

    software: dict[str, str] = {}

    for name, (binary, version_command) in SOFTWARE_COMMANDS.items():
        if not run_command(ssh, f"which {binary}"):
            continue

        version_output = run_command(ssh, version_command)
        version = _extract_version(version_output, name)
        if version:
            software[name] = version

    return software


def _extract_version(output: str, fallback_name: str) -> str:
    """Normalize a version command response into a compact version string."""

    if not output:
        return ""

    first_line = output.splitlines()[0].strip()
    if not first_line:
        return ""

    tokens = first_line.replace(",", " ").split()
    for token in tokens:
        candidate = token.lstrip("v")
        if "/" in candidate:
            _, suffix = candidate.rsplit("/", maxsplit=1)
            if any(char.isdigit() for char in suffix):
                return suffix
        if any(char.isdigit() for char in candidate):
            if candidate.lower() == fallback_name.lower():
                continue
            return candidate

    return first_line
