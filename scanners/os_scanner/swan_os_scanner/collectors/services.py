"""Running service collector."""

from __future__ import annotations

from swan_os_scanner.ssh import run_command


def collect_services(ssh) -> list[str]:
    """Collect running systemd service names."""

    if not run_command(ssh, "which systemctl"):
        return []

    raw_output = run_command(
        ssh,
        "systemctl list-units --type=service --state=running --no-legend --no-pager",
    )
    services: list[str] = []

    for line in raw_output.splitlines():
        parts = line.split()
        if not parts:
            continue
        service_name = parts[0]
        if service_name.endswith(".service"):
            services.append(service_name)

    return services
