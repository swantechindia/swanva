"""Network configuration collector."""

from __future__ import annotations

from swan_os_scanner.ssh import run_command


def collect_network(ssh) -> dict[str, object]:
    """Collect interface, route, and listening socket information."""

    interfaces_output = run_command(ssh, "ip addr")
    routes_output = run_command(ssh, "ip route")
    ports_output = run_command(ssh, "ss -tulnp")

    return {
        "interfaces": _parse_interfaces(interfaces_output),
        "routes": routes_output,
        "listening_ports": _parse_listening_ports(ports_output),
    }


def _parse_interfaces(raw_output: str) -> list[dict[str, object]]:
    """Parse `ip addr` output into interface and address records."""

    interfaces: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    for line in raw_output.splitlines():
        if not line:
            continue

        if line[0].isdigit():
            if current is not None:
                interfaces.append(current)

            _, remainder = line.split(": ", maxsplit=1)
            name = remainder.split(":", maxsplit=1)[0]
            current = {
                "name": name,
                "addresses": [],
            }
            continue

        if current is None:
            continue

        stripped = line.strip()
        if stripped.startswith("inet ") or stripped.startswith("inet6 "):
            address = stripped.split()[1]
            addresses = current.setdefault("addresses", [])
            if isinstance(addresses, list):
                addresses.append(address)

    if current is not None:
        interfaces.append(current)

    return interfaces


def _parse_listening_ports(raw_output: str) -> list[dict[str, str]]:
    """Parse `ss -tulnp` output into listening socket records."""

    listening_ports: list[dict[str, str]] = []

    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Netid"):
            continue

        parts = stripped.split()
        if len(parts) < 6:
            continue

        process = ""
        if len(parts) >= 7:
            process = " ".join(parts[6:])

        listening_ports.append(
            {
                "protocol": parts[0],
                "state": parts[1],
                "local_address": parts[4],
                "process": process,
            }
        )

    return listening_ports
