"""Utility helpers for SwanScan."""

from __future__ import annotations

import socket
from collections.abc import Iterator, Sequence
from typing import List, Literal

ScanState = Literal["open", "closed", "filtered"]

def parse_ports(port_spec: str) -> List[int]:
    """Parse a port specification string into a sorted list of unique ports.

    Supported formats include:
    - ``1-1000``
    - ``22,80,443``
    - ``1-1024,3306``

    Args:
        port_spec: Port specification supplied by the caller.

    Returns:
        A sorted list of unique TCP port numbers.

    Raises:
        ValueError: If the specification is empty or contains invalid values.
    """

    if not port_spec or not port_spec.strip():
        raise ValueError("Port specification cannot be empty.")

    ports: set[int] = set()

    for raw_part in port_spec.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("Invalid port specification: empty segment.")

        if "-" in part:
            start_text, end_text = part.split("-", maxsplit=1)
            if not start_text or not end_text:
                raise ValueError(f"Invalid port range: {part!r}")

            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {part!r}") from exc

            if start > end:
                raise ValueError(f"Invalid port range: start greater than end in {part!r}")

            _validate_port(start)
            _validate_port(end)
            ports.update(range(start, end + 1))
            continue

        try:
            port = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid port value: {part!r}") from exc

        _validate_port(port)
        ports.add(port)

    return sorted(ports)


def _validate_port(port: int) -> None:
    """Validate that a port is within the TCP/UDP port range."""

    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} is out of range. Expected 1-65535.")


def chunked(items: Sequence[int], size: int) -> Iterator[list[int]]:
    """Yield a sequence in fixed-size batches."""

    if size < 1:
        raise ValueError("Batch size must be at least 1.")

    for index in range(0, len(items), size):
        yield list(items[index : index + size])


def resolve_target(target: str) -> str:
    """Resolve a hostname or IP string to an IPv4 address."""

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target {target!r}.") from exc


def guess_service_name(port: int, protocol: str = "tcp") -> str:
    """Return a best-effort service name for a port."""

    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"
