"""TCP scanning primitives for pscan."""

from __future__ import annotations

import logging
import socket

LOGGER = logging.getLogger(__name__)


def scan_port(target: str, port: int, timeout: float) -> str:
    """Perform a TCP connect scan against a single port.

    Args:
        target: IP address or hostname to scan.
        port: TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        One of ``open``, ``closed``, or ``filtered``.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
    except socket.timeout:
        LOGGER.debug("TCP scan timed out for %s:%s", target, port)
        return "filtered"
    except socket.gaierror as exc:
        LOGGER.error("Failed to resolve target %r while scanning port %s: %s", target, port, exc)
        return "filtered"
    except OSError as exc:
        LOGGER.debug("Socket error while scanning %s:%s: %s", target, port, exc)
        return "filtered"

    if result == 0:
        return "open"

    return "closed"
