"""UDP scanning support for pscan."""

from __future__ import annotations

import logging

from pscan.utils import ScanState, resolve_target

LOGGER = logging.getLogger(__name__)


def scan_udp_port(target: str, port: int, timeout: float) -> ScanState:
    """Perform a UDP scan against a single port using Scapy.

    Args:
        target: IP address or hostname to scan.
        port: UDP port number.
        timeout: Packet response timeout in seconds.

    Returns:
        ``open`` when a UDP response is received, ``closed`` for ICMP port
        unreachable, and ``filtered`` otherwise.

    Raises:
        RuntimeError: If Scapy is unavailable or raw packet privileges are missing.
    """

    try:
        from scapy.all import ICMP, IP, UDP, conf, sr1  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        raise RuntimeError("UDP scanning requires the 'scapy' package to be installed.") from exc

    resolved_target = resolve_target(target)
    conf.verb = 0
    packet = IP(dst=resolved_target) / UDP(dport=port)

    try:
        response = sr1(packet, timeout=timeout, verbose=0)
    except PermissionError as exc:
        raise RuntimeError("UDP scanning requires elevated privileges.") from exc
    except OSError as exc:
        raise RuntimeError(f"UDP scan failed for {target}:{port}: {exc}") from exc

    if response is None:
        return "filtered"

    if response.haslayer(UDP):
        return "open"

    if response.haslayer(ICMP):
        icmp = response.getlayer(ICMP)
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            return "closed"
        LOGGER.debug(
            "ICMP unreachable response received during UDP scan for %s:%s (type=%s code=%s)",
            target,
            port,
            icmp.type,
            icmp.code,
        )
        return "filtered"

    return "filtered"
