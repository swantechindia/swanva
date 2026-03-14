"""SYN stealth scanning support for SwanScan."""

from __future__ import annotations

import logging

from swanscan.utils import ScanState, resolve_target

LOGGER = logging.getLogger(__name__)


def scan_syn_port(target: str, port: int, timeout: float) -> ScanState:
    """Perform a SYN scan against a single TCP port using Scapy.

    Args:
        target: IP address or hostname to scan.
        port: TCP port number.
        timeout: Packet response timeout in seconds.

    Returns:
        ``open`` for SYN/ACK, ``closed`` for RST, and ``filtered`` on no reply
        or when an ICMP unreachable response is observed.

    Raises:
        RuntimeError: If Scapy is unavailable or raw packet privileges are missing.
    """

    try:
        from scapy.all import ICMP, IP, TCP, conf, send, sr1  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        raise RuntimeError("SYN scanning requires the 'scapy' package to be installed.") from exc

    resolved_target = resolve_target(target)
    conf.verb = 0
    packet = IP(dst=resolved_target) / TCP(dport=port, flags="S")

    try:
        response = sr1(packet, timeout=timeout, verbose=0)
    except PermissionError as exc:
        raise RuntimeError("SYN scanning requires elevated privileges.") from exc
    except OSError as exc:
        raise RuntimeError(f"SYN scan failed for {target}:{port}: {exc}") from exc

    if response is None:
        return "filtered"

    if response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        flags = int(tcp_layer.flags)
        if flags & 0x12 == 0x12:
            send(
                IP(dst=resolved_target)
                / TCP(sport=int(tcp_layer.dport), dport=port, flags="R", seq=int(tcp_layer.ack)),
                verbose=0,
            )
            return "open"
        if (flags & 0x04) or ((flags & 0x14) == 0x14):
            return "closed"

    if response.haslayer(ICMP):
        LOGGER.debug("ICMP response received during SYN scan for %s:%s", target, port)
        return "filtered"

    return "filtered"
