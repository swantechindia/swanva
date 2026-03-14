"""Service detection and banner grabbing for SwanScan."""

from __future__ import annotations

import re
import socket
from typing import TypedDict

from swanscan.utils import guess_service_name

HTTP_PORTS = {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8443, 8888}


class ServiceInfo(TypedDict):
    """Structured service detection result for an open port."""

    service: str
    version: str
    banner: str


def detect_service(target: str, port: int, timeout: float) -> ServiceInfo:
    """Perform best-effort banner grabbing against an open TCP port."""

    service = guess_service_name(port, "tcp")
    banner = ""

    with socket.create_connection((target, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if port in HTTP_PORTS or service in {"http", "https", "http-alt", "www"}:
            sock.sendall(_build_http_probe(target))
            banner = _recv_text(sock)
        else:
            banner = _recv_text(sock)
            if not banner:
                if service in {"smtp", "submission", "ftp", "pop3", "imap", "ssh"}:
                    sock.sendall(b"\r\n")
                else:
                    sock.sendall(_build_generic_probe(service))
                banner = _recv_text(sock)

    identified_service, version = _parse_banner(service, banner)
    return {
        "service": identified_service,
        "version": version,
        "banner": banner,
    }


def _recv_text(sock: socket.socket, chunk_size: int = 4096) -> str:
    """Receive and decode a small banner response."""

    try:
        data = sock.recv(chunk_size)
    except socket.timeout:
        return ""
    except OSError:
        return ""

    return data.decode("utf-8", errors="ignore").strip()


def _build_http_probe(target: str) -> bytes:
    """Build a small HTTP probe request."""

    return (
        f"HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: SwanScan/2.0\r\n\r\n".encode("ascii")
    )


def _build_generic_probe(service: str) -> bytes:
    """Build a lightweight text probe for unknown services."""

    if service == "smtp":
        return b"EHLO swanscan.local\r\n"
    if service == "ftp":
        return b"HELP\r\n"
    return b"\r\n"


def _parse_banner(default_service: str, banner: str) -> tuple[str, str]:
    """Infer a service name and version string from a banner."""

    if not banner:
        return default_service, "-"

    first_line = banner.splitlines()[0].strip()
    lowered = banner.lower()

    if first_line.startswith("SSH-"):
        match = re.search(r"SSH-[0-9.]+-([A-Za-z0-9._-]+)", first_line)
        version = _format_product(match.group(1)) if match else first_line
        return "ssh", version

    if "server:" in lowered or first_line.startswith("HTTP/"):
        server_match = re.search(r"^Server:\s*(.+)$", banner, flags=re.IGNORECASE | re.MULTILINE)
        version = _format_http_server(server_match.group(1)) if server_match else "HTTP service"
        return "http", version

    if "smtp" in lowered or first_line.startswith("220") and "mail" in lowered:
        return "smtp", _cleanup_line(first_line.removeprefix("220 ").strip())

    if "ftp" in lowered:
        return "ftp", _cleanup_line(first_line.removeprefix("220-").removeprefix("220 ").strip())

    return default_service, _cleanup_line(first_line)


def _format_product(product: str) -> str:
    """Normalize a product token into a readable version string."""

    token = product.replace("_", " ")
    token = re.sub(r"(?<=\D)/(?=\d)", " ", token)
    return token.strip()


def _format_http_server(server_header: str) -> str:
    """Normalize an HTTP Server header."""

    server_header = server_header.strip()
    if "/" in server_header:
        name, version = server_header.split("/", maxsplit=1)
        return f"{name.strip()} {version.strip()}"
    return server_header


def _cleanup_line(line: str) -> str:
    """Trim a banner line for display."""

    cleaned = line.strip()
    return cleaned if cleaned else "-"
