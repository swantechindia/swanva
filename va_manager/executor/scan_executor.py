"""Bridge scan jobs to the existing scanner packages."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from va_manager.models.asset import Asset
from va_manager.models.scan_job import ScanJob
from va_manager.security.secrets import secret_manager

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NETWORK_SCANNER_PARENT = PROJECT_ROOT / "scanners" / "network_scanner"
OS_SCANNER_PARENT = PROJECT_ROOT / "scanners" / "os_scanner"

for path in (PROJECT_ROOT, NETWORK_SCANNER_PARENT, OS_SCANNER_PARENT):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from pscan.engine import ScannerEngine  # noqa: E402
from swan_os_scanner.scanner import scan_host  # noqa: E402
from scanners.web_scanner.web_scanner.scanner import start_scan as start_web_scan  # noqa: E402


def execute(job: ScanJob, asset: Asset) -> dict[str, Any]:
    """Dispatch a queued job to the requested scanner implementation."""

    if job.scanner_type == "network":
        return _run_network_scan(asset, job.scan_config)

    if job.scanner_type == "os":
        return _run_os_scan(asset, job.scan_config)

    if job.scanner_type == "web":
        return _run_web_scan(asset, job.scan_config)

    if job.scanner_type == "db":
        raise NotImplementedError("Database scanner execution is not implemented yet.")

    raise ValueError(f"Unsupported scanner type: {job.scanner_type}")


def _run_network_scan(asset: Asset, config: dict[str, Any]) -> dict[str, Any]:
    """Execute the port scanner using the existing scanner engine."""

    scan_type = _resolve_network_scan_type(config)
    engine = ScannerEngine(
        target=asset.target,
        ports=str(config.get("ports", "1-1000")),
        threads=int(config.get("threads", 100)),
        timeout=float(config.get("timeout", 1.0)),
        scan_type=scan_type,
        service_detection=bool(config.get("service_detection", False)),
    )
    return engine.run()


def _run_os_scan(asset: Asset, config: dict[str, Any]) -> dict[str, Any]:
    """Execute the SSH-based OS inventory scanner.

    Stored credentials are decrypted only inside this execution path and are
    never logged. This keeps secret exposure limited to the short-lived call
    boundary where the scanner actually needs the plaintext password.
    """

    username = str(config.get("username") or asset.username or "")
    password = _resolve_os_password(asset, config)
    if not username or not password:
        raise ValueError("OS scan requires SSH credentials on the asset or in the job config.")

    return scan_host(asset.target, username, password)


def _run_web_scan(asset: Asset, config: dict[str, Any]) -> dict[str, Any]:
    """Execute the web scanner for HTTP or HTTPS assets."""

    target = _build_web_target(asset)
    tools = config.get("tools")
    if tools is not None and not isinstance(tools, list):
        raise ValueError("Web scan config 'tools' must be a list when provided.")

    return start_web_scan(target, tools)


def _resolve_network_scan_type(config: dict[str, Any]) -> str:
    """Normalize network scan config into the engine's scan type set."""

    scan_type = str(config.get("scan_type", "tcp_connect")).strip().lower()
    if scan_type in {"tcp_connect", "syn", "udp"}:
        return scan_type
    if bool(config.get("syn_scan")):
        return "syn"
    if bool(config.get("udp_scan")):
        return "udp"
    return "tcp_connect"


def _build_web_target(asset: Asset) -> str:
    """Construct a web target URL from asset metadata."""

    protocol = (asset.protocol or "http").strip(":/")
    if asset.port:
        return f"{protocol}://{asset.target}:{asset.port}"
    return f"{protocol}://{asset.target}"


def _resolve_os_password(asset: Asset, config: dict[str, Any]) -> str:
    """Resolve scanner credentials, decrypting stored secrets only when needed."""

    config_password = config.get("password")
    if config_password not in (None, ""):
        return str(config_password)

    stored_password = str(asset.password or "")
    if not stored_password:
        return ""

    return secret_manager.decrypt(stored_password)
