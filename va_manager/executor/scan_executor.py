"""Bridge scan jobs to the existing scanner packages."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from va_manager.models.scan_job import ScanJob
from va_manager.services.asset_service import AssetExecutionView

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


def execute(job: ScanJob, asset: AssetExecutionView) -> dict[str, Any]:
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


def _run_network_scan(asset: AssetExecutionView, config: Mapping[str, object]) -> dict[str, Any]:
    """Execute the port scanner using the existing scanner engine."""

    scan_type = _resolve_network_scan_type(config)
    engine = ScannerEngine(
        target=_resolve_network_target(asset),
        ports=str(config.get("ports", "1-1000")),
        threads=int(config.get("threads", 100)),
        timeout=float(config.get("timeout", 1.0)),
        scan_type=scan_type,
        service_detection=bool(config.get("service_detection", False)),
    )
    return engine.run()


def _run_os_scan(asset: AssetExecutionView, config: Mapping[str, object]) -> dict[str, Any]:
    """Execute the SSH-based OS inventory scanner.

    Credentials are decrypted only in the short-lived execution asset view
    returned by the asset service.
    """

    credentials = _get_credentials(asset)
    username = str(credentials.get("username") or "").strip()
    password = str(credentials.get("password") or "").strip()
    if not username or not password:
        raise ValueError("OS scan requires endpoint credentials on the asset.")

    return scan_host(str(asset.config.get("ip") or asset.target), username, password)


def _run_web_scan(asset: AssetExecutionView, config: Mapping[str, object]) -> dict[str, Any]:
    """Execute the web scanner for HTTP or HTTPS assets."""

    target = _build_web_target(asset, config)
    tools = config.get("tools")
    if tools is not None and not isinstance(tools, list):
        raise ValueError("Web scan config 'tools' must be a list when provided.")

    return start_web_scan(target, tools)


def _resolve_network_scan_type(config: Mapping[str, object]) -> str:
    """Normalize network scan config into the engine's scan type set."""

    scan_type = str(config.get("scan_type", "tcp_connect")).strip().lower()
    if scan_type in {"tcp_connect", "syn", "udp"}:
        return scan_type
    if bool(config.get("syn_scan")):
        return "syn"
    if bool(config.get("udp_scan")):
        return "udp"
    return "tcp_connect"


def _build_web_target(asset: AssetExecutionView, config: Mapping[str, object]) -> str:
    """Construct a web target URL from asset metadata."""

    stored_url = str(asset.config.get("url") or asset.target).strip()
    parsed_target = urlparse(stored_url)
    if parsed_target.scheme and parsed_target.netloc:
        return stored_url

    scheme = str(config.get("scheme") or "https").strip(":/")
    port = config.get("port")
    if port is not None:
        return f"{scheme}://{asset.target}:{int(port)}"
    return f"{scheme}://{asset.target}"


def _resolve_network_target(asset: AssetExecutionView) -> str:
    """Resolve the host/IP that the network scanner should probe."""

    if asset.asset_type.value in {"endpoint", "database"}:
        return str(asset.config.get("ip") or asset.target)

    parsed = urlparse(str(asset.config.get("url") or asset.target))
    if parsed.hostname:
        return parsed.hostname
    return asset.target


def _get_credentials(asset: AssetExecutionView) -> Mapping[str, object]:
    """Return credential material from the decrypted execution view."""

    credentials = asset.config.get("credentials")
    if isinstance(credentials, Mapping):
        return credentials
    return {}
