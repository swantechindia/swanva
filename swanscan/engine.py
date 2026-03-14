"""Core scanning engine for SwanScan."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Literal, TypedDict

from swanscan.service_detection import ServiceInfo, detect_service
from swanscan.syn_scanner import scan_syn_port
from swanscan.tcp_scanner import scan_port
from swanscan.udp_scanner import scan_udp_port
from swanscan.utils import ScanState, chunked, parse_ports

LOGGER = logging.getLogger(__name__)
DEFAULT_BATCH_MULTIPLIER = 4
MINIMUM_BATCH_SIZE = 64
ScanType = Literal["tcp_connect", "syn", "udp"]


class ScanResults(TypedDict):
    """Structured scan output returned by the engine."""

    target: str
    scan_type: str
    open_ports: list[int]
    closed_ports: list[int]
    filtered_ports: list[int]
    services: dict[int, ServiceInfo]


class ScannerEngine:
    """Coordinate threaded TCP connect scanning for a target."""

    def __init__(
        self,
        target: str,
        ports: str,
        threads: int,
        timeout: float,
        scan_type: ScanType = "tcp_connect",
        service_detection: bool = False,
        batch_size: int | None = None,
    ) -> None:
        """Initialize the scanner engine.

        Args:
            target: IP address or hostname to scan.
            ports: Raw port specification string.
            threads: Maximum number of worker threads.
            timeout: Socket timeout in seconds.
            scan_type: Scan mode to execute.
            service_detection: Enable TCP banner grabbing on open ports.
            batch_size: Optional number of ports to process per batch.
        """

        if not target or not target.strip():
            raise ValueError("Target is required.")
        if threads < 1:
            raise ValueError("Thread count must be at least 1.")
        if timeout <= 0:
            raise ValueError("Timeout must be greater than 0.")
        if scan_type not in {"tcp_connect", "syn", "udp"}:
            raise ValueError(f"Unsupported scan type: {scan_type!r}")
        if batch_size is not None and batch_size < 1:
            raise ValueError("Batch size must be at least 1.")

        self.target = target.strip()
        self.port_spec = ports
        self.threads = threads
        self.timeout = timeout
        self.scan_type = scan_type
        self.service_detection = service_detection
        self.batch_size = batch_size or max(self.threads * DEFAULT_BATCH_MULTIPLIER, MINIMUM_BATCH_SIZE)

    def run(self) -> ScanResults:
        """Execute the selected scan type and return structured results."""

        port_list = parse_ports(self.port_spec)
        LOGGER.info(
            "Starting %s scan against %s across %d ports using %d threads",
            self.scan_type,
            self.target,
            len(port_list),
            self.threads,
        )

        results: dict[str, list[int]] = {
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
        }
        scan_func = self._get_scan_function()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for batch in chunked(port_list, self.batch_size):
                future_to_port = {
                    executor.submit(scan_func, self.target, port, self.timeout): port for port in batch
                }

                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        state = future.result()
                    except Exception as exc:  # pragma: no cover - defensive safeguard
                        LOGGER.exception("Unhandled error while scanning %s:%s: %s", self.target, port, exc)
                        state = "filtered"

                    self._store_state(results, port, state)

        for key in results:
            results[key].sort()

        services: dict[int, ServiceInfo] = {}
        if self.service_detection:
            if self.scan_type == "udp":
                LOGGER.warning("Service detection is only supported for TCP-based scans; skipping for UDP.")
            elif results["open_ports"]:
                services = self._detect_services(results["open_ports"])

        scan_results: ScanResults = {
            "target": self.target,
            "scan_type": self.scan_type,
            "open_ports": results["open_ports"],
            "closed_ports": results["closed_ports"],
            "filtered_ports": results["filtered_ports"],
            "services": services,
        }
        LOGGER.info(
            "Completed scan for %s: %d open, %d closed, %d filtered",
            self.target,
            len(results["open_ports"]),
            len(results["closed_ports"]),
            len(results["filtered_ports"]),
        )
        return scan_results

    def _get_scan_function(self) -> Callable[[str, int, float], ScanState]:
        """Return the scanner implementation for the configured scan type."""

        if self.scan_type == "tcp_connect":
            return scan_port
        if self.scan_type == "syn":
            return scan_syn_port
        return scan_udp_port

    def _store_state(self, results: dict[str, list[int]], port: int, state: ScanState) -> None:
        """Store a scan result in the appropriate bucket."""

        if state == "open":
            results["open_ports"].append(port)
        elif state == "closed":
            results["closed_ports"].append(port)
        else:
            results["filtered_ports"].append(port)

    def _detect_services(self, open_ports: list[int]) -> dict[int, ServiceInfo]:
        """Run banner grabbing concurrently across open TCP ports."""

        LOGGER.info("Starting service detection for %d open ports on %s", len(open_ports), self.target)
        services: dict[int, ServiceInfo] = {}

        with ThreadPoolExecutor(max_workers=min(self.threads, len(open_ports))) as executor:
            for batch in chunked(open_ports, self.batch_size):
                future_to_port = {
                    executor.submit(detect_service, self.target, port, self.timeout): port for port in batch
                }

                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        services[port] = future.result()
                    except Exception as exc:
                        LOGGER.debug("Service detection failed for %s:%s: %s", self.target, port, exc)

        return dict(sorted(services.items()))
