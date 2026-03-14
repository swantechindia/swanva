"""Command-line entrypoint for SwanScan."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from swanscan.engine import ScannerEngine
from swanscan.utils import guess_service_name

DEFAULT_PORTS = "1-1000"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 1.0


def build_parser() -> argparse.ArgumentParser:
    """Create the SwanScan CLI argument parser."""

    parser = argparse.ArgumentParser(description="SwanScan advanced network scanner")
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP address or hostname.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORTS,
        help="Port specification to scan (default: 1-1000).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help="Number of concurrent scanning threads.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout in seconds.",
    )
    parser.add_argument(
        "-sS",
        dest="syn_scan",
        action="store_true",
        help="Perform a TCP SYN stealth scan.",
    )
    parser.add_argument(
        "-sU",
        dest="udp_scan",
        action="store_true",
        help="Perform a UDP scan.",
    )
    parser.add_argument(
        "-sV",
        dest="service_detection",
        action="store_true",
        help="Enable service and version detection on open TCP ports.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Logging level for diagnostic output.",
    )
    return parser


def configure_logging(level: str) -> None:
    """Configure application logging."""

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def print_results_table(
    open_ports: list[int],
    services: dict[int, dict[str, str]],
    show_service_details: bool,
    scan_type: str,
) -> None:
    """Render scan results as a simple terminal table."""

    if show_service_details:
        print("PORT     STATE SERVICE VERSION")
    else:
        print("PORT     STATE")

    if not open_ports:
        print("No open ports found.")
        return

    for port in open_ports:
        if show_service_details:
            service_info = services.get(port, {})
            protocol = "udp" if scan_type == "udp" else "tcp"
            service = service_info.get("service") or guess_service_name(port, protocol)
            version = service_info.get("version") or "-"
            print(f"{port:<8} open  {service:<7} {version}")
            continue

        print(f"{port:<8} OPEN")


def determine_scan_type(args: argparse.Namespace) -> str:
    """Determine the requested scan mode from CLI flags."""

    if args.syn_scan and args.udp_scan:
        raise ValueError("Choose either -sS or -sU, not both.")
    if args.syn_scan:
        return "syn"
    if args.udp_scan:
        return "udp"
    return "tcp_connect"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the SwanScan CLI."""

    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    try:
        scan_type = determine_scan_type(args)
        engine = ScannerEngine(
            target=args.target,
            ports=args.ports,
            threads=args.threads,
            timeout=args.timeout,
            scan_type=scan_type,
            service_detection=args.service_detection,
        )
        results = engine.run()
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        logging.getLogger(__name__).exception("Scan failed: %s", exc)
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    print_results_table(results["open_ports"], results["services"], args.service_detection, scan_type)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
