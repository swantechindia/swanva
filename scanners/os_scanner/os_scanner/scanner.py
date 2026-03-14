"""Standalone CLI and orchestration for the OS credential scanner."""

from __future__ import annotations

import argparse
import json
import sys

from os_scanner.collectors import (
    collect_kernel,
    collect_os_info,
    collect_packages,
    collect_services,
    collect_users,
)
from os_scanner.ssh import connect


def scan_host(host: str, username: str, password: str) -> dict[str, object]:
    """Collect system information from a Linux host over SSH."""

    ssh = connect(host, username, password)

    try:
        result = {
            "asset": host,
            "scan_type": "os_credential_scan",
            "system": {
                "os": collect_os_info(ssh),
                "kernel": collect_kernel(ssh),
                "packages": collect_packages(ssh),
                "services": collect_services(ssh),
                "users": collect_users(ssh),
            },
        }
    finally:
        ssh.close()

    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface for the scanner."""

    parser = argparse.ArgumentParser(description="Swan OS credential scanner")
    parser.add_argument("--host", required=True, help="Target Linux host or IP.")
    parser.add_argument("--username", required=True, help="SSH username.")
    parser.add_argument("--password", required=True, help="SSH password.")
    return parser


def main() -> int:
    """Run the scanner CLI and print JSON output."""

    parser = build_parser()
    args = parser.parse_args()

    try:
        result = scan_host(args.host, args.username, args.password)
    except Exception as exc:  # pragma: no cover - CLI error handling
        print(
            json.dumps(
                {
                    "asset": args.host,
                    "scan_type": "os_credential_scan",
                    "error": str(exc),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
