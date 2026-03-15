"""Parsers for dpkg package listings."""

from __future__ import annotations


def parse_dpkg_output(raw_output: str) -> list[dict[str, str]]:
    """Parse `dpkg -l` output into package name/version records."""

    packages: list[dict[str, str]] = []

    for line in raw_output.splitlines():
        if not line.startswith("ii"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        packages.append(
            {
                "name": parts[1],
                "version": parts[2],
            }
        )

    return packages
