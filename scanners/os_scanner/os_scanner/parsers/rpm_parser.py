"""Parsers for RPM package listings."""

from __future__ import annotations


def parse_rpm_output(raw_output: str) -> list[dict[str, str]]:
    """Parse RPM query output into package name/version records."""

    packages: list[dict[str, str]] = []

    for line in raw_output.splitlines():
        entry = line.strip()
        if not entry:
            continue

        if "\t" in entry:
            name, version = entry.split("\t", maxsplit=1)
        else:
            parts = entry.split(maxsplit=1)
            if len(parts) != 2:
                continue
            name, version = parts

        packages.append(
            {
                "name": name,
                "version": version,
            }
        )

    return packages
