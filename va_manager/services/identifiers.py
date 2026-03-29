"""Helpers for frontend-facing resource identifiers."""

from __future__ import annotations

import re

SCAN_ID_RE = re.compile(r"^scan[-_]?(\d+)$", re.IGNORECASE)
REPORT_ID_RE = re.compile(r"^rep(?:ort)?[-_]?(\d+)$", re.IGNORECASE)


def format_scan_identifier(scan_job_id: int) -> str:
    """Return the frontend-facing scan identifier."""

    return f"SCAN-{scan_job_id:06d}"


def parse_scan_identifier(value: str | int) -> int:
    """Parse a scan identifier from either raw numeric or prefixed form."""

    if isinstance(value, int):
        return value

    normalized = str(value).strip()
    if normalized.isdigit():
        return int(normalized)

    match = SCAN_ID_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"Invalid scan identifier: {value}")
    return int(match.group(1))


def format_report_identifier(report_id: int) -> str:
    """Return the frontend-facing report identifier."""

    return f"REP-{report_id:06d}"


def parse_report_identifier(value: str | int) -> int:
    """Parse a report identifier from either raw numeric or prefixed form."""

    if isinstance(value, int):
        return value

    normalized = str(value).strip()
    if normalized.isdigit():
        return int(normalized)

    match = REPORT_ID_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"Invalid report identifier: {value}")
    return int(match.group(1))


def format_vulnerability_identifier(vulnerability_id: int) -> str:
    """Return the frontend-facing vulnerability identifier."""

    return f"VUL-{vulnerability_id:06d}"
