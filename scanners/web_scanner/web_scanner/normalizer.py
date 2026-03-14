"""Normalization helpers for plugin findings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone

from pydantic import ValidationError

from .models import SwanFinding

SEVERITY_MAP = {
    "info": "low",
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "low",
    "": "low",
}


def normalize_severity(value: object) -> str:
    """Normalize severity values into the Swan severity set."""

    if value is None:
        return "low"

    text = str(value).strip().lower()
    return SEVERITY_MAP.get(text, "low")


def normalize_finding(finding: Mapping[str, object], tool: str, target: str) -> SwanFinding | None:
    """Normalize a single plugin finding into the Swan schema."""

    payload = {
        "scanner": "web_scanner",
        "tool": tool,
        "target": target,
        "name": str(finding.get("name", "")).strip() or f"{tool} finding",
        "severity": normalize_severity(finding.get("severity")),
        "url": str(finding.get("url", "")).strip() or target,
        "description": str(finding.get("description", "")).strip(),
        "evidence": str(finding.get("evidence", "")).strip(),
        "timestamp": str(finding.get("timestamp", "")).strip() or _timestamp_now(),
    }

    if not payload["name"]:
        return None

    try:
        return SwanFinding.model_validate(payload)
    except ValidationError:
        return None


def normalize_findings(findings: Iterable[Mapping[str, object]], tool: str, target: str) -> list[SwanFinding]:
    """Normalize a sequence of plugin findings and drop invalid entries."""

    normalized: list[SwanFinding] = []

    for finding in findings:
        item = normalize_finding(finding, tool, target)
        if item is not None:
            normalized.append(item)

    return normalized


def _timestamp_now() -> str:
    """Return the current UTC timestamp in ISO 8601 form."""

    return datetime.now(timezone.utc).isoformat()
