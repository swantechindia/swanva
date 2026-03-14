"""Nuclei output parsing helpers."""

from __future__ import annotations

import json


def parse_nuclei_output(raw_output: str, target: str) -> list[dict[str, object]]:
    """Parse Nuclei NDJSON output into intermediate finding records."""

    findings: list[dict[str, object]] = []

    for line in raw_output.splitlines():
        entry = line.strip()
        if not entry:
            continue

        try:
            item = json.loads(entry)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        findings.append(
            {
                "name": str(info.get("name") or item.get("template-id") or "nuclei finding"),
                "severity": info.get("severity", "low"),
                "url": str(item.get("matched-at") or item.get("host") or target),
                "description": str(info.get("description") or item.get("template") or ""),
                "evidence": _extract_evidence(item),
                "timestamp": str(item.get("timestamp") or ""),
            }
        )

    return findings


class NucleiStreamParser:
    """Incrementally parse Nuclei NDJSON output."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._buffer = ""

    def feed(self, chunk: str) -> list[dict[str, object]]:
        """Parse complete JSON lines from a streamed stdout chunk."""

        self._buffer += chunk
        lines = self._buffer.splitlines(keepends=True)
        findings: list[dict[str, object]] = []

        if lines and not lines[-1].endswith(("\n", "\r")):
            self._buffer = lines.pop()
        else:
            self._buffer = ""

        for line in lines:
            findings.extend(_parse_nuclei_line(line, self.target))

        return findings

    def close(self) -> list[dict[str, object]]:
        """Flush any remaining buffered line when the process exits."""

        if not self._buffer.strip():
            return []

        buffered = self._buffer
        self._buffer = ""
        return _parse_nuclei_line(buffered, self.target)


def _parse_nuclei_line(line: str, target: str) -> list[dict[str, object]]:
    """Parse a single Nuclei JSON line into zero or one findings."""

    entry = line.strip()
    if not entry:
        return []

    try:
        item = json.loads(entry)
    except json.JSONDecodeError:
        return []

    info = item.get("info", {})
    return [
        {
            "name": str(info.get("name") or item.get("template-id") or "nuclei finding"),
            "severity": info.get("severity", "low"),
            "url": str(item.get("matched-at") or item.get("host") or target),
            "description": str(info.get("description") or item.get("template") or ""),
            "evidence": _extract_evidence(item),
            "timestamp": str(item.get("timestamp") or ""),
        }
    ]


def _extract_evidence(item: dict[str, object]) -> str:
    """Extract concise Nuclei evidence text."""

    extracted = item.get("extracted-results")
    if isinstance(extracted, list) and extracted:
        return ", ".join(str(entry) for entry in extracted)

    for key in ("matcher-name", "ip", "timestamp"):
        value = item.get(key)
        if value:
            return str(value)

    return ""
