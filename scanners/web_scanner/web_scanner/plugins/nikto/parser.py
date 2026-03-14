"""Nikto XML output parsing helpers."""

from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_nikto_output(raw_output: str, target: str) -> list[dict[str, object]]:
    """Parse Nikto XML output into intermediate finding records."""

    return parse_nikto_xml(raw_output, target)


def parse_nikto_xml(xml_output: str, target: str) -> list[dict[str, object]]:
    """Parse Nikto XML output into Swan-compatible intermediate findings."""

    if not xml_output.strip():
        return []

    findings: list[dict[str, object]] = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return []

    for item in root.findall(".//item"):
        finding = _build_finding(item, target)
        if finding is not None:
            findings.append(finding)

    return findings


class NiktoXmlStreamParser:
    """Incrementally parse streamed Nikto XML output."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._parser = ET.XMLPullParser(events=("end",))
        self._broken = False

    def feed(self, chunk: str) -> list[dict[str, object]]:
        """Consume an XML chunk and return any complete findings."""

        if self._broken or not chunk:
            return []

        try:
            self._parser.feed(chunk)
        except ET.ParseError:
            self._broken = True
            return []

        findings: list[dict[str, object]] = []

        for _, element in self._parser.read_events():
            if element.tag != "item":
                continue

            finding = _build_finding(element, self.target)
            if finding is not None:
                findings.append(finding)
            element.clear()

        return findings

    def close(self) -> list[dict[str, object]]:
        """Finalize parsing after the process exits."""

        if self._broken:
            return []

        findings: list[dict[str, object]] = []

        try:
            self._parser.feed("")
        except ET.ParseError:
            return []

        for _, element in self._parser.read_events():
            if element.tag != "item":
                continue

            finding = _build_finding(element, self.target)
            if finding is not None:
                findings.append(finding)
            element.clear()

        return findings


def _get_child_text(item: ET.Element, tag_name: str) -> str:
    """Safely extract stripped text from a child XML element."""

    child = item.find(tag_name)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _normalize_url(uri: str, target: str) -> str:
    """Normalize a Nikto URI into an absolute URL when possible."""

    if not uri:
        return target
    if uri.startswith("http://") or uri.startswith("https://"):
        return uri
    return f"{target.rstrip('/')}/{uri.lstrip('/')}"


def _build_finding(item: ET.Element, target: str) -> dict[str, object] | None:
    """Build a Swan-compatible finding from a Nikto XML item element."""

    uri = _get_child_text(item, "uri")
    description = _get_child_text(item, "description")
    message = _get_child_text(item, "msg")

    name = description or message
    if not name:
        return None

    return {
        "scanner": "web_scanner",
        "tool": "nikto",
        "target": target,
        "name": name,
        "severity": "medium",
        "url": _normalize_url(uri, target),
        "description": message,
        "evidence": "",
    }
