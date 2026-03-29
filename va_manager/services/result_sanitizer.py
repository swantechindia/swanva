"""Sanitize stored scan results before returning them via the API."""

from __future__ import annotations

from collections.abc import Mapping


def sanitize_result_payload(scanner: str, payload: Mapping[str, object]) -> dict[str, object]:
    """Return an API-safe result payload for a stored scan result."""

    if scanner == "network":
        return _sanitize_network_result(payload)
    if scanner == "web":
        return _sanitize_web_result(payload)
    if scanner == "vulnerability_engine":
        return _sanitize_vulnerability_report(payload)
    if scanner == "os":
        return _sanitize_os_result(payload)

    return _sanitize_generic_result(payload)


def _sanitize_network_result(payload: Mapping[str, object]) -> dict[str, object]:
    """Expose only ports and service metadata for network results."""

    services = payload.get("services")
    sanitized_services: dict[str, dict[str, str]] = {}
    if isinstance(services, Mapping):
        for port, value in services.items():
            if not isinstance(value, Mapping):
                continue
            sanitized_services[str(port)] = {
                "service": str(value.get("service") or ""),
                "version": str(value.get("version") or ""),
            }

    return {
        "target": str(payload.get("target") or ""),
        "scan_type": str(payload.get("scan_type") or "network"),
        "open_ports": _coerce_int_list(payload.get("open_ports")),
        "services": sanitized_services,
    }


def _sanitize_web_result(payload: Mapping[str, object]) -> dict[str, object]:
    """Expose normalized web findings without raw evidence dumps."""

    findings_payload = payload.get("findings")
    sanitized_findings: list[dict[str, object]] = []
    if isinstance(findings_payload, list):
        for finding in findings_payload:
            if not isinstance(finding, Mapping):
                continue
            sanitized_findings.append(
                {
                    "tool": str(finding.get("tool") or ""),
                    "name": str(finding.get("name") or ""),
                    "severity": str(finding.get("severity") or ""),
                    "url": str(finding.get("url") or ""),
                    "description": str(finding.get("description") or ""),
                    "timestamp": str(finding.get("timestamp") or ""),
                }
            )

    return {
        "asset": str(payload.get("asset") or ""),
        "scan_type": str(payload.get("scan_type") or "web_scan"),
        "findings": sanitized_findings,
        "errors": _coerce_error_list(payload.get("errors")),
    }


def _sanitize_vulnerability_report(payload: Mapping[str, object]) -> dict[str, object]:
    """Expose vulnerability findings as-is from the post-processing engine."""

    vulnerabilities = payload.get("vulnerabilities")
    sanitized_vulnerabilities: list[dict[str, object]] = []
    if isinstance(vulnerabilities, list):
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, Mapping):
                continue
            sanitized_vulnerabilities.append(
                {
                    "cve": str(vulnerability.get("cve") or ""),
                    "service": str(vulnerability.get("service") or ""),
                    "port": vulnerability.get("port"),
                    "severity": str(vulnerability.get("severity") or ""),
                    "cvss": vulnerability.get("cvss"),
                    "description": str(vulnerability.get("description") or ""),
                    "references": _coerce_string_list(vulnerability.get("references")),
                    "source": str(vulnerability.get("source") or ""),
                }
            )

    return {
        "asset": str(payload.get("asset") or ""),
        "scan_id": str(payload.get("scan_id") or ""),
        "vulnerabilities": sanitized_vulnerabilities,
    }


def _sanitize_os_result(payload: Mapping[str, object]) -> dict[str, object]:
    """Suppress raw credentialed OS inventory from API responses."""

    return {
        "asset": str(payload.get("asset") or ""),
        "scan_type": str(payload.get("scan_type") or "os_credential_scan"),
        "message": "Credentialed OS inventory results are not exposed by this API. Use vulnerability reports for actionable findings.",
    }


def _sanitize_generic_result(payload: Mapping[str, object]) -> dict[str, object]:
    """Return only safe generic fields for unknown result payloads."""

    safe_result: dict[str, object] = {}
    if "error" in payload:
        safe_result["error"] = str(payload.get("error") or "")
    if "analysis_status" in payload:
        safe_result["analysis_status"] = str(payload.get("analysis_status") or "")
    return safe_result


def _coerce_int_list(value: object) -> list[int]:
    """Convert a JSON-ish list into a list of ints."""

    if not isinstance(value, list):
        return []
    results: list[int] = []
    for item in value:
        try:
            results.append(int(item))
        except (TypeError, ValueError):
            continue
    return results


def _coerce_string_list(value: object) -> list[str]:
    """Convert a JSON-ish list into a list of strings."""

    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _coerce_error_list(value: object) -> list[dict[str, object]]:
    """Expose only safe web tool execution error details."""

    if not isinstance(value, list):
        return []

    errors: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        errors.append(
            {
                "tool": str(item.get("tool") or ""),
                "error": str(item.get("error") or ""),
                "returncode": item.get("returncode"),
            }
        )
    return errors
