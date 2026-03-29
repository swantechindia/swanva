"""Typed scan configuration normalization helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

ScannerType = Literal["network", "os", "web", "db"]


class ScanConfigurationError(ValueError):
    """Raised when a scan request contains an invalid config."""


class NetworkScanConfig(BaseModel):
    """Validated config for network scans."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ports: str = "1-1000"
    threads: int = Field(default=100, ge=1, le=1024)
    timeout: float = Field(default=1.0, gt=0, le=60)
    scan_type: Literal["tcp_connect", "syn", "udp"] = "tcp_connect"
    service_detection: bool = False


class OSScanConfig(BaseModel):
    """Validated config for OS scans."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WebScanConfig(BaseModel):
    """Validated config for web scans."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    tools: list[str] | None = None
    scheme: Literal["http", "https"] | None = None
    port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("tools")
    @classmethod
    def normalize_tools(cls, value: list[str] | None) -> list[str] | None:
        """Normalize tool names and reject empty items."""

        if value is None:
            return None

        normalized = [tool.strip().lower() for tool in value if tool.strip()]
        if len(normalized) != len(value):
            raise ValueError("Web scan tools cannot contain empty values.")
        return normalized


class DBScanConfig(BaseModel):
    """Validated config for DB scans."""

    model_config = ConfigDict(extra="forbid")


def normalize_scan_request(
    scanner_type: str,
    config: Mapping[str, object] | None,
) -> tuple[ScannerType, dict[str, object]]:
    """Validate and normalize scanner type plus config for persistence."""

    normalized_type = scanner_type.strip().lower()
    raw_config = dict(config or {})

    if normalized_type == "network":
        return normalized_type, _validate_config(NetworkScanConfig, raw_config)
    if normalized_type == "os":
        return normalized_type, _validate_config(OSScanConfig, raw_config)
    if normalized_type == "web":
        return normalized_type, _validate_config(WebScanConfig, raw_config)
    if normalized_type == "db":
        return normalized_type, _validate_config(DBScanConfig, raw_config)

    raise ScanConfigurationError(f"Unsupported scanner type: {scanner_type}")


def _validate_config(model: type[BaseModel], raw_config: dict[str, object]) -> dict[str, object]:
    """Validate one scan config model and normalize it for DB storage."""

    try:
        validated = model.model_validate(raw_config)
    except ValidationError as exc:
        raise ScanConfigurationError(str(exc)) from exc

    return validated.model_dump(exclude_none=True)
