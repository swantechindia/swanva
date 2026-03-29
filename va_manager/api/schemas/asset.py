"""Asset API schemas and configuration validators."""

from __future__ import annotations

import ipaddress
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class AssetType(str, Enum):
    """Supported managed asset categories."""

    ENDPOINT = "endpoint"
    DATABASE = "database"
    WEB = "web"


class CredentialsInput(BaseModel):
    """Credential payload accepted for credentialed assets."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=4096)


class EndpointConfigInput(BaseModel):
    """Connection metadata for endpoint assets."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ip: str
    os_type: str | None = Field(default=None, max_length=100)
    os_version: str | None = Field(default=None, max_length=100)
    credentials: CredentialsInput | None = None


class DatabaseConfigInput(BaseModel):
    """Connection metadata for database assets."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    db_type: str = Field(..., min_length=1, max_length=100)
    ip: str
    version: str | None = Field(default=None, max_length=100)
    credentials: CredentialsInput


class WebConfigInput(BaseModel):
    """Connection metadata for web assets."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str = Field(..., min_length=1, max_length=2048)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, min_length=4, max_length=5)


class AssetCreate(BaseModel):
    """Payload for creating an asset."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    config: dict[str, Any]
    description: str | None = Field(default=None, max_length=2000)


class AssetUpdate(BaseModel):
    """Payload for updating an asset."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: AssetType | None = None
    config: dict[str, Any] | None = None
    description: str | None = Field(default=None, max_length=2000)


class AssetConnectionTestRequest(BaseModel):
    """Payload for testing a draft asset connection without saving it."""

    model_config = ConfigDict(str_strip_whitespace=True)

    asset_type: AssetType
    config: dict[str, Any]
    timeout: int = Field(default=5, ge=1, le=30)


class AssetResponse(BaseModel):
    """Serialized asset response with sanitized config."""

    model_config = ConfigDict(from_attributes=False)

    id: int
    name: str
    target: str
    asset_type: AssetType
    config: dict[str, Any]
    description: str | None = None
    last_connection_status: str | None = None
    last_checked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AssetEnvelope(BaseModel):
    """Single-asset success response envelope."""

    success: bool = True
    data: AssetResponse


class AssetListEnvelope(BaseModel):
    """Asset collection success response envelope."""

    success: bool = True
    data: list[AssetResponse]


class AssetDeleteResult(BaseModel):
    """Delete confirmation payload."""

    id: int
    deleted: bool = True


class AssetDeleteEnvelope(BaseModel):
    """Delete success response envelope."""

    success: bool = True
    data: AssetDeleteResult


class ConnectionTestResult(BaseModel):
    """Connection test outcome payload."""

    status: str
    message: str


class ConnectionTestEnvelope(BaseModel):
    """Connection test success envelope."""

    success: bool = True
    data: ConnectionTestResult


@dataclass(frozen=True)
class NormalizedAssetConfig:
    """Validated and normalized asset config plus canonical target."""

    target: str
    config: dict[str, Any]


def normalize_asset_config(asset_type: AssetType, config: dict[str, Any]) -> NormalizedAssetConfig:
    """Validate one asset config payload and derive its canonical target."""

    if asset_type == AssetType.ENDPOINT:
        validated = _validate_config_model(EndpointConfigInput, config)
        normalized_ip = _normalize_ip(validated.ip)
        normalized_config = validated.model_dump(exclude_none=True)
        normalized_config["ip"] = normalized_ip
        return NormalizedAssetConfig(target=normalized_ip, config=normalized_config)

    if asset_type == AssetType.DATABASE:
        validated = _validate_config_model(DatabaseConfigInput, config)
        normalized_ip = _normalize_ip(validated.ip)
        normalized_config = validated.model_dump(exclude_none=True)
        normalized_config["ip"] = normalized_ip
        return NormalizedAssetConfig(target=normalized_ip, config=normalized_config)

    validated = _validate_config_model(WebConfigInput, config)
    normalized_url, normalized_protocol, normalized_port = _normalize_web_target(
        validated.url,
        validated.protocol,
        validated.port,
    )
    normalized_config = validated.model_dump(exclude_none=True)
    normalized_config["url"] = normalized_url
    normalized_config["protocol"] = normalized_protocol
    if normalized_port is not None:
        normalized_config["port"] = normalized_port
    else:
        normalized_config.pop("port", None)
    return NormalizedAssetConfig(target=normalized_url, config=normalized_config)


def sanitize_asset_config(config: dict[str, Any]) -> dict[str, Any]:
    """Remove password material from an asset config for API responses."""

    sanitized = deepcopy(config)
    credentials = sanitized.get("credentials")
    if isinstance(credentials, dict):
        username = str(credentials.get("username") or "").strip()
        if username:
            sanitized["credentials"] = {"username": username}
        else:
            sanitized.pop("credentials", None)
    return sanitized


def _validate_config_model(model: type[BaseModel], config: dict[str, Any]) -> BaseModel:
    """Validate a typed asset config and present readable errors."""

    try:
        return model.model_validate(config)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def _normalize_ip(value: str) -> str:
    """Normalize an IP address string."""

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def _normalize_web_target(url: str, protocol: str | None, port: int | None) -> tuple[str, str, int | None]:
    """Normalize web configuration into a canonical URL target."""

    raw_url = url.strip()
    requested_protocol = (protocol or "").strip().lower() or None
    if requested_protocol not in {None, "http", "https"}:
        raise ValueError("Web asset protocol must be 'http' or 'https'.")

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower() if parsed.scheme else requested_protocol or "https"
    if scheme not in {"http", "https"}:
        raise ValueError("Web asset URL must use http or https.")

    if parsed.scheme:
        hostname = parsed.hostname
        parsed_port = parsed.port
        path = parsed.path or ""
        query = parsed.query or ""
    else:
        parsed_without_scheme = urlparse(f"{scheme}://{raw_url}")
        hostname = parsed_without_scheme.hostname
        parsed_port = parsed_without_scheme.port
        path = parsed_without_scheme.path or ""
        query = parsed_without_scheme.query or ""

    if not hostname:
        raise ValueError("Web asset URL must include a hostname.")

    normalized_port = port if port is not None else parsed_port
    normalized_netloc = hostname
    if normalized_port is not None:
        normalized_netloc = f"{hostname}:{normalized_port}"

    normalized_url = urlunparse((scheme, normalized_netloc, path or "", "", query, ""))
    return normalized_url, scheme, normalized_port
