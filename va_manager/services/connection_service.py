"""Asset connection testing service."""

from __future__ import annotations

import socket
from datetime import datetime

import requests
from sqlalchemy.orm import Session

from va_manager.api.schemas.asset import (
    AssetConnectionTestRequest,
    AssetType,
    ConnectionTestEnvelope,
    ConnectionTestResult,
    normalize_asset_config,
)
from va_manager.models.asset import Asset
from va_manager.services.asset_service import AssetExecutionView, get_asset, get_asset_with_secrets

DEFAULT_CONNECTION_TIMEOUT_SECONDS = 5
CONNECTION_STATUS_SUCCESS = "success"
CONNECTION_STATUS_FAILED = "failed"


def test_asset_connection(
    db: Session,
    asset_id: int,
    timeout: int = DEFAULT_CONNECTION_TIMEOUT_SECONDS,
) -> ConnectionTestEnvelope:
    """Test connectivity for one asset and persist the latest health status."""

    persisted_asset = get_asset(db, asset_id)
    execution_asset = get_asset_with_secrets(db, asset_id)

    try:
        status, message = _run_connection_test(execution_asset, timeout)
    except ValueError:
        _update_connection_health(db, persisted_asset, CONNECTION_STATUS_FAILED)
        raise

    _update_connection_health(db, persisted_asset, status)
    return ConnectionTestEnvelope(data=ConnectionTestResult(status=status, message=message))


def test_unsaved_asset_connection(payload: AssetConnectionTestRequest) -> ConnectionTestEnvelope:
    """Test a draft asset configuration without persisting it."""

    normalized = normalize_asset_config(payload.asset_type, payload.config)
    execution_asset = AssetExecutionView(
        id=0,
        name="unsaved-asset",
        target=normalized.target,
        asset_type=payload.asset_type,
        config=normalized.config,
        description=None,
    )

    status, message = _run_connection_test(execution_asset, payload.timeout)
    return ConnectionTestEnvelope(data=ConnectionTestResult(status=status, message=message))


def _run_connection_test(asset: AssetExecutionView, timeout: int) -> tuple[str, str]:
    """Dispatch one connection test based on asset type."""

    if asset.asset_type == AssetType.ENDPOINT:
        return _test_endpoint_connection(asset, timeout)
    if asset.asset_type == AssetType.DATABASE:
        return _test_database_connection(asset, timeout)
    if asset.asset_type == AssetType.WEB:
        return _test_web_connection(asset, timeout)
    raise ValueError(f"Unsupported asset type: {asset.asset_type.value}")


def _test_endpoint_connection(asset: AssetExecutionView, timeout: int) -> tuple[str, str]:
    """Attempt a short-lived SSH connection to an endpoint asset."""

    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("SSH connectivity support is not installed.") from exc

    ip_address = str(asset.config.get("ip") or "").strip()
    if not ip_address:
        raise ValueError("Endpoint asset is missing an IP address.")
    credentials = _require_credentials(asset, "Endpoint")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip_address,
            username=credentials["username"],
            password=credentials["password"],
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        return CONNECTION_STATUS_FAILED, "Authentication failed."
    except (socket.timeout, TimeoutError):
        return CONNECTION_STATUS_FAILED, "Connection timed out."
    except (paramiko.SSHException, OSError):
        return CONNECTION_STATUS_FAILED, "Unable to connect to endpoint."
    finally:
        client.close()

    return CONNECTION_STATUS_SUCCESS, "Connection successful."


def _test_database_connection(asset: AssetExecutionView, timeout: int) -> tuple[str, str]:
    """Attempt a short-lived database connection."""

    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError("Database connectivity support is not installed.") from exc

    db_type = str(asset.config.get("db_type") or "").strip().lower()
    if db_type != "postgres":
        raise ValueError(f"Unsupported database type: {db_type or 'unknown'}.")

    ip_address = str(asset.config.get("ip") or "").strip()
    if not ip_address:
        raise ValueError("Database asset is missing an IP address.")
    credentials = _require_credentials(asset, "Database")
    connection = None

    try:
        connection = psycopg2.connect(
            host=ip_address,
            user=credentials["username"],
            password=credentials["password"],
            connect_timeout=timeout,
        )
    except psycopg2.OperationalError as exc:
        return CONNECTION_STATUS_FAILED, _normalize_database_error_message(str(exc))
    finally:
        if connection is not None:
            connection.close()

    return CONNECTION_STATUS_SUCCESS, "Connection successful."


def _test_web_connection(asset: AssetExecutionView, timeout: int) -> tuple[str, str]:
    """Attempt a simple HTTP(S) request to a web asset."""

    url = str(asset.config.get("url") or asset.target).strip()
    if not url:
        raise ValueError("Web asset is missing a URL.")

    try:
        response = requests.get(url, timeout=timeout)
        response.close()
    except requests.Timeout:
        return CONNECTION_STATUS_FAILED, "Connection timed out."
    except requests.RequestException:
        return CONNECTION_STATUS_FAILED, "Unable to connect to web asset."

    return CONNECTION_STATUS_SUCCESS, "Connection successful."


def _require_credentials(asset: AssetExecutionView, asset_label: str) -> dict[str, str]:
    """Return credentials from the decrypted config or reject invalid assets."""

    credentials = asset.config.get("credentials")
    if not isinstance(credentials, dict):
        raise ValueError(f"{asset_label} asset is missing credentials.")

    username = str(credentials.get("username") or "").strip()
    password = str(credentials.get("password") or "").strip()
    if not username or not password:
        raise ValueError(f"{asset_label} asset is missing credentials.")

    return {"username": username, "password": password}


def _normalize_database_error_message(error_message: str) -> str:
    """Map driver messages to safe, normalized API responses."""

    lowered = error_message.lower()
    if "password authentication failed" in lowered or "authentication failed" in lowered:
        return "Authentication failed."
    if "timeout" in lowered or "timed out" in lowered:
        return "Connection timed out."
    return "Unable to connect to database."


def _update_connection_health(db: Session, asset: Asset, status: str) -> None:
    """Persist the latest connection test status on the asset row."""

    asset.last_connection_status = status
    asset.last_checked_at = datetime.utcnow()
    db.commit()
