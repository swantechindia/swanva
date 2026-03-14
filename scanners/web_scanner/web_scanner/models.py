"""Shared Pydantic data models for the web scanner."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SwanFinding(BaseModel):
    """Unified Swan finding schema."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    scanner: str = "web_scanner"
    tool: str
    target: str
    name: str
    severity: str
    url: str
    description: str = ""
    evidence: str = ""
    timestamp: str = ""


class ToolExecutionResult(BaseModel):
    """Raw command execution result from a plugin runner."""

    model_config = ConfigDict(extra="ignore")

    tool: str
    target: str
    command: list[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    error: str = ""


class ToolScanResult(BaseModel):
    """Parsed and normalized results returned by a plugin."""

    model_config = ConfigDict(extra="ignore")

    tool: str
    target: str
    findings: list[SwanFinding] = Field(default_factory=list)
    error: str = ""
    command: list[str] = Field(default_factory=list)
    returncode: int | None = None


class ScanError(BaseModel):
    """Structured tool execution warning or error."""

    model_config = ConfigDict(extra="ignore")

    tool: str
    error: str
    returncode: int | None = None
    command: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Structured scan report returned by the public interface."""

    model_config = ConfigDict(extra="ignore")

    asset: str
    scan_type: str = "web_scan"
    findings: list[SwanFinding] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
