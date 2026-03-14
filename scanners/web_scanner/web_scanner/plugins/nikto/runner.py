"""Nikto subprocess execution helpers."""

from __future__ import annotations

import subprocess

from ...models import ToolExecutionResult


def run_nikto(target: str) -> ToolExecutionResult:
    """Execute Nikto against a target and capture raw output."""

    command = ["nikto", "-h", target, "-Format", "json"]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return ToolExecutionResult(
            tool="nikto",
            target=target,
            command=command,
            error="Nikto is not installed or not available in PATH.",
        )
    except OSError as exc:
        return ToolExecutionResult(
            tool="nikto",
            target=target,
            command=command,
            error=str(exc),
        )

    return ToolExecutionResult(
        tool="nikto",
        target=target,
        command=command,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        error=completed.stderr.strip() if completed.returncode not in (0, None) and not completed.stdout else "",
    )
