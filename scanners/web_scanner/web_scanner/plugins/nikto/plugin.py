"""Nikto plugin implementation."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from ...models import ToolExecutionResult
from .parser import NiktoXmlStreamParser, parse_nikto_output


class Plugin:
    """Nikto plugin wrapper."""

    name = "nikto"

    def build_command(self, target: str) -> list[str]:
        """Build the Nikto command for a target."""

        return ["nikto", "-h", target, "-Format", "xml", "-output", "-"]

    def run(self, target: str) -> ToolExecutionResult:
        """Execute Nikto for a target."""

        command = self.build_command(target)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return ToolExecutionResult(
                tool=self.name,
                target=target,
                command=command,
                error="nikto not installed",
            )
        except OSError as exc:
            return ToolExecutionResult(
                tool=self.name,
                target=target,
                command=command,
                error=str(exc),
            )

        return ToolExecutionResult(
            tool=self.name,
            target=target,
            command=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            error=completed.stderr.strip() if completed.returncode not in (0, None) and not completed.stdout else "",
        )

    def create_stream_parser(self, target: str) -> NiktoXmlStreamParser:
        """Create a stateful parser for streamed Nikto XML output."""

        return NiktoXmlStreamParser(target)

    def run_to_tempfile(self, target: str) -> ToolExecutionResult:
        """Execute Nikto and capture XML output via a temporary file."""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as handle:
            output_path = Path(handle.name)

        command = ["nikto", "-h", target, "-Format", "xml", "-output", str(output_path)]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return ToolExecutionResult(
                tool=self.name,
                target=target,
                command=command,
                error="nikto not installed",
            )
        except OSError as exc:
            return ToolExecutionResult(
                tool=self.name,
                target=target,
                command=command,
                error=str(exc),
            )

        try:
            stdout = output_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            stdout = ""
        finally:
            output_path.unlink(missing_ok=True)

        return ToolExecutionResult(
            tool=self.name,
            target=target,
            command=command,
            stdout=stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            error=completed.stderr.strip() if completed.returncode not in (0, None) and not stdout else "",
        )

    def parse(self, raw_output: str, target: str) -> list[dict[str, object]]:
        """Parse Nikto output into intermediate findings."""

        return parse_nikto_output(raw_output, target)
