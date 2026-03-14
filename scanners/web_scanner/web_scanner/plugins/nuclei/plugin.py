"""Nuclei plugin implementation."""

from __future__ import annotations

from ...models import ToolExecutionResult
from .parser import NucleiStreamParser, parse_nuclei_output
from .runner import run_nuclei


class Plugin:
    """Nuclei plugin wrapper."""

    name = "nuclei"

    def build_command(self, target: str) -> list[str]:
        """Build the Nuclei command for a target."""

        return ["nuclei", "-u", target, "-json"]

    def run(self, target: str) -> ToolExecutionResult:
        """Execute Nuclei for a target."""

        return run_nuclei(target)

    def create_stream_parser(self, target: str) -> NucleiStreamParser:
        """Create a stateful parser for streamed Nuclei output."""

        return NucleiStreamParser(target)

    def parse(self, raw_output: str, target: str) -> list[dict[str, object]]:
        """Parse Nuclei output into intermediate findings."""

        return parse_nuclei_output(raw_output, target)
