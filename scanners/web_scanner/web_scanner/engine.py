"""Plugin loading, parallel execution, and streaming for the web scanner."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, Generator
from contextlib import suppress
from queue import Empty, Queue
from threading import Thread

from .models import ScanError, ScanReport, SwanFinding, ToolExecutionResult, ToolScanResult
from .normalizer import normalize_findings
from .plugins.nikto.plugin import Plugin as NiktoPlugin
from .plugins.nuclei.plugin import Plugin as NucleiPlugin

LOGGER = logging.getLogger(__name__)
DEFAULT_TOOLS = ["nikto", "nuclei"]
PLUGIN_REGISTRY = {
    "nikto": NiktoPlugin,
    "nuclei": NucleiPlugin,
}
_STREAM_SENTINEL = object()
_PLUGIN_DONE = object()


class ScannerEngine:
    """Load and execute web scanner plugins for a target."""

    def __init__(self, target: str, tools: list[str] | None = None) -> None:
        if not target or not target.strip():
            raise ValueError("Target is required.")

        self.target = target.strip()
        self.tools = [tool.lower() for tool in tools] if tools else list(DEFAULT_TOOLS)

    async def run(self) -> ScanReport:
        """Execute plugins concurrently and collect all findings."""

        plugins = self._load_plugins()
        results = await _run_plugins_async(self.target, plugins)

        findings: list[SwanFinding] = []
        errors: list[ScanError] = []

        for result in results:
            findings.extend(result.findings)
            if result.error:
                LOGGER.warning("%s scan skipped or failed for %s: %s", result.tool, result.target, result.error)
                errors.append(
                    ScanError(
                        tool=result.tool,
                        error=result.error,
                        returncode=result.returncode,
                        command=result.command,
                    )
                )

        return ScanReport(
            asset=self.target,
            findings=findings,
            errors=errors,
        )

    async def stream(self) -> AsyncGenerator[SwanFinding, None]:
        """Yield normalized findings as plugins complete."""

        plugins = self._load_plugins()

        async for finding, error in _scan_stream_async(self.target, plugins):
            if error is not None:
                LOGGER.warning("%s scan skipped or failed for %s: %s", error.tool, self.target, error.error)
                continue
            yield finding

    def _load_plugins(self) -> list[object]:
        """Instantiate the requested plugins."""

        plugins: list[object] = []

        for tool in self.tools:
            plugin_class = PLUGIN_REGISTRY.get(tool)
            if plugin_class is None:
                raise ValueError(f"Unsupported tool: {tool}")
            plugins.append(plugin_class())

        return plugins


def run_plugins(target: str, tools: list[str] | None = None) -> ScanReport:
    """Run all requested plugins and return a full structured report."""

    return asyncio.run(ScannerEngine(target, tools).run())


def scan_stream(target: str, tools: list[str] | None = None) -> Generator[SwanFinding, None, None]:
    """Yield findings one by one while plugins execute in parallel."""

    queue: Queue[object] = Queue()

    def _runner() -> None:
        asyncio.run(_stream_to_queue(target, tools, queue))

    thread = Thread(target=_runner, daemon=True)
    thread.start()

    try:
        while True:
            try:
                item = queue.get(timeout=0.25)
            except Empty:
                if not thread.is_alive():
                    break
                continue
            if item is _STREAM_SENTINEL:
                break
            if isinstance(item, SwanFinding):
                yield item
    finally:
        thread.join(timeout=0.1)


async def _stream_to_queue(target: str, tools: list[str] | None, queue: Queue[object]) -> None:
    """Execute the async streaming pipeline and push findings onto a queue."""

    try:
        async for finding, error in _scan_stream_async(target, ScannerEngine(target, tools)._load_plugins()):
            if error is not None:
                LOGGER.warning("%s scan skipped or failed for %s: %s", error.tool, target, error.error)
                continue
            queue.put(finding)
    finally:
        queue.put(_STREAM_SENTINEL)


async def _run_plugins_async(target: str, plugins: list[object]) -> list[ToolScanResult]:
    """Run all plugins concurrently using asyncio subprocess execution."""

    if not plugins:
        return []

    tasks = [
        asyncio.create_task(_execute_plugin_async(plugin, target))
        for plugin in plugins
    ]
    return await asyncio.gather(*tasks)


async def _scan_stream_async(
    target: str,
    plugins: list[object],
) -> AsyncGenerator[tuple[SwanFinding | None, ScanError | None], None]:
    """Run plugins concurrently and yield findings as each finishes."""

    if not plugins:
        return

    queue: asyncio.Queue[object] = asyncio.Queue()
    tasks = [asyncio.create_task(_stream_plugin_async(plugin, target, queue)) for plugin in plugins]
    completed_plugins = 0

    try:
        while completed_plugins < len(tasks):
            item = await queue.get()
            if item is _PLUGIN_DONE:
                completed_plugins += 1
                continue

            finding, error = item
            yield finding, error
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(*tasks)


async def _execute_plugin_async(plugin: object, target: str) -> ToolScanResult:
    """Run a single plugin asynchronously and normalize its findings."""

    execution = await _run_command_async(plugin.name, target, plugin.build_command(target))

    parsed_findings: list[dict[str, object]] = []
    if execution.stdout:
        parsed_findings = plugin.parse(execution.stdout, target)

    return ToolScanResult(
        tool=plugin.name,
        target=target,
        findings=normalize_findings(parsed_findings, plugin.name, target),
        error=execution.error,
        command=execution.command,
        returncode=execution.returncode,
    )


async def _stream_plugin_async(
    plugin: object,
    target: str,
    queue: asyncio.Queue[object],
) -> None:
    """Run one plugin and push streamed findings or errors onto a queue."""

    try:
        parser_factory = getattr(plugin, "create_stream_parser", None)
        if parser_factory is None:
            result = await _execute_plugin_async(plugin, target)
            if result.error:
                await queue.put(
                    (
                        None,
                        ScanError(
                            tool=result.tool,
                            error=result.error,
                            returncode=result.returncode,
                            command=result.command,
                        ),
                    )
                )
            for finding in result.findings:
                await queue.put((finding, None))
            return

        await _stream_command_async(plugin, target, queue)
    finally:
        await queue.put(_PLUGIN_DONE)


async def _run_command_async(tool: str, target: str, command: list[str]) -> ToolExecutionResult:
    """Execute a scanner command asynchronously and capture raw output."""

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return ToolExecutionResult(
            tool=tool,
            target=target,
            command=command,
            error=f"{tool.capitalize()} is not installed or not available in PATH.",
        )
    except OSError as exc:
        return ToolExecutionResult(
            tool=tool,
            target=target,
            command=command,
            error=str(exc),
        )

    try:
        stdout_bytes, stderr_bytes = await process.communicate()
    except (asyncio.CancelledError, KeyboardInterrupt):
        await _terminate_process(process)
        raise

    stdout = stdout_bytes.decode("utf-8", errors="ignore")
    stderr = stderr_bytes.decode("utf-8", errors="ignore")

    return ToolExecutionResult(
        tool=tool,
        target=target,
        command=command,
        stdout=stdout,
        stderr=stderr,
        returncode=process.returncode,
        error=stderr.strip() if process.returncode not in (0, None) and not stdout else "",
    )


async def _stream_command_async(plugin: object, target: str, queue: asyncio.Queue[object]) -> None:
    """Stream a plugin command and emit findings as stdout becomes parseable."""

    command = plugin.build_command(target)
    tool = plugin.name

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        await queue.put(
            (
                None,
                ScanError(
                    tool=tool,
                    error=f"{tool.capitalize()} is not installed or not available in PATH.",
                    command=command,
                ),
            )
        )
        return
    except OSError as exc:
        await queue.put((None, ScanError(tool=tool, error=str(exc), command=command)))
        return

    stderr_task = asyncio.create_task(process.stderr.read() if process.stderr else asyncio.sleep(0, result=b""))
    parser = plugin.create_stream_parser(target)
    emitted_any = False

    try:
        if process.stdout is not None:
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break

                findings = normalize_findings(parser.feed(chunk.decode("utf-8", errors="ignore")), tool, target)
                for finding in findings:
                    emitted_any = True
                    await queue.put((finding, None))

        trailing_findings = normalize_findings(parser.close(), tool, target)
        for finding in trailing_findings:
            emitted_any = True
            await queue.put((finding, None))

        await process.wait()
        stderr_bytes = await stderr_task
    except (asyncio.CancelledError, KeyboardInterrupt):
        stderr_task.cancel()
        with suppress(asyncio.CancelledError):
            await stderr_task
        await _terminate_process(process)
        raise

    stderr = stderr_bytes.decode("utf-8", errors="ignore")

    if process.returncode not in (0, None) and not emitted_any:
        await queue.put(
            (
                None,
                ScanError(
                    tool=tool,
                    error=stderr.strip() or f"{tool} exited with status {process.returncode}",
                    returncode=process.returncode,
                    command=command,
                ),
            )
        )


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    """Terminate an asyncio subprocess and wait for it to exit."""

    if process.returncode is not None:
        return

    with suppress(ProcessLookupError):
        process.terminate()

    try:
        await asyncio.wait_for(process.wait(), timeout=2)
        return
    except (asyncio.TimeoutError, ProcessLookupError):
        pass

    with suppress(ProcessLookupError):
        process.kill()
    with suppress(asyncio.TimeoutError, ProcessLookupError):
        await asyncio.wait_for(process.wait(), timeout=2)
