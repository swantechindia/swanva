# web_scanner

`web_scanner` is SwanVA's plugin-based web scanning package. It provides a clean scanning interface that runs Nikto and Nuclei in parallel, normalizes their output, and supports streaming findings for later ingestion by `va_manager`.

## Package

- Package root: [scanners/web_scanner](/root/swanva/scanners/web_scanner)
- Python package: [scanners/web_scanner/web_scanner](/root/swanva/scanners/web_scanner/web_scanner)
- Metadata: [scanners/web_scanner/pyproject.toml](/root/swanva/scanners/web_scanner/pyproject.toml#L1)

## Features

- Plugin-based engine
- Nikto integration through subprocess
- Nuclei integration through subprocess
- Parallel execution through `asyncio`
- Streaming result support
- Unified finding normalization across tools
- Graceful failure when a tool is not installed

## Structure

- [scanners/web_scanner/web_scanner/scanner.py](/root/swanva/scanners/web_scanner/web_scanner/scanner.py#L1): public `start_scan()` interface
- [scanners/web_scanner/web_scanner/engine.py](/root/swanva/scanners/web_scanner/web_scanner/engine.py#L1): plugin loading and execution
- [scanners/web_scanner/web_scanner/models.py](/root/swanva/scanners/web_scanner/web_scanner/models.py#L1): shared result models
- [scanners/web_scanner/web_scanner/normalizer.py](/root/swanva/scanners/web_scanner/web_scanner/normalizer.py#L1): Swan schema normalization
- [scanners/web_scanner/web_scanner/plugins/nikto](/root/swanva/scanners/web_scanner/web_scanner/plugins/nikto): Nikto plugin
- [scanners/web_scanner/web_scanner/plugins/nuclei](/root/swanva/scanners/web_scanner/web_scanner/plugins/nuclei): Nuclei plugin

## Install

```bash
cd scanners/web_scanner
pip install .
```

## Usage

```python
from scanners.web_scanner.web_scanner.scanner import start_scan, stream_scan

results = start_scan("http://example.com")
results = start_scan("http://example.com", tools=["nikto"])

for finding in stream_scan("http://example.com"):
    print(finding)
```

If `tools` is omitted, both `nikto` and `nuclei` are attempted.

## Output

Findings are normalized into the Swan web finding schema:

```json
{
  "scanner": "web_scanner",
  "tool": "nikto",
  "target": "http://example.com",
  "name": "finding name",
  "severity": "low",
  "url": "http://example.com/path",
  "description": "details",
  "evidence": "",
  "timestamp": ""
}
```

## Notes

- This package only exposes scanning logic; queueing and worker orchestration belong in `va_manager`.
- If Nikto or Nuclei is missing from `PATH`, the scanner returns structured errors instead of raising hard failures.
