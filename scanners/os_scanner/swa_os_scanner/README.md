# os_scanner

`os_scanner` is SwanVA's SSH-based OS credential scanner. It connects to Linux hosts with credentials and collects structured system inventory data for later analysis.

## Package

- Package root: [scanners/os_scanner/swa_os_scanner](/root/swanva/scanners/os_scanner/swa_os_scanner)
- Python package: [scanners/os_scanner/swa_os_scanner/os_scanner](/root/swanva/scanners/os_scanner/swa_os_scanner/os_scanner)
- Entry point: `swan-os-scanner`
- Metadata: [scanners/os_scanner/swa_os_scanner/pyproject.toml](/root/swanva/scanners/os_scanner/swa_os_scanner/pyproject.toml#L1)

## What It Collects

- OS metadata
- Kernel version
- Installed packages
- Running services
- Local users
- Sudo configuration
- Common software versions
- Network interfaces, routes, and listening sockets
- Cron configuration
- Permissions for selected sensitive files

## Supported Systems

- Linux hosts reachable over SSH
- Debian and Ubuntu package inventory through `dpkg`
- RPM-based package inventory through `rpm`

## Install

```bash
cd scanners/os_scanner/swa_os_scanner
pip install .
```

## Usage

```bash
swan-os-scanner --host 192.168.1.25 --username root --password password
python -m os_scanner.scanner --host 192.168.1.25 --username root --password password
```

## Output

The scanner returns structured JSON shaped like:

```json
{
  "asset": "192.168.1.25",
  "scan_type": "os_credential_scan",
  "system": {
    "os": {},
    "kernel": "",
    "packages": [],
    "services": [],
    "users": [],
    "sudo": {},
    "software": {},
    "network": {},
    "cron": {},
    "permissions": {}
  }
}
```

## Important Files

- [scanners/os_scanner/swa_os_scanner/os_scanner/scanner.py](/root/swanva/scanners/os_scanner/swa_os_scanner/os_scanner/scanner.py#L1): collector orchestration and CLI
- [scanners/os_scanner/swa_os_scanner/os_scanner/ssh.py](/root/swanva/scanners/os_scanner/swa_os_scanner/os_scanner/ssh.py#L1): SSH transport layer
- [scanners/os_scanner/swa_os_scanner/os_scanner/system_detector.py](/root/swanva/scanners/os_scanner/swa_os_scanner/os_scanner/system_detector.py#L1): OS detection
- [scanners/os_scanner/swa_os_scanner/os_scanner/collectors](/root/swanva/scanners/os_scanner/swa_os_scanner/os_scanner/collectors): modular collectors
- [scanners/os_scanner/swa_os_scanner/os_scanner/parsers](/root/swanva/scanners/os_scanner/swa_os_scanner/os_scanner/parsers): package output parsers

## Notes

- This scanner is a pure system inventory collector.
- It does not perform vulnerability detection or CVE matching.
