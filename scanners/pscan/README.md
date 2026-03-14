# pscan

`pscan` is SwanVA's network port scanner package. It supports TCP connect scans, SYN scans, UDP scans, and optional service detection for open TCP ports.

## Package

- Package root: [scanners/pscan](/root/swanva/scanners/pscan)
- Python package: [scanners/pscan/pscan](/root/swanva/scanners/pscan/pscan)
- Entry point: `pscan`
- Metadata: [scanners/pscan/pyproject.toml](/root/swanva/scanners/pscan/pyproject.toml#L1)

## Features

- TCP connect scanning
- SYN scanning with Scapy
- UDP scanning with Scapy
- Concurrent execution
- Flexible port specifications
- Optional banner-based service detection

## Install

```bash
cd scanners/pscan
pip install .
```

## Usage

```bash
pscan -t 192.168.1.10
pscan -t 192.168.1.10 -sS
pscan -t 192.168.1.10 -sU
pscan -t 192.168.1.10 -sS -sV
```

## Important Files

- [scanners/pscan/pscan/cli.py](/root/swanva/scanners/pscan/pscan/cli.py#L1): CLI entrypoint
- [scanners/pscan/pscan/engine.py](/root/swanva/scanners/pscan/pscan/engine.py#L1): scan orchestration
- [scanners/pscan/pscan/tcp_scanner.py](/root/swanva/scanners/pscan/pscan/tcp_scanner.py#L1): TCP connect logic
- [scanners/pscan/pscan/syn_scanner.py](/root/swanva/scanners/pscan/pscan/syn_scanner.py#L1): SYN scan logic
- [scanners/pscan/pscan/udp_scanner.py](/root/swanva/scanners/pscan/pscan/udp_scanner.py#L1): UDP scan logic
- [scanners/pscan/pscan/service_detection.py](/root/swanva/scanners/pscan/pscan/service_detection.py#L1): banner detection

## Notes

- SYN and UDP scans may require elevated privileges.
- Service detection is intended for TCP-based scans.
