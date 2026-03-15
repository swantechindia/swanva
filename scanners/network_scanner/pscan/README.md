# pscan

`pscan` is SwanVA's network port scanner package. It supports TCP connect scans, SYN scans, UDP scans, and optional service detection for open TCP ports.

## Package

- Package root: [scanners/network_scanner/pscan](/root/swanva/scanners/network_scanner/pscan)
- Python package: [scanners/network_scanner/pscan/pscan](/root/swanva/scanners/network_scanner/pscan/pscan)
- Entry point: `pscan`
- Metadata: [scanners/network_scanner/pscan/pyproject.toml](/root/swanva/scanners/network_scanner/pscan/pyproject.toml#L1)

## Features

- TCP connect scanning
- SYN scanning with Scapy
- UDP scanning with Scapy
- Concurrent execution
- Flexible port specifications
- Optional banner-based service detection

## Install

```bash
cd scanners/network_scanner/pscan
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

- [scanners/network_scanner/pscan/pscan/cli.py](/root/swanva/scanners/network_scanner/pscan/pscan/cli.py#L1): CLI entrypoint
- [scanners/network_scanner/pscan/pscan/engine.py](/root/swanva/scanners/network_scanner/pscan/pscan/engine.py#L1): scan orchestration
- [scanners/network_scanner/pscan/pscan/tcp_scanner.py](/root/swanva/scanners/network_scanner/pscan/pscan/tcp_scanner.py#L1): TCP connect logic
- [scanners/network_scanner/pscan/pscan/syn_scanner.py](/root/swanva/scanners/network_scanner/pscan/pscan/syn_scanner.py#L1): SYN scan logic
- [scanners/network_scanner/pscan/pscan/udp_scanner.py](/root/swanva/scanners/network_scanner/pscan/pscan/udp_scanner.py#L1): UDP scan logic
- [scanners/network_scanner/pscan/pscan/service_detection.py](/root/swanva/scanners/network_scanner/pscan/pscan/service_detection.py#L1): banner detection

## Notes

- SYN and UDP scans may require elevated privileges.
- Service detection is intended for TCP-based scans.
