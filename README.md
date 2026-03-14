# SwanVA

SwanVA is a Python scanner monorepo. Each scanner lives in its own installable package under `scanners/`.

## Architecture

- `scanners/`: independently installable scanner packages
- `va_manager/`: shared orchestration layer for coordinating scanner execution

Current packages:

- `scanners/pscan`: network port scanner with TCP connect, SYN, UDP, and service detection
- `scanners/os_scanner`: placeholder package for future OS detection work
- `scanners/web_scanner`: placeholder package for future web scanning work
- `scanners/db_scanner`: placeholder package for future database scanning work
- `va_manager`: central management module for future scanner orchestration

The `pscan` package remains a Python-based port scanner for TCP connect, SYN stealth, and UDP reconnaissance. It provides a simple CLI, concurrent scanning, structured scan results inside the engine, and optional service/version detection for open TCP ports.

## Features

- TCP connect scanning
- SYN stealth scanning with Scapy
- UDP scanning with Scapy
- Concurrent threaded execution
- Flexible port parsing like `1-1000`, `22,80,443`, and `1-1024,3306`
- Optional service/version detection with banner grabbing
- Clean CLI output for quick operator use

## Requirements

- Python 3.10 or newer recommended
- `pip`
- Network access to the target
- Elevated privileges for raw-packet scans in many environments

SYN and UDP scans often require `sudo` or root privileges because they rely on raw packet operations through Scapy.

## Installation

Clone or copy the project to your system, then install the scanner package you want.

```bash
git clone <your-repo-url>
cd swanva
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
cd scanners/pscan
pip install .
```

This installs the `pscan` package and creates the `pscan` command.

Package metadata for the port scanner is defined in [scanners/pscan/pyproject.toml](/root/swanva/scanners/pscan/pyproject.toml).

Main runtime dependency:

```txt
scapy
```

## Quick Start

Run a default TCP connect scan against the first 1000 ports:

```bash
pscan -t 192.168.1.10
```

Scan a custom range:

```bash
pscan -t 192.168.1.10 -p 1-2000
```

Scan a custom list:

```bash
pscan -t 192.168.1.10 -p 22,80,443,8080
```

Increase concurrency and reduce timeout:

```bash
pscan -t 192.168.1.10 -p 1-1000 --threads 200 --timeout 0.5
```

## Usage

Display CLI help:

```bash
pscan --help
```

Current CLI options:

- `-t, --target`: target IP address or hostname
- `-p, --ports`: port range/list, default `1-1000`
- `--threads`: concurrent worker count, default `100`
- `--timeout`: socket or packet timeout in seconds, default `1.0`
- `-sS`: TCP SYN stealth scan
- `-sU`: UDP scan
- `-sV`: service/version detection for open TCP ports
- `--log-level`: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

## Scan Modes

### TCP Connect Scan

This is the default mode and does not require `-sS` or `-sU`.

```bash
pscan -t scanme.local -p 1-1000
```

Use this mode when you want compatibility and do not need raw packet scanning.

### SYN Stealth Scan

Run a SYN scan with:

```bash
sudo pscan -t 192.168.1.10 -sS -p 1-1024
```

Behavior:

- SYN -> SYN/ACK = open
- SYN -> RST = closed
- No response = filtered

This mode is lower-noise than full TCP connect but usually needs elevated privileges.

### UDP Scan

Run a UDP scan with:

```bash
sudo pscan -t 192.168.1.10 -sU -p 53,67,68,123,161
```

Behavior:

- UDP response = open
- ICMP port unreachable = closed
- No response or non-port-unreachable ICMP = filtered

UDP scans are slower and more ambiguous by nature, so longer timeouts may help.

### Service and Version Detection

Enable banner grabbing on open TCP ports:

```bash
pscan -t 192.168.1.10 -p 22,80,443 -sV
```

You can combine it with SYN scan:

```bash
sudo pscan -t 192.168.1.10 -sS -sV -p 1-1024
```

Supported banner-grab targets include common HTTP, SSH, FTP, and SMTP services.

`-sV` is intended for TCP-based scans. If used with UDP mode, pscan skips TCP banner grabbing and falls back to basic service naming where possible.

## Output Examples

Basic output:

```text
PORT     STATE
22       OPEN
80       OPEN
443      OPEN
```

Service detection output:

```text
PORT     STATE SERVICE VERSION
22       open  ssh     OpenSSH 8.4
80       open  http    Apache 2.4
443      open  https   -
```

No open ports:

```text
PORT     STATE
No open ports found.
```

## Practical Examples

Scan a web server for common ports:

```bash
pscan -t example.com -p 22,80,443,8080,8443 -sV
```

Fast internal TCP sweep:

```bash
pscan -t 10.0.0.25 -p 1-4096 --threads 300 --timeout 0.3
```

Focused UDP infrastructure scan:

```bash
sudo pscan -t 10.0.0.53 -sU -p 53,123,161 --timeout 2
```

Debug a scan with verbose logging:

```bash
pscan -t 192.168.1.10 -p 22,80 -sV --log-level DEBUG
```

## Troubleshooting

### `python: command not found`

Use `python3` instead:

```bash
pscan -t 127.0.0.1
```

### `No module named 'scapy'`

Install the package:

```bash
pip install .
```

If using a virtual environment, make sure it is activated first.

### SYN or UDP scan fails with permissions errors

Run with elevated privileges:

```bash
sudo pscan -t 192.168.1.10 -sS
sudo pscan -t 192.168.1.10 -sU
```

### All ports show as filtered

Possible causes:

- host firewall is dropping probes
- a network firewall is filtering traffic
- timeout is too low
- raw packet scans are blocked in your environment
- the target is offline or unreachable

Try increasing timeout:

```bash
pscan -t 192.168.1.10 --timeout 2
```

### Hostname resolution fails

Use a direct IP address or verify DNS resolution for the hostname.

### Service detection returns `-`

Some services do not expose a banner, require protocol-specific negotiation, or are protected by middleboxes. In those cases pscan may identify the port as open but not extract a usable version string.

## Operational Notes

- TCP connect scans are the most portable mode.
- SYN and UDP scans are more environment-sensitive and may behave differently depending on OS privileges, local firewall rules, and target filtering.
- UDP results are inherently less certain than TCP results.
- Large scans should balance `--threads` and `--timeout` to avoid overwhelming your host or the network.

## Legal and Ethical Use

Use pscan only on systems and networks you own or are explicitly authorized to assess.

Unauthorized port scanning may violate:

- laws and regulations
- company policy
- ISP or cloud provider acceptable-use terms
- contractual security boundaries

Before running pscan:

- confirm written authorization
- define scan scope clearly
- notify stakeholders when appropriate
- avoid production disruption by tuning ports, threads, and timeouts responsibly

The operator is responsible for compliant and ethical use of this tool.

## Project Status

pscan currently supports:

- Phase 1: threaded TCP connect scanning
- Phase 2: SYN scan, UDP scan, and TCP service detection

Installed command examples:

- `pscan -t 192.168.1.10`
- `pscan -t 192.168.1.10 -sS`
- `pscan -t 192.168.1.10 -sU`
- `pscan -t 192.168.1.10 -sS -sV`

Future improvements could include:

- JSON or file-based report export
- richer protocol fingerprinting
- test coverage
- packaging as an installable command-line application
