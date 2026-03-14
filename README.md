# SwanVA

SwanVA is a Python scanner monorepo. Each scanner lives in its own installable package under `scanners/`, and shared orchestration code lives in `va_manager/`.

## Architecture

```text
swanva/
├── scanners/
│   ├── pscan/
│   ├── os_scanner/
│   ├── web_scanner/
│   └── db_scanner/
├── va_manager/
├── .gitignore
├── README.md
└── requirements.txt
```

## Packages

- [scanners/pscan/README.md](/root/swanva/scanners/pscan/README.md): TCP connect, SYN, UDP, and service detection scanner
- [scanners/os_scanner/README.md](/root/swanva/scanners/os_scanner/README.md): SSH-based Linux system inventory collector
- [scanners/web_scanner/README.md](/root/swanva/scanners/web_scanner/README.md): plugin-based web scanning engine for Nikto and Nuclei
- [scanners/db_scanner/README.md](/root/swanva/scanners/db_scanner/README.md): placeholder package for future database scanning features
- [va_manager/manager.py](/root/swanva/va_manager/manager.py#L1): central manager skeleton for scanner orchestration

## Install

Install scanners individually from their package directories:

```bash
git clone <your-repo-url>
cd swanva
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
cd scanners/pscan
pip install .
```

Swap `scanners/pscan` for another scanner package when needed.

## Notes

- Scanners are independently versioned and installable.
- `pscan` is the most complete active scanner right now.
- `os_scanner` is a pure system-information collector for Linux hosts over SSH.
- `web_scanner` provides a plugin-based interface around Nikto and Nuclei.
- `db_scanner` remains a placeholder package ready for future implementation.
