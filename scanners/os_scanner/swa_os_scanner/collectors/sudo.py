"""Sudo configuration collector."""

from __future__ import annotations

from swa_os_scanner.ssh import run_command


def collect_sudo(ssh) -> dict[str, object]:
    """Collect sudo configuration file information."""

    sudoers_content = run_command(ssh, "cat /etc/sudoers")
    raw_files = run_command(ssh, "ls /etc/sudoers.d 2>/dev/null")

    sudo_config_files: list[str] = []
    for line in raw_files.splitlines():
        entry = line.strip()
        if not entry:
            continue
        if entry.startswith("/"):
            sudo_config_files.append(entry)
        else:
            sudo_config_files.append(f"/etc/sudoers.d/{entry}")

    return {
        "sudo_config_files": sudo_config_files,
        "sudoers_content": sudoers_content,
    }
