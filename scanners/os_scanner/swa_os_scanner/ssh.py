"""SSH connection helpers for the OS credential scanner."""

from __future__ import annotations

from typing import Any


def connect(host: str, username: str, password: str, timeout: float = 10.0) -> Any:
    """Create an SSH connection to a target host."""

    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=username,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
    )
    return client


def run_command(ssh: Any, command: str, check: bool = False) -> str:
    """Run a command over SSH and return decoded stdout."""

    _, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8", errors="ignore").strip()

    if check and exit_status != 0:
        error = stderr.read().decode("utf-8", errors="ignore").strip()
        raise RuntimeError(error or f"Command failed: {command}")

    return output
