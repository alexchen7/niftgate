from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SSHResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    latency_ms: int | None = None


def build_ssh_command(
    host: str,
    user: str,
    port: int,
    key: str,
    remote_args: list[str],
    timeout: int = 8,
    auth_method: str = "key",
    password_file: str = "",
) -> list[str]:
    target = f"{user}@{host}" if user else host
    method = (auth_method or "key").lower()
    cmd: list[str] = []
    if method == "password":
        if not password_file:
            raise ValueError("password auth requires password_file")
        if not Path(password_file).exists():
            raise ValueError(f"password file not found: {password_file}")
        cmd += ["sshpass", "-f", password_file]
    cmd += [
        "ssh",
        "-o",
        f"ConnectTimeout={timeout}",
        "-p",
        str(port),
    ]
    if method == "password":
        cmd += [
            "-o",
            "BatchMode=no",
            "-o",
            "PreferredAuthentications=password,keyboard-interactive",
        ]
    else:
        cmd += ["-o", "BatchMode=yes"]
        if key:
            cmd += ["-i", key]
    cmd.append(target)
    cmd += remote_args
    return cmd


def ssh_command(
    host: str,
    user: str,
    port: int,
    key: str,
    remote_args: list[str],
    timeout: int = 8,
    auth_method: str = "key",
    password_file: str = "",
) -> SSHResult:
    if not host:
        return SSHResult(False, "", "missing ssh host", 255)
    try:
        cmd = build_ssh_command(host, user, port, key, remote_args, timeout, auth_method, password_file)
    except ValueError as exc:
        return SSHResult(False, "", str(exc), 255)
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout + 3)
    except subprocess.TimeoutExpired as exc:
        return SSHResult(False, exc.stdout or "", "ssh timeout", 124, int((time.monotonic() - start) * 1000))
    except OSError as exc:
        return SSHResult(False, "", str(exc), 127, int((time.monotonic() - start) * 1000))
    return SSHResult(proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode, int((time.monotonic() - start) * 1000))
