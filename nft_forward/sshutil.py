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


SSH_ATTEMPTS = 5
TRANSIENT_SSH_ERRORS = (
    "kex_exchange_identification",
    "connection closed by remote host",
    "connection reset by peer",
    "ssh timeout",
)


def is_transient_ssh_failure(result: SSHResult) -> bool:
    if result.ok:
        return False
    if result.returncode not in {124, 255}:
        return False
    text = f"{result.stdout}\n{result.stderr}".lower()
    return any(pattern in text for pattern in TRANSIENT_SSH_ERRORS)


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
    deadline = start + timeout + 3
    result: SSHResult | None = None
    for attempt in range(SSH_ATTEMPTS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result or SSHResult(False, "", "ssh timeout", 124, int((time.monotonic() - start) * 1000))
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=remaining)
            result = SSHResult(proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired as exc:
            result = SSHResult(False, exc.stdout or "", "ssh timeout", 124)
        except OSError as exc:
            return SSHResult(False, "", str(exc), 127, int((time.monotonic() - start) * 1000))
        result.latency_ms = int((time.monotonic() - start) * 1000)
        if result.ok or attempt == SSH_ATTEMPTS - 1 or not is_transient_ssh_failure(result):
            return result
        delay = min(2.0, 0.5 * (attempt + 1))
        if time.monotonic() + delay >= deadline:
            return result
        time.sleep(delay)
    assert result is not None
    return result
