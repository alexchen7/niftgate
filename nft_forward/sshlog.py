from __future__ import annotations

import re
import socket
import subprocess
import sys
import time
from functools import lru_cache
from pathlib import Path

from .config import load_settings
from .relay import ingest_source


ACCEPTED_RE = re.compile(r"\bAccepted\s+\S+\s+for\s+.+?\s+from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+port\b")


@lru_cache(maxsize=16)
def resolved_ipv4(host: str) -> frozenset[str]:
    if not host:
        return frozenset()
    try:
        return frozenset(info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET))
    except OSError:
        return frozenset()


def accepted_ip(line: str) -> str | None:
    match = ACCEPTED_RE.search(line)
    return match.group(1) if match else None


def handle_line(line: str) -> bool:
    ip = accepted_ip(line)
    if not ip:
        return False
    settings = load_settings()
    if settings.exit_host and ip in resolved_ipv4(settings.exit_host):
        return False
    return ingest_source(settings, "ssh_login", ip, note="ssh-login", apply_rules=True)


def _reader_command() -> list[str]:
    if Path("/var/log/auth.log").exists():
        return ["tail", "-n", "0", "-F", "/var/log/auth.log"]
    return ["journalctl", "-f", "-n", "0", "-u", "ssh", "-u", "sshd", "-o", "cat"]


def run() -> None:
    seen: dict[str, float] = {}
    while True:
        try:
            proc = subprocess.Popen(
                _reader_command(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                ip = accepted_ip(line)
                if not ip:
                    continue
                now = time.monotonic()
                if now - seen.get(ip, 0) < 60:
                    continue
                seen[ip] = now
                if len(seen) > 2048:
                    cutoff = now - 3600
                    seen = {key: value for key, value in seen.items() if value >= cutoff}
                try:
                    handle_line(line)
                except Exception as exc:
                    print(f"nft-forward sshlog line error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        except (OSError, AssertionError) as exc:
            print(f"nft-forward sshlog reader error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            time.sleep(10)
        except Exception as exc:
            print(f"nft-forward sshlog error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            time.sleep(5)
