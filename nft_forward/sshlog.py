from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

from .config import load_settings
from .relay import ingest_source


ACCEPTED_RE = re.compile(r"\bAccepted\s+\S+\s+for\s+.+?\s+from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+port\b")


def handle_line(line: str) -> bool:
    match = ACCEPTED_RE.search(line)
    if not match:
        return False
    ip = match.group(1)
    settings = load_settings()
    if settings.exit_host and ip == settings.exit_host:
        return False
    return ingest_source(settings, "ssh_login", ip, note="ssh-login", apply_rules=True)


def _reader_command() -> list[str]:
    if Path("/var/log/auth.log").exists():
        return ["tail", "-n", "0", "-F", "/var/log/auth.log"]
    return ["journalctl", "-f", "-n", "0", "-u", "ssh", "-u", "sshd", "-o", "cat"]


def run() -> None:
    seen: set[str] = set()
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
                key = line.strip()
                if not key or key in seen:
                    continue
                seen.add(key)
                if len(seen) > 2048:
                    seen = set(list(seen)[-1024:])
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
