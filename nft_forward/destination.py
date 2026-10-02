from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from urllib.parse import urlsplit

from .iputil import normalize_ip


def normalize_destination(value: str) -> str:
    """Return an IPv4 address or DNS hostname; URLs contribute only their host."""
    value = value.strip()
    if not value or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise ValueError("destination must be an IPv4 address, hostname, or HTTP(S) URL")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("destination URL must use http:// or https://")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("destination URL must not contain credentials")
        _ = parsed.port  # Reject malformed ports even though routing uses dest_port.
        value = parsed.hostname
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        return normalize_ip(str(address))
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if (
        len(value) > 253
        or re.fullmatch(r"[0-9.]+", value)
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels)
    ):
        raise ValueError("invalid destination hostname")
    return value


def validate_port(value: int) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def resolve_ipv4(host: str, timeout: float = 5) -> list[str]:
    # getaddrinfo is not bounded by socket.setdefaulttimeout. A child process
    # lets subprocess.run kill and reap a stalled system resolver.
    code = (
        "import json,socket,sys; "
        "print(json.dumps(sorted({r[4][0] for r in "
        "socket.getaddrinfo(sys.argv[1],None,socket.AF_INET,socket.SOCK_STREAM)})))"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code, host], capture_output=True, text=True,
            timeout=max(0.1, float(timeout)),
        )
        if proc.returncode:
            raise ValueError("resolver returned no usable IPv4 address")
        answers = json.loads(proc.stdout)
        if not isinstance(answers, list) or not answers:
            raise ValueError("resolver returned no usable IPv4 address")
        return sorted({normalize_ip(ip) for ip in answers}, key=ipaddress.IPv4Address)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"DNS lookup failed for {host}: {exc}") from exc


def prepare_destination(value: str, timeout: float, current=None) -> tuple[str, str]:
    destination = normalize_destination(value)
    try:
        return normalize_ip(destination), ""
    except ValueError:
        pass
    if current and current.dest_host == destination:
        return current.dest_ip, destination
    return resolve_ipv4(destination, timeout)[0], destination
