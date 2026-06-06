from __future__ import annotations

import json
import re
import socket
from pathlib import Path

from .config import Settings
from .constants import DEFAULT_RULESET
from .geo import GeoLookup
from .iputil import normalize_ip, normalize_network
from .nft import write_and_apply
from .state import State


def state_for(settings: Settings) -> State:
    if not settings.paths:
        raise RuntimeError("missing configured paths")
    return State(settings.paths.state_db, settings.paths.audit_log)


def source_for_channel(state: State, ruleset: str, channel: str, ip: str) -> tuple[str, int | None]:
    prefix = state.ruleset_prefix(ruleset, channel)
    spec = normalize_network(ip, host_policy=prefix)
    return spec.text, spec.prefix_len


def ingest_source(
    settings: Settings,
    channel: str,
    ip: str,
    ruleset: str = DEFAULT_RULESET,
    note: str = "",
    apply_rules: bool = True,
) -> bool:
    addr = normalize_ip(ip)
    state = state_for(settings)
    try:
        source, prefix_len = source_for_channel(state, ruleset, channel, addr)
        geo = GeoLookup(settings).lookup(addr)
        ok = state.add_allow(
            ruleset,
            source,
            channel,
            prefix_len,
            ttl_days=settings.dynamic_ttl_days,
            note=note,
            geo=geo.geo,
            isp=geo.isp,
        )
        if ok and apply_rules:
            write_and_apply(settings, state, apply=True)
        return ok
    finally:
        state.close()


def sync_ddns(settings: Settings, apply_rules: bool = True) -> int:
    cfg_path = settings.paths.config_file if settings.paths else None
    if not cfg_path or not cfg_path.exists():
        return 0
    data = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    entries = data.get("ddns", [])
    changed = 0
    for item in entries:
        if isinstance(item, str):
            host = item
            ruleset = DEFAULT_RULESET
            enabled = True
        elif isinstance(item, dict):
            host = item.get("host")
            ruleset = item.get("ruleset", DEFAULT_RULESET)
            enabled = bool(item.get("enabled", True))
        else:
            continue
        if not host:
            continue
        if not enabled:
            continue
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(settings.ddns_timeout)
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            continue
        finally:
            socket.setdefaulttimeout(old_timeout)
        ips = sorted({info[4][0] for info in infos})
        for ip in ips:
            if ingest_source(settings, "ddns", ip, ruleset=ruleset, note=f"DDNS {host}", apply_rules=False):
                changed += 1
    if changed and apply_rules:
        state = state_for(settings)
        try:
            write_and_apply(settings, state, apply=True)
        finally:
            state.close()
    return changed


def record_block_line(settings: Settings, line: str) -> bool:
    src = re.search(r"\bSRC=([0-9.]+)", line)
    dpt = re.search(r"\bDPT=([0-9]+)", line)
    proto = re.search(r"\bPROTO=([A-Za-z0-9]+)", line)
    if not (src and dpt):
        return False
    ip = src.group(1)
    lport = int(dpt.group(1))
    protocol = proto.group(1) if proto else "UNKNOWN"
    geo = GeoLookup(settings).lookup(ip)
    state = state_for(settings)
    try:
        state.record_block(ip, protocol, lport, geo.geo, geo.isp)
        if settings.paths:
            from .logging_util import append_jsonl

            append_jsonl(
                settings.paths.blocked_log,
                {"source_ip": ip, "proto": protocol, "lport": lport, "geo": geo.geo, "isp": geo.isp},
            )
        return True
    finally:
        state.close()


def status(settings: Settings) -> dict[str, object]:
    state = state_for(settings)
    try:
        return {
            "mode": state.mode(),
            "rules": len(state.rules()),
            "active_allow_entries": len(state.active_allow_entries()),
            "blocked_visible": len(state.blocked(limit=1000)),
            "state_db": str(settings.paths.state_db if settings.paths else ""),
            "nft_conf": str(settings.paths.nft_conf if settings.paths else ""),
        }
    finally:
        state.close()


def bot_status(settings: Settings) -> dict[str, object]:
    state = state_for(settings)
    try:
        rulesets = [row for row in state.rulesets() if row["name"] != DEFAULT_RULESET]
        return {
            "mode": state.mode(),
            "allow": len(state.active_allow_entries()),
            "rules": len(state.rules()),
            "rulesets": len(rulesets),
            "blocked": len(state.blocked(limit=1000)),
        }
    finally:
        state.close()
