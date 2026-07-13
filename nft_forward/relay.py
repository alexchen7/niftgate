from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path

from . import __version__
from .config import Settings
from .constants import DEFAULT_RULESET
from .geo import GeoLookup
from .iputil import contains_ip, normalize_ip, normalize_network
from .nft import write_and_apply
from .state import State


def state_for(settings: Settings) -> State:
    if not settings.paths:
        raise RuntimeError("missing configured paths")
    return State(settings.paths.state_db, settings.paths.audit_log)


def apply_state(settings: Settings, state: State, reason: str) -> str:
    try:
        message = write_and_apply(settings, state, apply=True)
    except Exception as exc:
        state.set_meta("apply_pending", "1")
        state.audit("nft_apply_failed", reason=reason, error=str(exc))
        raise
    state.set_meta("apply_pending", "0")
    state.audit("nft_apply_ok", reason=reason, message=message)
    return message


def retry_pending_apply(settings: Settings) -> bool:
    state = state_for(settings)
    try:
        if state.get_meta("apply_pending", "0") != "1":
            return False
        apply_state(settings, state, "pending-retry")
        return True
    except Exception:
        return False
    finally:
        state.close()


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
            state.set_meta("apply_pending", "1")
            apply_state(settings, state, f"ingest:{channel}")
        return ok
    finally:
        state.close()


def sync_ddns(settings: Settings, apply_rules: bool = True) -> int:
    if apply_rules:
        retry_pending_apply(settings)
    cfg_path = settings.paths.config_file if settings.paths else None
    if not cfg_path or not cfg_path.exists():
        return 0
    data = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    entries = data.get("ddns", [])
    state = state_for(settings)
    changed = 0
    try:
        if state.mode() == "attack":
            return 0
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
            if not host or not enabled:
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
            try:
                prefix = state.ruleset_prefix(ruleset, "ddns")
            except ValueError:
                continue
            current_sources = {
                normalize_network(ip, host_policy=prefix).text
                for ip in ips
            }
            for ip in ips:
                if ingest_source(
                    settings,
                    "ddns",
                    ip,
                    ruleset=ruleset,
                    note=f"DDNS {host}",
                    apply_rules=False,
                ):
                    changed += 1
            changed += state.reconcile_ddns_allow_entries(host, ruleset, current_sources)
        if changed and apply_rules:
            apply_state(settings, state, "sync-ddns")
        return changed
    finally:
        state.close()

def record_block_line(settings: Settings, line: str) -> bool:
    src = re.search(r"\bSRC=([0-9.]+)", line)
    dpt = re.search(r"\bDPT=([0-9]+)", line)
    proto = re.search(r"\bPROTO=([A-Za-z0-9]+)", line)
    if not (src and dpt):
        return False
    ip = src.group(1)
    lport = int(dpt.group(1))
    protocol = proto.group(1) if proto else "UNKNOWN"
    state = state_for(settings)
    try:
        if _blocked_ip_is_allowed_by_state(state, ip, lport):
            state.audit("allowed_source_blocked_by_stale_live_nft", source_ip=ip, proto=protocol, lport=lport)
            if _stale_live_repair_due(state):
                state.set_meta("apply_pending", "1")
                try:
                    apply_state(settings, state, "repair-stale-live-nft")
                    return True
                except Exception:
                    pass
            else:
                state.audit("stale_live_repair_throttled", source_ip=ip, proto=protocol, lport=lport)
                return True
        geo = GeoLookup(settings).lookup(ip)
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


def _stale_live_repair_due(state: State, interval: int = 30) -> bool:
    now = time.time()
    try:
        last = float(state.get_meta("last_stale_live_repair_at", "0") or 0)
    except ValueError:
        last = 0
    if now - last < interval:
        return False
    state.set_meta("last_stale_live_repair_at", str(int(now)))
    return True

def _blocked_ip_is_allowed_by_state(state: State, ip: str, lport: int) -> bool:
    rule = state.rule_by_lport(lport)
    if not rule:
        return False
    if rule.open_access:
        return True
    return any(contains_ip(source, ip) for source in state.effective_sources_for_rule(rule))


def status(settings: Settings) -> dict[str, object]:
    state = state_for(settings)
    try:
        return {
            "version": __version__,
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
            "version": __version__,
            "mode": state.mode(),
            "allow": len(state.active_allow_entries()),
            "rules": len(state.rules()),
            "rulesets": len(rulesets),
            "blocked": len(state.blocked(limit=1000)),
        }
    finally:
        state.close()
