from __future__ import annotations

import json
import shlex
import time
from typing import Any

from .config import Settings, load_settings
from .geo import GeoLookup
from .sshutil import ssh_command
from .state import State


def state_for(settings: Settings) -> State:
    if not settings.paths:
        raise RuntimeError("missing configured paths")
    return State(settings.paths.state_db)


def relay_args(settings: Settings, args: list[str]) -> tuple[bool, str]:
    result = relay_result(settings, args)
    text = (result.stdout or result.stderr).strip()
    return result.ok, text


def relay_result(settings: Settings, args: list[str]):
    return ssh_command(
        settings.relay_host,
        settings.relay_user,
        settings.relay_port,
        settings.relay_key,
        ["nft.sh"] + args,
        timeout=settings.ssh_timeout,
        auth_method=settings.relay_auth_method,
        password_file=settings.relay_password_file,
    )


def enqueue_relay(settings: Settings, action: str, payload: dict[str, Any]) -> None:
    state = state_for(settings)
    try:
        state.enqueue(action, payload)
    finally:
        state.close()


def push_ingest(settings: Settings, channel: str, ip: str, ruleset: str = "public", note: str = "") -> bool:
    args = ["ingest", channel, "--ip", ip, "--ruleset", ruleset]
    if note:
        args += ["--note", note]
    ok, _ = relay_args(settings, args)
    if not ok:
        enqueue_relay(settings, "ingest", {"channel": channel, "ip": ip, "ruleset": ruleset, "note": note})
    return ok


def push_secret_hit(settings: Settings, url_id: int) -> bool:
    ok, _ = relay_args(settings, ["secret-url", "hit", str(url_id)])
    if not ok:
        enqueue_relay(settings, "secret_hit", {"id": url_id})
    return ok


def sync_from_relay(settings: Settings) -> tuple[bool, str]:
    ok, out = relay_args(settings, ["export", "--include-secrets"])
    if not ok:
        ok, out = relay_args(settings, ["secret-url", "list", "--all", "--include-secrets"])
        if not ok:
            return False, out
        try:
            urls = json.loads(out)
        except json.JSONDecodeError:
            return False, "relay returned invalid secret-url JSON"
        payload = {"secret_urls": urls, "rulesets": []}
    else:
        try:
            payload = json.loads(out)
        except json.JSONDecodeError:
            return False, "relay returned invalid export JSON"
    try:
        urls = payload.get("secret_urls", [])
        rulesets = payload.get("rulesets", [])
    except AttributeError:
        return False, "relay returned invalid sync payload"
    state = state_for(settings)
    try:
        for row in rulesets:
            state.update_ruleset(row["name"], row.get("channels", []), row.get("prefixes", {}), row.get("note", ""))
        state.replace_secret_urls(urls)
    finally:
        state.close()
    return True, f"synced secret URLs: {len(urls)}"


def drain_queue(settings: Settings) -> int:
    state = state_for(settings)
    sent = 0
    try:
        for row in state.due_queue():
            payload = json.loads(row["payload"])
            ok = False
            if row["action"] == "ingest":
                args = ["ingest", payload["channel"], "--ip", payload["ip"], "--ruleset", payload.get("ruleset", "public")]
                if payload.get("note"):
                    args += ["--note", payload["note"]]
                ok, _ = relay_args(settings, args)
            elif row["action"] == "secret_hit":
                ok, _ = relay_args(settings, ["secret-url", "hit", str(payload["id"])])
            if ok:
                state.delete_queue(row["id"])
                sent += 1
            else:
                state.retry_queue(row["id"])
    finally:
        state.close()
    return sent


def queue_worker() -> None:
    settings = load_settings()
    next_sync = 0
    while True:
        try:
            drain_queue(settings)
            now = time.time()
            if now >= next_sync:
                sync_from_relay(settings)
                next_sync = now + 60
        except Exception:
            pass
        time.sleep(10)


def online_geo_command(ip: str) -> str:
    settings = load_settings()
    geo = GeoLookup(settings).lookup_online(ip)
    return json.dumps({"ip": ip, "geo": geo.geo, "isp": geo.isp, "source": geo.source}, ensure_ascii=False)


def shell_join(args: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in args)
