from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .blocklog import run as run_blocklog
from .config import load_settings, write_example_config
from .constants import DEFAULT_RULESET, RESERVED_PORTS
from .exitnode import online_geo_command, queue_worker, sync_from_relay
from .geo import GeoLookup
from .iputil import normalize_sources
from .legacy import import_legacy_conf
from .nft import render_nft, write_and_apply
from .phone_server import run as run_phone
from .relay import bot_status, ingest_source, state_for, status, sync_ddns
from .sshlog import run as run_sshlog
from .sshutil import ssh_command
from .state import State
from .telegram_bot import run as run_telegram

EXIT_CONFIG_PATH = Path("/etc/nft-forward-exit/config.json")
EXIT_SERVICES = [
    "nft-forward-exit-phone.service",
    "nft-forward-exit-queue.service",
    "nft-forward-exit-telegram.service",
]


def print_json(data: object) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def read_config_json(settings) -> dict[str, Any]:
    cfg = settings.paths.config_file if settings.paths else None
    if cfg and cfg.exists():
        return json.loads(cfg.read_text(encoding="utf-8"))
    return {}


def write_config_json(settings, data: dict[str, Any]) -> None:
    cfg = settings.paths.config_file if settings.paths else None
    if not cfg:
        raise RuntimeError("missing config path")
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(cfg, 0o600)
    except OSError:
        pass


DDNS_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def clean_ddns_host(host: str) -> str:
    value = str(host or "").strip().strip(".").lower()
    if not value or "://" in value or "/" in value or not DDNS_HOST_RE.match(value):
        raise ValueError("DDNS host must be a hostname, not a URL")
    if any(part in {"", "-"} or part.startswith("-") or part.endswith("-") for part in value.split(".")):
        raise ValueError("DDNS host contains an invalid label")
    return value


def ddns_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in data.get("ddns", []):
        if isinstance(item, str):
            host = item
            ruleset = DEFAULT_RULESET
            enabled = True
        elif isinstance(item, dict):
            host = item.get("host", "")
            ruleset = item.get("ruleset") or DEFAULT_RULESET
            enabled = bool(item.get("enabled", True))
        else:
            continue
        try:
            clean_host = clean_ddns_host(host)
        except ValueError:
            continue
        rows.append(
            {
                "id": len(rows) + 1,
                "host": clean_host,
                "ruleset": str(ruleset or DEFAULT_RULESET),
                "enabled": enabled,
            }
        )
    return rows


def set_ddns_entries(data: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    data["ddns"] = [
        {"host": row["host"], "ruleset": row.get("ruleset") or DEFAULT_RULESET, "enabled": bool(row.get("enabled", True))}
        for row in rows
    ]


def load_exit_settings(args: argparse.Namespace):
    config = args.config or os.environ.get("NFT_FORWARD_CONFIG")
    if not config and EXIT_CONFIG_PATH.exists():
        config = str(EXIT_CONFIG_PATH)
    return load_settings(config)


def relay_pairing_summary(data: dict[str, Any]) -> dict[str, Any]:
    ssh = data.get("ssh", {})
    password_file = ssh.get("relay_password_file", "")
    return {
        "relay_host": ssh.get("relay_host", ""),
        "relay_user": ssh.get("relay_user", "root"),
        "relay_port": ssh.get("relay_port", 22),
        "relay_auth_method": ssh.get("relay_auth_method", "key"),
        "relay_key": ssh.get("relay_key", ""),
        "relay_password_file": password_file,
        "relay_password_file_exists": bool(password_file and Path(password_file).exists()),
        "ssh_timeout": ssh.get("timeout", 8),
    }


def restart_exit_services() -> str:
    try:
        proc = subprocess.run(
            ["systemctl", "try-restart", *EXIT_SERVICES],
            text=True,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"service restart skipped: {exc}"
    if proc.returncode == 0:
        return "active exit services restarted"
    detail = (proc.stderr or proc.stdout).strip()
    return f"service restart warning: {detail or proc.returncode}"


def secret_url_dict(url, include_secrets: bool = True, settings=None) -> dict[str, Any]:
    row = {
        "id": url.id,
        "label": url.label,
        "ruleset": url.ruleset,
        "active": url.active,
        "created_at": url.created_at,
        "last_used_at": url.last_used_at,
        "hit_count": url.hit_count,
    }
    if include_secrets:
        row["secret_path"] = url.secret_path
        if settings and settings.phone_public_host:
            port = f":{settings.phone_public_port}" if settings.phone_public_port not in {80, 443} else ""
            row["url"] = f"{settings.phone_public_scheme}://{settings.phone_public_host}{port}/{url.secret_path}"
    return row


def migrate_secret_path(settings, state: State) -> None:
    if settings.phone_secret_path:
        state.ensure_secret_url(settings.phone_secret_path, label="default")


def cmd_init_config(args: argparse.Namespace) -> int:
    write_example_config(Path(args.path))
    print(f"wrote {args.path}")
    return 0


def cmd_init_db(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    migrate_secret_path(settings, state)
    state.close()
    print("state initialized")
    return 0


def cmd_import_legacy(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        count = import_legacy_conf(Path(args.path or settings.paths.nft_conf), state)
        print(f"imported {count} forwarding rules")
    finally:
        state.close()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    print_json(status(load_settings(args.config)))
    return 0


def cmd_bot_status(args: argparse.Namespace) -> int:
    print_json(bot_status(load_settings(args.config)))
    return 0


def cmd_language(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    data = read_config_json(settings)
    ui = data.setdefault("ui", {})
    if args.language:
        lang = args.language.lower()
        if lang in {"cn", "zh-cn", "zh_hans", "zh-hans", "chinese"}:
            lang = "zh"
        if lang not in {"en", "zh"}:
            raise SystemExit("language must be en or zh")
        ui["language"] = lang
        write_config_json(settings, data)
    print(ui.get("language", settings.language))
    return 0


def cmd_mode(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        if args.mode:
            state.set_mode(args.mode)
        print(state.mode())
    finally:
        state.close()
    return 0


def cmd_ruleset(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        if args.ruleset_action == "list":
            for row in state.rulesets():
                print(f"{row['name']}\tchannels={row['channels']}\tprefixes={row['prefixes']}\t{row['note']}")
        elif args.ruleset_action == "set":
            channels = args.channels.split(",") if args.channels else ["manual", "ssh_login", "ddns", "web"]
            prefixes = {"manual": args.manual_prefix, "ssh_login": args.ssh_prefix, "ddns": args.ddns_prefix, "web": args.web_prefix}
            state.update_ruleset(args.name, channels, prefixes, args.note or "")
            print(f"ruleset updated: {args.name}")
    finally:
        state.close()
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        rows = []
        for rule in state.rules():
            rows.append(
                {
                    "lport": rule.lport,
                    "target": f"{rule.dest_ip}:{rule.dest_port}",
                    "note": rule.note,
                    "rulesets": rule.rulesets,
                    "include_public": rule.include_public,
                    "open_access": rule.open_access,
                    "effective_sources": state.effective_sources_for_rule(rule),
                }
            )
        print_json(rows)
    finally:
        state.close()
    return 0


def cmd_add_rule(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    if args.lport in settings.reserved_ports:
        raise SystemExit(f"refusing reserved relay port: {args.lport}")
    state = state_for(settings)
    try:
        state.add_rule(
            args.lport,
            args.dest_ip,
            args.dest_port,
            note=args.note or "",
            rulesets=args.ruleset or [],
            include_public=not args.no_public,
            open_access=args.open,
        )
        if args.apply:
            write_and_apply(settings, state, apply=True)
        print(f"rule upserted: {args.lport} -> {args.dest_ip}:{args.dest_port}")
    finally:
        state.close()
    return 0


def cmd_delete_rule(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        ok = state.delete_rule(args.lport)
        if args.apply:
            write_and_apply(settings, state, apply=True)
        print("deleted" if ok else "not found")
    finally:
        state.close()
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    geo_lookup = GeoLookup(settings)
    try:
        policy = int(args.prefix) if args.prefix else state.ruleset_prefix(args.ruleset, args.channel)
        count = 0
        for spec in normalize_sources(args.source, host_policy=policy):
            ip_for_geo = spec.text.split("/", 1)[0].split("-", 1)[0]
            geo = geo_lookup.lookup(ip_for_geo)
            if state.add_allow(args.ruleset, spec.text, args.channel, spec.prefix_len, settings.dynamic_ttl_days, args.note or "", geo.geo, geo.isp):
                count += 1
        if args.apply:
            write_and_apply(settings, state, apply=True)
        print(f"allowed entries upserted: {count}")
    finally:
        state.close()
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    ok = ingest_source(load_settings(args.config), args.channel, args.ip, args.ruleset, args.note or "", apply_rules=args.apply)
    print("accepted" if ok else "rejected")
    return 0 if ok else 2


def cmd_remove_allow(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        ok = state.remove_allow(int(args.id))
        if args.apply:
            write_and_apply(settings, state, apply=True)
        print("removed" if ok else "not found")
    finally:
        state.close()
    return 0


def cmd_allow_list(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        rows = [
            {
                "id": e.id,
                "ruleset": e.ruleset,
                "source": e.source,
                "channel": e.channel,
                "prefix_len": e.prefix_len,
                "geo": e.geo,
                "isp": e.isp,
                "created_at": e.created_at,
                "expires_at": e.expires_at,
                "note": e.note,
            }
            for e in state.all_allow_entries()
        ]
        print_json(rows)
    finally:
        state.close()
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        if args.print:
            print(render_nft(settings, state))
        else:
            print(write_and_apply(settings, state, apply=not args.no_apply))
    finally:
        state.close()
    return 0


def cmd_sync_ddns(args: argparse.Namespace) -> int:
    count = sync_ddns(load_settings(args.config), apply_rules=args.apply)
    print(f"ddns entries updated: {count}")
    return 0


def cmd_ddns(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    data = read_config_json(settings)
    rows = ddns_entries(data)
    if args.ddns_action == "list":
        print_json(rows)
        return 0

    if args.ddns_action == "add":
        host = clean_ddns_host(args.host)
        ruleset = args.ruleset or DEFAULT_RULESET
        for row in rows:
            if row["host"] == host and row["ruleset"] == ruleset:
                row["enabled"] = True
                set_ddns_entries(data, rows)
                write_config_json(settings, data)
                print_json(row)
                return 0
        row = {"id": len(rows) + 1, "host": host, "ruleset": ruleset, "enabled": True}
        rows.append(row)
        set_ddns_entries(data, rows)
        write_config_json(settings, data)
        print_json(row)
        return 0

    if args.ddns_action == "delete":
        ids: set[int] = set()
        hosts: set[str] = set()
        for token in args.items:
            if token.isdigit():
                ids.add(int(token))
            else:
                hosts.add(clean_ddns_host(token))
        removed_pairs: list[tuple[str, str]] = []
        kept: list[dict[str, Any]] = []
        for row in rows:
            selected = row["id"] in ids or row["host"] in hosts
            if selected:
                removed_pairs.append((row["host"], row["ruleset"]))
            else:
                kept.append({**row, "id": len(kept) + 1})
        set_ddns_entries(data, kept)
        write_config_json(settings, data)
        removed_allow = 0
        if removed_pairs and not args.keep_allowlist:
            state = state_for(settings)
            try:
                removed_allow = state.remove_ddns_allow_entries(removed_pairs)
                if removed_allow and args.apply:
                    write_and_apply(settings, state, apply=True)
            finally:
                state.close()
        print_json({"deleted": len(removed_pairs), "removed_allow_entries": removed_allow})
        return 0

    raise SystemExit("unknown ddns action")


def cmd_blocked(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        rows = [dict(row) for row in state.blocked(include_hidden=args.all, limit=args.limit)]
        print_json(rows)
    finally:
        state.close()
    return 0


def cmd_delete_block(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        print("deleted" if state.hide_block(int(args.id)) else "not found")
    finally:
        state.close()
    return 0


def cmd_promote_block(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        row = state.conn.execute("SELECT * FROM blocked_events WHERE id=?", (int(args.id),)).fetchone()
        if not row:
            print("not found")
            return 1
        source = row["source_ip"]
        spec = normalize_sources(source, host_policy=int(args.prefix))[0]
        geo = GeoLookup(settings).lookup(source)
        state.add_allow(args.ruleset, spec.text, "manual", spec.prefix_len, note=f"promoted blocked id {args.id}", geo=geo.geo, isp=geo.isp)
        state.hide_block(int(args.id))
        if args.apply:
            write_and_apply(settings, state, apply=True)
        print(f"promoted {source} as {spec.text}")
    finally:
        state.close()
    return 0


def cmd_record_block(args: argparse.Namespace) -> int:
    from .relay import record_block_line

    ok = record_block_line(load_settings(args.config), args.line)
    print("recorded" if ok else "ignored")
    return 0 if ok else 1


def cmd_secret_url(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    state = state_for(settings)
    try:
        migrate_secret_path(settings, state)
        if args.secret_url_action == "list":
            include = args.include_secrets or not args.hide_secrets
            rows = [secret_url_dict(url, include_secrets=include, settings=settings) for url in state.secret_urls(include_inactive=args.all)]
            print_json(rows)
        elif args.secret_url_action == "create":
            path = args.path or secrets.token_urlsafe(48)
            url = state.create_secret_url(path, ruleset=args.ruleset, label=args.label or "")
            print_json(secret_url_dict(url, include_secrets=True, settings=settings))
        elif args.secret_url_action == "delete":
            print(f"deleted: {state.delete_secret_urls([int(x) for x in args.ids])}")
        elif args.secret_url_action == "hit":
            print("recorded" if state.record_secret_url_hit(int(args.id)) else "not found")
        else:
            raise SystemExit("unknown secret-url action")
    finally:
        state.close()
    return 0


def export_payload(settings, include_secrets: bool) -> dict[str, Any]:
    state = state_for(settings)
    try:
        migrate_secret_path(settings, state)
        return {
            "version": 1,
            "mode": state.mode(),
            "rulesets": [
                {
                    "name": row["name"],
                    "channels": json.loads(row["channels"]),
                    "prefixes": json.loads(row["prefixes"]),
                    "note": row["note"],
                }
                for row in state.rulesets()
            ],
            "forward_rules": [
                {
                    "lport": rule.lport,
                    "dest_ip": rule.dest_ip,
                    "dest_port": rule.dest_port,
                    "note": rule.note,
                    "rulesets": rule.rulesets,
                    "include_public": rule.include_public,
                    "open_access": rule.open_access,
                }
                for rule in state.rules()
            ],
            "ddns": read_config_json(settings).get("ddns", []),
            "secret_urls": [
                secret_url_dict(url, include_secrets=include_secrets, settings=settings)
                for url in state.secret_urls(include_inactive=True)
            ],
        }
    finally:
        state.close()


def cmd_export(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    payload = export_payload(settings, include_secrets=args.include_secrets)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"exported: {args.output}")
    else:
        print(text, end="")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
    state = state_for(settings)
    try:
        if args.replace:
            state.conn.execute("DELETE FROM forward_rules")
            state.conn.execute("DELETE FROM rulesets WHERE name != ?", (DEFAULT_RULESET,))
            state.conn.execute("DELETE FROM secret_urls")
            state.conn.commit()
        for row in payload.get("rulesets", []):
            state.update_ruleset(row["name"], row.get("channels", []), row.get("prefixes", {}), row.get("note", ""))
        for row in payload.get("forward_rules", []):
            state.add_rule(
                int(row["lport"]),
                row["dest_ip"],
                int(row["dest_port"]),
                note=row.get("note", ""),
                rulesets=row.get("rulesets", []),
                include_public=bool(row.get("include_public", True)),
                open_access=bool(row.get("open_access", False)),
            )
        for row in payload.get("secret_urls", []):
            path = row.get("secret_path")
            if not path:
                continue
            state.upsert_secret_url_record(row)
        state.conn.commit()
    finally:
        state.close()
    if "ddns" in payload:
        data = read_config_json(settings)
        data["ddns"] = payload.get("ddns", [])
        write_config_json(settings, data)
    print("imported")
    return 0


def cmd_pair_exit(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    data = read_config_json(settings)
    ssh = data.setdefault("ssh", {})
    phone = data.setdefault("phone", {})
    if args.host:
        ssh["exit_host"] = args.host
    if args.user:
        ssh["exit_user"] = args.user
    if args.port:
        ssh["exit_port"] = args.port
    if args.key:
        ssh["exit_key"] = args.key
    if args.auth_method:
        ssh["exit_auth_method"] = args.auth_method
    if args.password_file:
        ssh["exit_password_file"] = args.password_file
    if args.public_host:
        phone["public_host"] = args.public_host
    if args.public_port:
        phone["public_port"] = args.public_port
    if args.public_scheme:
        phone["public_scheme"] = args.public_scheme
    write_config_json(settings, data)
    print("exit pairing updated")
    return 0


def cmd_pair_relay(args: argparse.Namespace) -> int:
    settings = load_exit_settings(args)
    data = read_config_json(settings)
    ssh = data.setdefault("ssh", {})

    changed = False
    if args.host:
        ssh["relay_host"] = args.host
        changed = True
    if args.user:
        ssh["relay_user"] = args.user
        changed = True
    if args.port:
        ssh["relay_port"] = args.port
        changed = True
    if args.timeout:
        ssh["timeout"] = args.timeout
        changed = True
    if args.key:
        ssh["relay_key"] = args.key
        if not args.auth_method:
            ssh["relay_auth_method"] = "key"
        changed = True
    if args.password_file:
        ssh["relay_password_file"] = args.password_file
        if not args.auth_method:
            ssh["relay_auth_method"] = "password"
        changed = True
    if args.ask_password:
        cfg = settings.paths.config_file if settings.paths else EXIT_CONFIG_PATH
        password_file = Path(args.password_file or ssh.get("relay_password_file") or cfg.parent / "ssh" / "relay_password")
        password = getpass.getpass("Relay SSH password: ")
        password_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(password_file.parent, 0o700)
        except OSError:
            pass
        password_file.write_text(password + "\n", encoding="utf-8")
        os.chmod(password_file, 0o600)
        ssh["relay_password_file"] = str(password_file)
        if not args.auth_method:
            ssh["relay_auth_method"] = "password"
        changed = True
    if args.clear_password:
        old_password_file = ssh.get("relay_password_file", "")
        if old_password_file:
            try:
                Path(old_password_file).unlink()
            except FileNotFoundError:
                pass
        ssh["relay_password_file"] = ""
        changed = True
    if args.auth_method:
        ssh["relay_auth_method"] = args.auth_method
        changed = True

    if changed:
        write_config_json(settings, data)
        print("relay pairing updated")

    if args.test:
        refreshed = load_exit_settings(args)
        result = ssh_command(
            refreshed.relay_host,
            refreshed.relay_user,
            refreshed.relay_port,
            refreshed.relay_key,
            ["true"],
            timeout=refreshed.ssh_timeout,
            auth_method=refreshed.relay_auth_method,
            password_file=refreshed.relay_password_file,
        )
        if result.ok:
            print(f"relay ssh ok: {result.latency_ms} ms")
        else:
            detail = (result.stderr or result.stdout or str(result.returncode)).strip()
            print(f"relay ssh failed: {detail}")

    if changed and not args.no_restart:
        print(restart_exit_services())

    print_json(relay_pairing_summary(data))
    return 0


def cmd_sync_from_relay(args: argparse.Namespace) -> int:
    ok, out = sync_from_relay(load_exit_settings(args))
    print(out)
    return 0 if ok else 1


def cmd_menu(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)

    def tr(en: str, zh: str) -> str:
        return zh if settings.language == "zh" else en

    while True:
        print(tr("\nNiftGate Menu", "\nNiftGate 菜单"))
        print(tr("1) Status", "1) 状态"))
        print(tr("2) Forwarding rules", "2) 转发规则"))
        print(tr("3) Secret URLs", "3) Secret URL"))
        print(tr("4) Attack mode", "4) 攻击模式"))
        print(tr("5) Export", "5) 导出"))
        print(tr("6) Exit", "6) 退出"))
        choice = input(tr("Choose [1-6]: ", "请选择 [1-6]: ")).strip()
        if choice == "1":
            cmd_status(args)
        elif choice == "2":
            cmd_list(args)
        elif choice == "3":
            state = state_for(settings)
            try:
                migrate_secret_path(settings, state)
                for url in state.secret_urls():
                    print(f"#{url.id} {url.label} ruleset={url.ruleset} hits={url.hit_count} /{url.secret_path}")
                sub = input(tr("Secret URL action: [c]reate, [d]elete, [enter] back: ", "Secret URL 操作：[c]创建，[d]删除，[回车]返回：")).strip().lower()
                if sub == "c":
                    ruleset = input(tr("Ruleset [public]: ", "规则集 [public]: ")).strip() or DEFAULT_RULESET
                    label = input(tr("Label [auto]: ", "标签 [自动]: ")).strip()
                    url = state.create_secret_url(secrets.token_urlsafe(48), ruleset=ruleset, label=label)
                    print_json(secret_url_dict(url, include_secrets=True, settings=settings))
                elif sub == "d":
                    ids = [int(x) for x in input(tr("IDs to delete, separated by spaces: ", "要删除的 ID，用空格分隔：")).split()]
                    print(tr("deleted: ", "已删除：") + str(state.delete_secret_urls(ids)))
            finally:
                state.close()
        elif choice == "4":
            mode = input(tr("Mode [regular/attack]: ", "模式 [regular/attack]: ")).strip()
            if mode in {"regular", "attack"}:
                args.mode = mode
                cmd_mode(args)
        elif choice == "5":
            print(json.dumps(export_payload(settings, include_secrets=False), ensure_ascii=False, indent=2))
        elif choice == "6" or choice == "":
            return 0
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nft.sh", description="Portable nftables forwarding whitelist toolkit")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-config")
    p.add_argument("--path", default="config/config.example.json")
    p.set_defaults(func=cmd_init_config)

    p = sub.add_parser("init-db")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("import-legacy")
    p.add_argument("path", nargs="?")
    p.set_defaults(func=cmd_import_legacy)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("bot-status", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_bot_status)

    p = sub.add_parser("language")
    p.add_argument("language", nargs="?", choices=["en", "zh", "cn", "zh-cn"])
    p.set_defaults(func=cmd_language)

    p = sub.add_parser("mode")
    p.add_argument("mode", nargs="?", choices=["regular", "attack"])
    p.set_defaults(func=cmd_mode)

    p = sub.add_parser("ruleset")
    rs = p.add_subparsers(dest="ruleset_action", required=True)
    q = rs.add_parser("list")
    q.set_defaults(func=cmd_ruleset)
    q = rs.add_parser("set")
    q.add_argument("name")
    q.add_argument("--channels", help="comma-separated channel list")
    q.add_argument("--manual-prefix", type=int, choices=[24, 32], default=32)
    q.add_argument("--ssh-prefix", type=int, choices=[24, 32], default=24)
    q.add_argument("--ddns-prefix", type=int, choices=[24, 32], default=24)
    q.add_argument("--web-prefix", type=int, choices=[24, 32], default=24)
    q.add_argument("--note")
    q.set_defaults(func=cmd_ruleset)

    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("add-rule")
    p.add_argument("lport", type=int)
    p.add_argument("dest_ip")
    p.add_argument("dest_port", type=int)
    p.add_argument("--note")
    p.add_argument("--ruleset", action="append")
    p.add_argument("--no-public", action="store_true")
    p.add_argument("--open", action="store_true", help="legacy open access; use carefully")
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_add_rule)

    p = sub.add_parser("delete-rule")
    p.add_argument("lport", type=int)
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_delete_rule)

    p = sub.add_parser("allow")
    p.add_argument("source")
    p.add_argument("--ruleset", default=DEFAULT_RULESET)
    p.add_argument("--channel", default="manual", choices=["manual", "ssh_login", "ddns", "web"])
    p.add_argument("--prefix", choices=["24", "32"])
    p.add_argument("--note")
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_allow)

    p = sub.add_parser("allow-list")
    p.set_defaults(func=cmd_allow_list)

    p = sub.add_parser("ingest")
    p.add_argument("channel", choices=["ssh_login", "ddns", "web", "manual"])
    p.add_argument("--ip", required=True)
    p.add_argument("--ruleset", default=DEFAULT_RULESET)
    p.add_argument("--note")
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("remove-allow")
    p.add_argument("id")
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_remove_allow)

    p = sub.add_parser("apply")
    p.add_argument("--print", action="store_true")
    p.add_argument("--no-apply", action="store_true")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("sync-ddns")
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_sync_ddns)

    p = sub.add_parser("ddns")
    ddns = p.add_subparsers(dest="ddns_action", required=True)
    q = ddns.add_parser("list")
    q.set_defaults(func=cmd_ddns)
    q = ddns.add_parser("add")
    q.add_argument("host")
    q.add_argument("--ruleset", default=DEFAULT_RULESET)
    q.set_defaults(func=cmd_ddns)
    q = ddns.add_parser("delete")
    q.add_argument("items", nargs="+", help="1-based DDNS ids or hostnames")
    q.add_argument("--keep-allowlist", action="store_true", help="do not remove whitelist entries created by these DDNS records")
    q.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    q.set_defaults(func=cmd_ddns)

    p = sub.add_parser("blocked")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_blocked)

    p = sub.add_parser("delete-block")
    p.add_argument("id")
    p.set_defaults(func=cmd_delete_block)

    p = sub.add_parser("promote-block")
    p.add_argument("id")
    p.add_argument("--prefix", choices=["24", "32"], default="24")
    p.add_argument("--ruleset", default=DEFAULT_RULESET)
    p.add_argument("--no-apply", dest="apply", action="store_false", default=True)
    p.set_defaults(func=cmd_promote_block)

    p = sub.add_parser("record-block")
    p.add_argument("line")
    p.set_defaults(func=cmd_record_block)

    p = sub.add_parser("secret-url")
    su = p.add_subparsers(dest="secret_url_action", required=True)
    q = su.add_parser("list")
    q.add_argument("--all", action="store_true")
    q.add_argument("--include-secrets", action="store_true")
    q.add_argument("--hide-secrets", action="store_true")
    q.set_defaults(func=cmd_secret_url)
    q = su.add_parser("create")
    q.add_argument("--ruleset", default=DEFAULT_RULESET)
    q.add_argument("--label")
    q.add_argument("--path", help=argparse.SUPPRESS)
    q.set_defaults(func=cmd_secret_url)
    q = su.add_parser("delete")
    q.add_argument("ids", nargs="+")
    q.set_defaults(func=cmd_secret_url)
    q = su.add_parser("hit")
    q.add_argument("id")
    q.set_defaults(func=cmd_secret_url)

    p = sub.add_parser("export")
    p.add_argument("--include-secrets", action="store_true")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("import")
    p.add_argument("file")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--merge", action="store_true", default=True)
    mode.add_argument("--replace", action="store_true")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("pair-exit")
    p.add_argument("--host")
    p.add_argument("--user")
    p.add_argument("--port", type=int)
    p.add_argument("--key")
    p.add_argument("--auth-method", choices=["key", "password"])
    p.add_argument("--password-file")
    p.add_argument("--public-host")
    p.add_argument("--public-port", type=int)
    p.add_argument("--public-scheme", choices=["http", "https"])
    p.set_defaults(func=cmd_pair_exit)

    p = sub.add_parser("pair-relay", help="update the relay SSH pairing from an exit node")
    p.add_argument("--host", help="relay intranet IP/host reachable from this exit node")
    p.add_argument("--user", help="relay SSH user")
    p.add_argument("--port", type=int, help="relay SSH port")
    p.add_argument("--auth-method", choices=["key", "password"], help="relay SSH auth method")
    p.add_argument("--key", help="relay SSH private key path")
    p.add_argument("--password-file", help="root-readable file containing the relay SSH password")
    p.add_argument("--ask-password", action="store_true", help="prompt and save relay SSH password to the configured password file")
    p.add_argument("--clear-password", action="store_true", help="remove the saved relay password file and clear it from config")
    p.add_argument("--timeout", type=int, help="relay SSH connection timeout in seconds")
    p.add_argument("--test", action="store_true", help="test SSH connectivity after updating")
    p.add_argument("--no-restart", action="store_true", help="do not try-restart active exit services after updating")
    p.set_defaults(func=cmd_pair_relay)

    p = sub.add_parser("sync-from-relay")
    p.set_defaults(func=cmd_sync_from_relay)

    p = sub.add_parser("menu")
    p.set_defaults(func=cmd_menu)

    p = sub.add_parser("run-blocklog")
    p.set_defaults(func=lambda _args: run_blocklog() or 0)
    p = sub.add_parser("run-sshlog")
    p.set_defaults(func=lambda _args: run_sshlog() or 0)
    p = sub.add_parser("run-telegram")
    p.set_defaults(func=lambda _args: run_telegram() or 0)
    p = sub.add_parser("run-phone")
    p.set_defaults(func=lambda _args: run_phone() or 0)
    p = sub.add_parser("run-exit-queue")
    p.set_defaults(func=lambda _args: queue_worker() or 0)
    p = sub.add_parser("exit-geo")
    p.add_argument("ip")
    p.set_defaults(func=lambda args: print(online_geo_command(args.ip)) or 0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.config:
        os.environ["NFT_FORWARD_CONFIG"] = args.config
    try:
        return int(args.func(args) or 0)
    except BrokenPipeError:
        return 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
