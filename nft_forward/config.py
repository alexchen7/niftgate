from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constants import DEFAULT_TTL_DAYS, RESERVED_PORTS


def project_dir() -> Path:
    return Path(os.environ.get("NFT_FORWARD_PROJECT_DIR", Path.cwd())).resolve()


@dataclass
class Paths:
    config_file: Path
    state_db: Path
    nft_conf: Path
    main_nft_conf: Path
    audit_log: Path
    blocked_log: Path
    ip_cache: Path


@dataclass
class Settings:
    role: str = "relay"
    mode: str = "regular"
    dynamic_ttl_days: int = DEFAULT_TTL_DAYS
    reserved_ports: set[int] = field(default_factory=lambda: set(RESERVED_PORTS))
    paths: Paths | None = None
    relay_host: str = ""
    relay_user: str = "root"
    relay_port: int = 22
    relay_key: str = ""
    relay_auth_method: str = "key"
    relay_password_file: str = ""
    exit_host: str = ""
    exit_user: str = "root"
    exit_port: int = 22
    exit_key: str = ""
    exit_auth_method: str = "key"
    exit_password_file: str = ""
    ssh_timeout: int = 8
    telegram_token: str = ""
    telegram_admin_ids: list[int] = field(default_factory=list)
    telegram_timeout: int = 20
    phone_bind: str = "127.0.0.1"
    phone_port: int = 18088
    phone_public_port: int = 18443
    phone_public_host: str = ""
    phone_public_scheme: str = "https"
    phone_secret_path: str = ""
    geo_timeout: int = 5
    geo_fallback_url: str = "https://ipwho.is/{ip}"
    ddns_timeout: int = 5


def default_paths(base: Path | None = None) -> Paths:
    base = base or project_dir()
    return Paths(
        config_file=Path("/etc/nft-forward/config.json"),
        state_db=Path("/var/lib/nft-forward/state.db"),
        nft_conf=Path("/etc/nftables.d/port-forward.conf"),
        main_nft_conf=Path("/etc/nftables.conf"),
        audit_log=Path("/var/log/nft-forward/audit.jsonl"),
        blocked_log=Path("/var/log/nft-forward/blocked.jsonl"),
        ip_cache=base / "cache" / "iplist",
    )


def _path(data: dict[str, Any], key: str, default: Path) -> Path:
    return Path(data.get(key, str(default)))


def load_settings(config_path: str | Path | None = None) -> Settings:
    base = project_dir()
    paths = default_paths(base)
    cfg_path = Path(config_path or os.environ.get("NFT_FORWARD_CONFIG", paths.config_file))
    data: dict[str, Any] = {}
    if cfg_path.exists():
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    path_data = data.get("paths", {})
    paths = Paths(
        config_file=cfg_path,
        state_db=_path(path_data, "state_db", paths.state_db),
        nft_conf=_path(path_data, "nft_conf", paths.nft_conf),
        main_nft_conf=_path(path_data, "main_nft_conf", paths.main_nft_conf),
        audit_log=_path(path_data, "audit_log", paths.audit_log),
        blocked_log=_path(path_data, "blocked_log", paths.blocked_log),
        ip_cache=_path(path_data, "ip_cache", paths.ip_cache),
    )
    ssh = data.get("ssh", {})
    telegram = data.get("telegram", {})
    phone = data.get("phone", {})
    geo = data.get("geo", {})
    return Settings(
        role=data.get("role", "relay"),
        mode=data.get("mode", "regular"),
        dynamic_ttl_days=int(data.get("dynamic_ttl_days", DEFAULT_TTL_DAYS)),
        reserved_ports=set(int(p) for p in data.get("reserved_ports", sorted(RESERVED_PORTS))),
        paths=paths,
        relay_host=ssh.get("relay_host", ""),
        relay_user=ssh.get("relay_user", "root"),
        relay_port=int(ssh.get("relay_port", 22)),
        relay_key=ssh.get("relay_key", ""),
        relay_auth_method=ssh.get("relay_auth_method", "key"),
        relay_password_file=ssh.get("relay_password_file", ""),
        exit_host=ssh.get("exit_host", ""),
        exit_user=ssh.get("exit_user", "root"),
        exit_port=int(ssh.get("exit_port", 22)),
        exit_key=ssh.get("exit_key", ""),
        exit_auth_method=ssh.get("exit_auth_method", "key"),
        exit_password_file=ssh.get("exit_password_file", ""),
        ssh_timeout=int(ssh.get("timeout", 8)),
        telegram_token=telegram.get("token", ""),
        telegram_admin_ids=[int(x) for x in telegram.get("admin_ids", [])],
        telegram_timeout=int(telegram.get("timeout", 20)),
        phone_bind=phone.get("bind", "127.0.0.1"),
        phone_port=int(phone.get("port", 18088)),
        phone_public_port=int(phone.get("public_port", 18443)),
        phone_public_host=phone.get("public_host", ""),
        phone_public_scheme=phone.get("public_scheme", "https"),
        phone_secret_path=phone.get("secret_path", ""),
        geo_timeout=int(geo.get("timeout", 5)),
        geo_fallback_url=geo.get("fallback_url", "https://ipwho.is/{ip}"),
        ddns_timeout=int(data.get("ddns_timeout", 5)),
    )


def write_example_config(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    example = {
        "role": "relay",
        "mode": "regular",
        "dynamic_ttl_days": DEFAULT_TTL_DAYS,
        "reserved_ports": sorted(RESERVED_PORTS),
        "paths": {
            "state_db": "/var/lib/nft-forward/state.db",
            "nft_conf": "/etc/nftables.d/port-forward.conf",
            "main_nft_conf": "/etc/nftables.conf",
            "audit_log": "/var/log/nft-forward/audit.jsonl",
            "blocked_log": "/var/log/nft-forward/blocked.jsonl",
            "ip_cache": str(project_dir() / "cache" / "iplist"),
        },
        "ssh": {
            "relay_host": "relay.example.com",
            "relay_user": "root",
            "relay_port": 22,
            "relay_key": "/etc/nft-forward-exit/ssh/relay_ed25519",
            "relay_auth_method": "key",
            "relay_password_file": "",
            "exit_host": "exit.example.com",
            "exit_user": "root",
            "exit_port": 22,
            "exit_key": "/etc/nft-forward/ssh/exit_ed25519",
            "exit_auth_method": "key",
            "exit_password_file": "",
            "timeout": 8,
        },
        "telegram": {"token": "", "admin_ids": [], "timeout": 20},
        "phone": {
            "bind": "127.0.0.1",
            "port": 18088,
            "public_port": 18443,
            "public_host": "",
            "public_scheme": "https",
            "secret_path": "replace-with-long-random-path",
        },
        "geo": {"timeout": 5, "fallback_url": "https://ipwho.is/{ip}"},
        "ddns": [],
    }
    path.write_text(json.dumps(example, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
