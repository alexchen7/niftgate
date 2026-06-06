from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .constants import CHANNELS, DEFAULT_RULESET, DEFAULT_TTL_DAYS
from .logging_util import append_jsonl


def utc_now() -> int:
    return int(time.time())


@dataclass
class ForwardRule:
    id: int
    lport: int
    dest_ip: str
    dest_port: int
    note: str
    rulesets: list[str]
    include_public: bool
    open_access: bool


@dataclass
class AllowEntry:
    id: int
    ruleset: str
    source: str
    channel: str
    prefix_len: int | None
    note: str
    geo: str
    isp: str
    created_at: int
    expires_at: int | None


@dataclass
class SecretURL:
    id: int
    label: str
    secret_path: str
    ruleset: str
    active: bool
    created_at: int
    last_used_at: int | None
    hit_count: int


class State:
    def __init__(self, db_path: Path, audit_log: Path | None = None):
        self.db_path = db_path
        self.audit_log = audit_log
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rulesets (
              name TEXT PRIMARY KEY,
              channels TEXT NOT NULL,
              prefixes TEXT NOT NULL,
              note TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS forward_rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              lport INTEGER NOT NULL UNIQUE,
              dest_ip TEXT NOT NULL,
              dest_port INTEGER NOT NULL,
              note TEXT NOT NULL DEFAULT '',
              rulesets TEXT NOT NULL DEFAULT '[]',
              include_public INTEGER NOT NULL DEFAULT 1,
              open_access INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS allow_entries (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ruleset TEXT NOT NULL,
              source TEXT NOT NULL,
              channel TEXT NOT NULL,
              prefix_len INTEGER,
              note TEXT NOT NULL DEFAULT '',
              geo TEXT NOT NULL DEFAULT 'unknown',
              isp TEXT NOT NULL DEFAULT 'unknown',
              created_at INTEGER NOT NULL,
              expires_at INTEGER,
              UNIQUE(ruleset, source, channel)
            );
            CREATE TABLE IF NOT EXISTS blocked_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source_ip TEXT NOT NULL,
              proto TEXT NOT NULL,
              lport INTEGER NOT NULL,
              geo TEXT NOT NULL DEFAULT 'unknown',
              isp TEXT NOT NULL DEFAULT 'unknown',
              first_seen INTEGER NOT NULL,
              last_seen INTEGER NOT NULL,
              count INTEGER NOT NULL DEFAULT 1,
              hidden INTEGER NOT NULL DEFAULT 0,
              UNIQUE(source_ip, proto, lport)
            );
            CREATE TABLE IF NOT EXISTS exit_queue (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              action TEXT NOT NULL,
              payload TEXT NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,
              next_attempt_at INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secret_urls (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              label TEXT NOT NULL DEFAULT '',
              secret_path TEXT NOT NULL UNIQUE,
              ruleset TEXT NOT NULL DEFAULT 'public',
              active INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL,
              last_used_at INTEGER,
              hit_count INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self.conn.commit()
        self.ensure_ruleset(DEFAULT_RULESET)

    def close(self) -> None:
        self.conn.close()

    def audit(self, event: str, **fields: Any) -> None:
        if self.audit_log:
            append_jsonl(self.audit_log, {"event": event, **fields})

    def get_meta(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def mode(self) -> str:
        return self.get_meta("mode", "regular")

    def set_mode(self, mode: str) -> None:
        if mode not in {"regular", "attack"}:
            raise ValueError("mode must be regular or attack")
        self.set_meta("mode", mode)
        self.audit("mode_changed", mode=mode)

    def ensure_ruleset(
        self,
        name: str,
        channels: Iterable[str] | None = None,
        prefixes: dict[str, int] | None = None,
        note: str = "",
    ) -> None:
        channels = set(channels or CHANNELS)
        unknown = channels - CHANNELS
        if unknown:
            raise ValueError(f"unknown channels: {', '.join(sorted(unknown))}")
        prefixes = prefixes or {"manual": 32, "ssh_login": 24, "ddns": 24, "web": 24}
        self.conn.execute(
            """
            INSERT INTO rulesets(name, channels, prefixes, note)
            VALUES(?,?,?,?)
            ON CONFLICT(name) DO NOTHING
            """,
            (name, json.dumps(sorted(channels)), json.dumps(prefixes, sort_keys=True), note),
        )
        self.conn.commit()

    def update_ruleset(
        self, name: str, channels: Iterable[str], prefixes: dict[str, int], note: str = ""
    ) -> None:
        channels = set(channels)
        unknown = channels - CHANNELS
        if unknown:
            raise ValueError(f"unknown channels: {', '.join(sorted(unknown))}")
        for channel, prefix in prefixes.items():
            if channel not in CHANNELS or prefix not in {24, 32}:
                raise ValueError("prefix policy must be /24 or /32 per known channel")
        self.conn.execute(
            """
            INSERT INTO rulesets(name, channels, prefixes, note)
            VALUES(?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET channels=excluded.channels, prefixes=excluded.prefixes, note=excluded.note
            """,
            (name, json.dumps(sorted(channels)), json.dumps(prefixes, sort_keys=True), note),
        )
        self.conn.commit()
        self.audit("ruleset_updated", name=name, channels=sorted(channels), prefixes=prefixes)

    def delete_ruleset(self, name: str) -> dict[str, Any]:
        if name == DEFAULT_RULESET:
            raise ValueError("public ruleset cannot be deleted")
        row = self.conn.execute("SELECT name FROM rulesets WHERE name=?", (name,)).fetchone()
        if not row:
            return {
                "name": name,
                "deleted": False,
                "removed_allow_entries": 0,
                "detached_forward_rules": 0,
                "disabled_secret_urls": 0,
            }

        allow_cur = self.conn.execute("DELETE FROM allow_entries WHERE ruleset=?", (name,))
        detached = 0
        for rule in self.conn.execute("SELECT id,rulesets FROM forward_rules").fetchall():
            refs = json.loads(rule["rulesets"])
            if name not in refs:
                continue
            refs = [ref for ref in refs if ref != name]
            self.conn.execute("UPDATE forward_rules SET rulesets=? WHERE id=?", (json.dumps(refs), rule["id"]))
            detached += 1
        url_cur = self.conn.execute("UPDATE secret_urls SET active=0 WHERE ruleset=? AND active=1", (name,))
        self.conn.execute("DELETE FROM rulesets WHERE name=?", (name,))
        self.conn.commit()
        summary = {
            "name": name,
            "deleted": True,
            "removed_allow_entries": allow_cur.rowcount,
            "detached_forward_rules": detached,
            "disabled_secret_urls": url_cur.rowcount,
        }
        self.audit("ruleset_deleted", **summary)
        return summary

    def ruleset(self, name: str) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM rulesets WHERE name=?", (name,)).fetchone()
        if not row:
            raise ValueError(f"ruleset not found: {name}")
        return row

    def rulesets(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM rulesets ORDER BY name"))

    def ruleset_accepts(self, name: str, channel: str) -> bool:
        row = self.ruleset(name)
        return channel in set(json.loads(row["channels"]))

    def ruleset_prefix(self, name: str, channel: str) -> int:
        row = self.ruleset(name)
        return int(json.loads(row["prefixes"]).get(channel, 32))

    def add_rule(
        self,
        lport: int,
        dest_ip: str,
        dest_port: int,
        note: str = "",
        rulesets: list[str] | None = None,
        include_public: bool = True,
        open_access: bool = False,
    ) -> None:
        refs = sorted(set(rulesets or []))
        for ruleset in refs:
            self.ensure_ruleset(ruleset)
        self.conn.execute(
            """
            INSERT INTO forward_rules(lport,dest_ip,dest_port,note,rulesets,include_public,open_access)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(lport) DO UPDATE SET
              dest_ip=excluded.dest_ip,
              dest_port=excluded.dest_port,
              note=excluded.note,
              rulesets=excluded.rulesets,
              include_public=excluded.include_public,
              open_access=excluded.open_access
            """,
            (lport, dest_ip, dest_port, note, json.dumps(refs), int(include_public), int(open_access)),
        )
        self.conn.commit()
        self.audit("forward_rule_upserted", lport=lport, dest=f"{dest_ip}:{dest_port}", rulesets=refs, open_access=open_access)

    def delete_rule(self, lport: int) -> bool:
        cur = self.conn.execute("DELETE FROM forward_rules WHERE lport=?", (lport,))
        self.conn.commit()
        deleted = cur.rowcount > 0
        if deleted:
            self.audit("forward_rule_deleted", lport=lport)
        return deleted

    def rule_by_lport(self, lport: int) -> ForwardRule | None:
        row = self.conn.execute("SELECT * FROM forward_rules WHERE lport=?", (lport,)).fetchone()
        return self._rule_row(row) if row else None

    def rules(self) -> list[ForwardRule]:
        rows = self.conn.execute("SELECT * FROM forward_rules ORDER BY lport").fetchall()
        return [self._rule_row(row) for row in rows]

    def _rule_row(self, row: sqlite3.Row) -> ForwardRule:
        return ForwardRule(
            id=row["id"],
            lport=row["lport"],
            dest_ip=row["dest_ip"],
            dest_port=row["dest_port"],
            note=row["note"],
            rulesets=json.loads(row["rulesets"]),
            include_public=bool(row["include_public"]),
            open_access=bool(row["open_access"]),
        )

    def add_allow(
        self,
        ruleset: str,
        source: str,
        channel: str,
        prefix_len: int | None,
        ttl_days: int = DEFAULT_TTL_DAYS,
        note: str = "",
        geo: str = "unknown",
        isp: str = "unknown",
        manual: bool | None = None,
    ) -> bool:
        self.ensure_ruleset(ruleset)
        if not self.ruleset_accepts(ruleset, channel):
            return False
        if self.mode() == "attack" and channel in {"ssh_login", "ddns", "web"}:
            self.audit("allow_rejected_attack_mode", ruleset=ruleset, source=source, channel=channel)
            return False
        created = utc_now()
        is_manual = channel == "manual" if manual is None else manual
        expires = None if is_manual else created + ttl_days * 86400
        self.conn.execute(
            """
            INSERT INTO allow_entries(ruleset,source,channel,prefix_len,note,geo,isp,created_at,expires_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ruleset,source,channel) DO UPDATE SET
              note=excluded.note,
              geo=excluded.geo,
              isp=excluded.isp,
              expires_at=excluded.expires_at
            """,
            (ruleset, source, channel, prefix_len, note, geo, isp, created, expires),
        )
        self.conn.commit()
        self.audit("allow_upserted", ruleset=ruleset, source=source, channel=channel, prefix_len=prefix_len, geo=geo, isp=isp, expires_at=expires)
        return True

    def remove_allow(self, entry_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM allow_entries WHERE id=?", (entry_id,))
        self.conn.commit()
        deleted = cur.rowcount > 0
        if deleted:
            self.audit("allow_removed", id=entry_id)
        return deleted

    def remove_allow_sources(self, ruleset: str, sources: list[str], channel: str | None = None) -> int:
        if not sources:
            return 0
        removed = 0
        for source in sources:
            if channel:
                cur = self.conn.execute(
                    "DELETE FROM allow_entries WHERE ruleset=? AND source=? AND channel=?",
                    (ruleset, source, channel),
                )
            else:
                cur = self.conn.execute(
                    "DELETE FROM allow_entries WHERE ruleset=? AND source=?",
                    (ruleset, source),
                )
            removed += cur.rowcount
        self.conn.commit()
        if removed:
            self.audit("allow_sources_removed", ruleset=ruleset, sources=sources, channel=channel, count=removed)
        return removed

    def remove_ddns_allow_entries(self, pairs: list[tuple[str, str]]) -> int:
        removed = 0
        for host, ruleset in pairs:
            note = f"DDNS {host}"
            cur = self.conn.execute(
                "DELETE FROM allow_entries WHERE channel='ddns' AND note=? AND ruleset=?",
                (note, ruleset),
            )
            removed += cur.rowcount
        self.conn.commit()
        if removed:
            self.audit("ddns_allow_removed", count=removed, pairs=pairs)
        return removed

    def active_allow_entries(self) -> list[AllowEntry]:
        now = utc_now()
        rows = self.conn.execute(
            "SELECT * FROM allow_entries WHERE expires_at IS NULL OR expires_at > ? ORDER BY ruleset, source",
            (now,),
        ).fetchall()
        return [self._allow_row(row) for row in rows]

    def all_allow_entries(self) -> list[AllowEntry]:
        return [self._allow_row(row) for row in self.conn.execute("SELECT * FROM allow_entries ORDER BY ruleset, source")]

    def _allow_row(self, row: sqlite3.Row) -> AllowEntry:
        return AllowEntry(
            id=row["id"],
            ruleset=row["ruleset"],
            source=row["source"],
            channel=row["channel"],
            prefix_len=row["prefix_len"],
            note=row["note"],
            geo=row["geo"],
            isp=row["isp"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def effective_sources_for_rule(self, rule: ForwardRule) -> list[str]:
        if rule.open_access:
            return ["0.0.0.0/0"]
        names = set(rule.rulesets)
        if rule.include_public:
            names.add(DEFAULT_RULESET)
        active = self.active_allow_entries()
        return sorted({entry.source for entry in active if entry.ruleset in names})

    def record_block(self, source_ip: str, proto: str, lport: int, geo: str = "unknown", isp: str = "unknown") -> None:
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO blocked_events(source_ip,proto,lport,geo,isp,first_seen,last_seen,count,hidden)
            VALUES(?,?,?,?,?,?,?,1,0)
            ON CONFLICT(source_ip,proto,lport) DO UPDATE SET
              last_seen=excluded.last_seen,
              count=count+1,
              geo=excluded.geo,
              isp=excluded.isp
            """,
            (source_ip, proto.upper(), lport, geo, isp, now, now),
        )
        self.conn.commit()

    def blocked(self, include_hidden: bool = False, limit: int = 50) -> list[sqlite3.Row]:
        sql = "SELECT * FROM blocked_events"
        if not include_hidden:
            sql += " WHERE hidden=0"
        sql += " ORDER BY last_seen DESC LIMIT ?"
        return list(self.conn.execute(sql, (limit,)))

    def hide_block(self, block_id: int) -> bool:
        cur = self.conn.execute("UPDATE blocked_events SET hidden=1 WHERE id=?", (block_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def enqueue(self, action: str, payload: dict[str, Any]) -> None:
        now = utc_now()
        self.conn.execute(
            "INSERT INTO exit_queue(action,payload,created_at,next_attempt_at) VALUES(?,?,?,?)",
            (action, json.dumps(payload, ensure_ascii=False), now, now),
        )
        self.conn.commit()

    def due_queue(self, limit: int = 20) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM exit_queue WHERE next_attempt_at <= ? ORDER BY id LIMIT ?",
                (utc_now(), limit),
            )
        )

    def delete_queue(self, qid: int) -> None:
        self.conn.execute("DELETE FROM exit_queue WHERE id=?", (qid,))
        self.conn.commit()

    def retry_queue(self, qid: int) -> None:
        row = self.conn.execute("SELECT attempts FROM exit_queue WHERE id=?", (qid,)).fetchone()
        attempts = int(row["attempts"]) if row else 0
        delay = min(3600, 2 ** min(attempts + 1, 10))
        self.conn.execute(
            "UPDATE exit_queue SET attempts=attempts+1, next_attempt_at=? WHERE id=?",
            (utc_now() + delay, qid),
        )
        self.conn.commit()

    def ensure_secret_url(self, secret_path: str, ruleset: str = DEFAULT_RULESET, label: str = "default") -> SecretURL | None:
        path = secret_path.strip("/")
        if not path:
            return None
        self.ensure_ruleset(ruleset)
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO secret_urls(label, secret_path, ruleset, active, created_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(secret_path) DO UPDATE SET
              label=CASE WHEN secret_urls.label='' THEN excluded.label ELSE secret_urls.label END,
              ruleset=excluded.ruleset,
              active=1
            """,
            (label, path, ruleset, 1, now),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM secret_urls WHERE secret_path=?", (path,)).fetchone()
        return self._secret_url_row(row) if row else None

    def create_secret_url(self, secret_path: str, ruleset: str = DEFAULT_RULESET, label: str = "") -> SecretURL:
        path = secret_path.strip("/")
        if not path:
            raise ValueError("secret_path is required")
        self.ensure_ruleset(ruleset)
        now = utc_now()
        cur = self.conn.execute(
            """
            INSERT INTO secret_urls(label, secret_path, ruleset, active, created_at)
            VALUES(?,?,?,?,?)
            """,
            (label or f"url-{now}", path, ruleset, 1, now),
        )
        self.conn.commit()
        self.audit("secret_url_created", id=cur.lastrowid, label=label, ruleset=ruleset)
        row = self.conn.execute("SELECT * FROM secret_urls WHERE id=?", (cur.lastrowid,)).fetchone()
        return self._secret_url_row(row)

    def secret_urls(self, include_inactive: bool = False) -> list[SecretURL]:
        sql = "SELECT * FROM secret_urls"
        if not include_inactive:
            sql += " WHERE active=1"
        sql += " ORDER BY active DESC, created_at DESC, id DESC"
        return [self._secret_url_row(row) for row in self.conn.execute(sql)]

    def secret_url_by_path(self, secret_path: str) -> SecretURL | None:
        row = self.conn.execute(
            "SELECT * FROM secret_urls WHERE secret_path=? AND active=1",
            (secret_path.strip("/"),),
        ).fetchone()
        return self._secret_url_row(row) if row else None

    def delete_secret_urls(self, ids: list[int]) -> int:
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        cur = self.conn.execute(f"UPDATE secret_urls SET active=0 WHERE id IN ({placeholders})", ids)
        self.conn.commit()
        if cur.rowcount:
            self.audit("secret_url_deleted", ids=ids)
        return cur.rowcount

    def record_secret_url_hit(self, url_id: int) -> bool:
        now = utc_now()
        cur = self.conn.execute(
            "UPDATE secret_urls SET last_used_at=?, hit_count=hit_count+1 WHERE id=?",
            (now, url_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def replace_secret_urls(self, urls: list[dict[str, Any]]) -> None:
        self.conn.execute("DELETE FROM secret_urls")
        for item in urls:
            self.upsert_secret_url_record(item)
        self.conn.commit()

    def upsert_secret_url_record(self, item: dict[str, Any]) -> None:
        self.ensure_ruleset(item.get("ruleset") or DEFAULT_RULESET)
        path = str(item["secret_path"]).strip("/")
        row_id = item.get("id")
        columns = "label,secret_path,ruleset,active,created_at,last_used_at,hit_count"
        values = (
            item.get("label") or "",
            path,
            item.get("ruleset") or DEFAULT_RULESET,
            int(bool(item.get("active", True))),
            int(item.get("created_at") or utc_now()),
            item.get("last_used_at"),
            int(item.get("hit_count") or 0),
        )
        if row_id is not None:
            self.conn.execute(
                f"""
                INSERT INTO secret_urls(id,{columns}) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(secret_path) DO UPDATE SET
                  label=excluded.label,
                  ruleset=excluded.ruleset,
                  active=excluded.active,
                  created_at=excluded.created_at,
                  last_used_at=excluded.last_used_at,
                  hit_count=excluded.hit_count
                """,
                (int(row_id), *values),
            )
        else:
            self.conn.execute(
                f"""
                INSERT INTO secret_urls({columns}) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(secret_path) DO UPDATE SET
                  label=excluded.label,
                  ruleset=excluded.ruleset,
                  active=excluded.active,
                  created_at=excluded.created_at,
                  last_used_at=excluded.last_used_at,
                  hit_count=excluded.hit_count
                """,
                values,
            )

    def _secret_url_row(self, row: sqlite3.Row) -> SecretURL:
        return SecretURL(
            id=row["id"],
            label=row["label"],
            secret_path=row["secret_path"],
            ruleset=row["ruleset"],
            active=bool(row["active"]),
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            hit_count=row["hit_count"],
        )
