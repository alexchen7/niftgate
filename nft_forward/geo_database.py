"""Indexed, atomically replaceable ip2region data using only the standard library."""
from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
import urllib.request

from . import __version__

REPOSITORY = "https://github.com/lionsoul2014/ip2region"
RAW_BASE = "https://raw.githubusercontent.com/lionsoul2014/ip2region"
COMMITS_URL = "https://api.github.com/repos/lionsoul2014/ip2region/commits?path=data/ipv4_source.txt&per_page=1"
APPLICATION_ID = 0x4E47454F
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_DATABASE_BYTES = 256 * 1024 * 1024
MIN_ROWS = 1000
MAX_ROWS = 2_000_000


def database_path(settings) -> Path:
    if not settings.paths:
        raise ValueError("missing configured paths")
    return settings.paths.ip_cache / "geoip.db"


def connect_readonly(path: Path):
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True, timeout=2)
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA cache_size=-2048")
    return conn


def database_info(settings) -> dict:
    path = database_path(settings)
    if not path.is_file():
        return {"provider": "metowolf/iplist", "installed": False}
    try:
        conn = connect_readonly(path)
        try:
            info = json.loads(conn.execute("SELECT value FROM metadata WHERE key='info'").fetchone()[0])
            if not isinstance(info, dict):
                raise ValueError("invalid database metadata")
            return {**{key: value for key, value in info.items() if key != "license"}, "installed": True}
        finally:
            conn.close()
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return {"provider": "metowolf/iplist", "installed": False, "error": "community database unavailable"}


def lookup_database(settings, ip: str) -> tuple[str, str] | None:
    path = database_path(settings)
    if not path.is_file():
        return None
    try:
        value = int(ipaddress.IPv4Address(ip))
        conn = connect_readonly(path)
        try:
            row = conn.execute("SELECT end,geo,isp FROM ranges WHERE start<=? ORDER BY start DESC LIMIT 1", (value,)).fetchone()
        finally:
            conn.close()
        return (row[1], row[2]) if row and value <= row[0] else None
    except (OSError, ValueError, sqlite3.Error):
        return None


def copy_bounded(source, target, limit: int, deadline: float | None = None) -> str:
    total = 0
    digest = hashlib.sha256()
    while True:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("database transfer exceeded its time limit")
        chunk = source.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError("database exceeds the configured size limit")
        digest.update(chunk)
        target.write(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path, limit: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": f"NiftGate/{__version__}"})
    with urllib.request.urlopen(request, timeout=20) as response, destination.open("wb") as output:
        return copy_bounded(response, output, limit, time.monotonic() + 180)


def fetch_source(directory: Path) -> tuple[Path, dict]:
    commit_file = directory / "commit.json"
    revision, source_date = "master", ""
    try:
        download(COMMITS_URL, commit_file, 256 * 1024)
        data = json.loads(commit_file.read_text(encoding="utf-8"))[0]
        candidate = data["sha"]
        if len(candidate) != 40 or any(c not in "0123456789abcdef" for c in candidate):
            raise ValueError("invalid upstream revision")
        revision = candidate
        source_date = data["commit"]["committer"]["date"]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        pass  # GitHub API rate limits must not prevent downloading public data.
    source = directory / "ipv4_source.txt"
    source_url = f"{RAW_BASE}/{revision}/data/ipv4_source.txt"
    source_sha = download(source_url, source, MAX_SOURCE_BYTES)
    license_file = directory / "LICENSE.md"
    download(f"{RAW_BASE}/{revision}/LICENSE.md", license_file, 256 * 1024)
    return source, {"provider": "ip2region", "repository": REPOSITORY, "source_url": source_url,
                    "revision": revision if revision != "master" else "", "source_date": source_date,
                    "source_sha256": source_sha, "license": license_file.read_text(encoding="utf-8"),
                    "built_at": int(time.time())}


def clean_field(value: str) -> str:
    value = value.strip()
    if len(value) > 512 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid geolocation field")
    return "unknown" if value in {"", "0", "-", "unknown"} else value


def build_database(source: Path, target: Path, metadata: dict) -> dict:
    conn = sqlite3.connect(target)
    try:
        conn.executescript(f"""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA application_id={APPLICATION_ID};
            PRAGMA user_version=1;
            CREATE TABLE ranges(start INTEGER PRIMARY KEY,end INTEGER NOT NULL,geo TEXT NOT NULL,isp TEXT NOT NULL);
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        """)
        previous, count, batch = -1, 0, []
        with source.open(encoding="utf-8-sig") as lines:
            for line in lines:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.rstrip("\r\n").split("|")
                if len(parts) != 7:
                    raise ValueError("unexpected ip2region format; active database retained")
                start, end = (int(ipaddress.IPv4Address(x)) for x in parts[:2])
                if start != previous + 1 or end < start:
                    raise ValueError("database has overlapping, missing, or unordered IPv4 ranges")
                fields = [clean_field(field) for field in parts[2:5]]
                geo = "/".join(dict.fromkeys(x for x in fields if x != "unknown")) or "unknown"
                batch.append((start, end, geo, clean_field(parts[5])))
                previous, count = end, count + 1
                if count > MAX_ROWS:
                    raise ValueError("too many database rows")
                if len(batch) >= 5000:
                    conn.executemany("INSERT INTO ranges VALUES(?,?,?,?)", batch)
                    batch.clear()
        if count < MIN_ROWS or previous != 0xFFFFFFFF:
            raise ValueError("incomplete IPv4 database; active database retained")
        conn.executemany("INSERT INTO ranges VALUES(?,?,?,?)", batch)
        info = {**metadata, "provider": "ip2region", "schema_version": 1, "rows": count}
        conn.execute("INSERT INTO metadata VALUES('info',?)", (json.dumps(info, ensure_ascii=False),))
        conn.commit()
        return info
    finally:
        conn.close()


def validate_database(path: Path) -> dict:
    if path.stat().st_size > MAX_DATABASE_BYTES:
        raise ValueError("database file is too large")
    conn = connect_readonly(path)
    try:
        if conn.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
            raise ValueError("unrecognized geolocation database")
        schema = conn.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if set(schema) != {("table", "ranges"), ("table", "metadata")}:
            raise ValueError("unexpected database schema")
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("database integrity check failed")
        info = json.loads(conn.execute("SELECT value FROM metadata WHERE key='info'").fetchone()[0])
        if not isinstance(info, dict):
            raise ValueError("invalid database metadata")
        count = conn.execute("SELECT COUNT(*) FROM ranges").fetchone()[0]
        if info.get("provider") != "ip2region" or info.get("schema_version") != 1 or count != info.get("rows") or not MIN_ROWS <= count <= MAX_ROWS:
            raise ValueError("invalid database metadata")
        previous = -1
        for start, end, geo, isp in conn.execute("SELECT start,end,geo,isp FROM ranges ORDER BY start"):
            if start != previous + 1 or not start <= end <= 0xFFFFFFFF:
                raise ValueError("invalid IPv4 ranges")
            clean_field(geo)
            clean_field(isp)
            previous = end
        if previous != 0xFFFFFFFF:
            raise ValueError("incomplete IPv4 coverage")
        return info
    finally:
        conn.close()


def install_database(settings, candidate: Path) -> dict:
    info = validate_database(candidate)
    active = database_path(settings)
    active.parent.mkdir(parents=True, exist_ok=True)
    if active.exists():
        def digest(path):
            value = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    value.update(chunk)
            return value.digest()
        if digest(active) == digest(candidate):
            return {key: value for key, value in info.items() if key != "license"}
        previous = active.with_name("geoip.previous.db")
        temp_backup = active.with_name("geoip.backup.tmp")
        shutil.copyfile(active, temp_backup)
        os.replace(temp_backup, previous)
    candidate.chmod(0o644)
    os.replace(candidate, active)
    return {key: value for key, value in info.items() if key != "license"}


def receive_database(settings, stream, expected_sha256: str) -> dict:
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise ValueError("invalid database checksum")
    directory = database_path(settings).parent
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".geo-receive-", dir=directory) as temporary:
        candidate = Path(temporary) / "geoip.db"
        with gzip.GzipFile(fileobj=stream, mode="rb") as decompressed, candidate.open("wb") as output:
            digest = copy_bounded(decompressed, output, MAX_DATABASE_BYTES, time.monotonic() + 180)
        if digest != expected_sha256:
            raise ValueError("database checksum mismatch; active database retained")
        return install_database(settings, candidate)
