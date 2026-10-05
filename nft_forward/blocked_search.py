"""Validated blocked-history queries and bounded, stable pagination snapshots."""
from __future__ import annotations

import contextlib
import bisect
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import unicodedata

PAGE_SIZE = 5
SNAPSHOT_TTL = 1800
MAX_SNAPSHOTS = 8
MAX_ROWS = 100_000
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_QUERY_SECONDS = 5

# Other country names work unchanged and are available through the country picker.
COUNTRIES = {
    "CN": ("China", "中国", "CHN", "中国大陆", "中华人民共和国"),
    "US": ("United States", "美国", "USA", "United States of America"),
    "GB": ("United Kingdom", "英国", "UK", "GBR"),
    "CA": ("Canada", "加拿大", "CAN"),
    "AU": ("Australia", "澳大利亚", "AUS"),
    "JP": ("Japan", "日本", "JPN"),
    "KR": ("South Korea", "韩国", "Korea", "KOR"),
    "HK": ("Hong Kong", "香港", "中国香港", "Hong Kong SAR"),
    "MO": ("Macao", "澳门", "中国澳门", "Macau"),
    "TW": ("Taiwan", "台湾", "中国台湾"),
    "SG": ("Singapore", "新加坡", "SGP"),
    "DE": ("Germany", "德国", "DEU"),
    "FR": ("France", "法国", "FRA"),
    "NL": ("Netherlands", "荷兰", "NLD"),
    "RU": ("Russia", "俄罗斯", "Russian Federation", "RUS"),
    "IN": ("India", "印度", "IND"),
    "TH": ("Thailand", "泰国", "THA"),
    "VN": ("Vietnam", "越南", "Viet Nam", "VNM"),
    "MY": ("Malaysia", "马来西亚", "MYS"),
    "ID": ("Indonesia", "印度尼西亚", "IDN"),
    "BR": ("Brazil", "巴西", "BRA"),
    "??": ("Unknown", "未知", "", "0", "unknown"),
}
ALIASES = {name.casefold(): code for code, names in COUNTRIES.items() for name in (code, *names)}


def country_key(value: str) -> str:
    country = unicodedata.normalize("NFKC", str(value or "unknown")).strip().casefold()
    if len(country) > 80 or any(ord(c) < 32 for c in country):
        raise ValueError("country name is too long or contains control characters")
    return ALIASES.get(country, country)


def geo_country(geo: str) -> str:
    try:
        return country_key((geo or "unknown").split("/", 1)[0])
    except ValueError:
        return "??"


def country_label(value: str, language: str = "en") -> str:
    names = COUNTRIES.get(value)
    return names[1 if language == "zh" else 0] if names else value


def parse_time(value: str, end: bool = False) -> int:
    value = value.strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?)?", value):
        raise ValueError("use YYYY-MM-DD HH:MM (UTC) or an ISO date/time with an explicit offset")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if len(value) == 10 and end:
        parsed = parsed.replace(hour=23, minute=59, second=59)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    result = int(parsed.timestamp())
    if not 0 <= result <= 253402300799:
        raise ValueError("date/time is out of range")
    return result


def source_bounds(value: str) -> tuple[int, int]:
    if "-" in value:
        first, last = value.split("-", 1)
        low, high = int(ipaddress.IPv4Address(first.strip())), int(ipaddress.IPv4Address(last.strip()))
        if low > high:
            raise ValueError("source range start exceeds end")
        return low, high
    net = ipaddress.IPv4Network(value.strip(), strict=False)
    return int(net.network_address), int(net.broadcast_address)


def normalize_query(query: dict | None, now: int | None = None) -> dict:
    query = {} if query is None else query
    allowed = {"operator", "ports", "countries", "sources", "protocol", "since", "until", "window", "exclude_whitelisted"}
    if not isinstance(query, dict) or set(query) - allowed:
        raise ValueError("invalid blocked-search fields")
    operator = query.get("operator", "AND")
    if not isinstance(operator, str) or operator not in {"AND", "OR"}:
        raise ValueError("operator must be AND or OR")
    result = {"operator": operator}
    if "exclude_whitelisted" in query:
        if type(query["exclude_whitelisted"]) is not bool:
            raise ValueError("exclude_whitelisted must be true or false")
        if query["exclude_whitelisted"]:
            result["exclude_whitelisted"] = True
    for field in ("ports", "countries", "sources"):
        values = query.get(field, [])
        if not isinstance(values, list) or len(values) > 16:
            raise ValueError(f"{field} must contain at most 16 values")
        cleaned = []
        for value in values:
            if field == "ports":
                if type(value) is not int or not 1 <= value <= 65535:
                    raise ValueError("ports must be integers from 1 to 65535")
            else:
                if not isinstance(value, str) or len(value) > 80:
                    raise ValueError(f"invalid {field} value")
                value = country_key(value) if field == "countries" else value.strip()
                if field == "sources":
                    source_bounds(value)
            if value not in cleaned:
                cleaned.append(value)
        if cleaned:
            result[field] = cleaned
    protocol = query.get("protocol")
    if protocol:
        if not isinstance(protocol, str) or protocol not in {"TCP", "UDP"}:
            raise ValueError("protocol must be TCP or UDP")
        result["protocol"] = protocol
    for field in ("since", "until"):
        value = query.get(field)
        if value is not None:
            if type(value) is not int or not 0 <= value <= 253402300799:
                raise ValueError(f"invalid {field} timestamp")
            result[field] = value
    window = query.get("window")
    if window is not None:
        if type(window) is not int or not 1 <= window <= 3650 * 86400:
            raise ValueError("duration must be between one second and 3650 days")
        now = int(time.time()) if now is None else now
        result.update(window=window, since=max(0, now - window), until=now)
    if result.get("since", 0) > result.get("until", 253402300799):
        raise ValueError("start time must not be after end time")
    return result


def compile_query(query: dict) -> tuple[str, list]:
    clauses, params = [], []
    for field, column in (("ports", "lport"), ("countries", "geo_country(geo)")):
        values = query.get(field, [])
        if values:
            clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
            params.extend(values)
    if query.get("sources"):
        ranges = []
        for source in query["sources"]:
            low, high = source_bounds(source)
            ranges.append("ipv4_number(source_ip) BETWEEN ? AND ?")
            params.extend((low, high))
        clauses.append("(" + " OR ".join(ranges) + ")")
    if query.get("protocol"):
        clauses.append("proto=?")
        params.append(query["protocol"])
    times = []
    for field, op in (("since", ">="), ("until", "<=")):
        if field in query:
            times.append(f"last_seen {op} ?")
            params.append(query[field])
    if times:
        clauses.append("(" + " AND ".join(times) + ")")
    condition = f" {query['operator']} ".join(clauses) or "1"
    # Hidden records are excluded outside the OR expression as well.
    exclusion = " AND NOT currently_whitelisted(source_ip)" if query.get("exclude_whitelisted") else ""
    return "hidden=0" + exclusion + " AND (" + condition + ")", params


def whitelist_checker(conn, now=None):
    """Freeze the union of active public/custom allow entries for this query."""
    now = int(time.time()) if now is None else now
    intervals = []
    for row in conn.execute("SELECT source FROM allow_entries WHERE expires_at IS NULL OR expires_at>?", (now,)):
        try:
            intervals.append(source_bounds(row[0]))
        except ValueError:
            continue
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    starts = [row[0] for row in merged]
    def check(address):
        try:
            value = int(ipaddress.IPv4Address(address))
        except ValueError:
            return False
        index = bisect.bisect_right(starts, value) - 1
        return index >= 0 and value <= merged[index][1]
    return check


@contextlib.contextmanager
def history_connection(settings):
    conn = sqlite3.connect(settings.paths.state_db.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    deadline = time.monotonic() + MAX_QUERY_SECONDS
    conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    conn.create_function("geo_country", 1, geo_country)
    def number(value):
        try:
            return int(ipaddress.IPv4Address(value))
        except ValueError:
            return None
    conn.create_function("ipv4_number", 1, number)
    try:
        yield conn
    finally:
        conn.close()


def facets(settings) -> dict:
    with history_connection(settings) as conn:
        ports = [row[0] for row in conn.execute("SELECT DISTINCT lport FROM blocked_events WHERE hidden=0 ORDER BY lport")]
        countries = [dict(row) for row in conn.execute(
            "SELECT geo_country(geo) AS key,COUNT(*) AS count FROM blocked_events WHERE hidden=0 GROUP BY geo_country(geo) ORDER BY count DESC,key")]
    return {"ports": ports, "countries": countries}


def cache_dir(settings) -> Path:
    return settings.paths.state_db.parent / "blocked-search"


@contextlib.contextmanager
def cache_lock(root):
    import fcntl
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    with (root / "cache.lock").open("a") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("another blocked-history search is being prepared; retry shortly") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def snapshot(settings, raw_query: dict | None = None) -> str:
    query = normalize_query(raw_query)
    where, params = compile_query(query)
    root = cache_dir(settings)
    token = secrets.token_hex(16)
    with cache_lock(root):
        now = time.time()
        files = sorted(root.glob("*.db"), key=lambda p: p.stat().st_mtime)
        for path in files:
            if now - path.stat().st_mtime > SNAPSHOT_TTL:
                path.unlink(missing_ok=True)
        for path in root.glob("*.tmp"):
            if now - path.stat().st_mtime > SNAPSHOT_TTL:
                path.unlink(missing_ok=True)
        temporary = root / f"{token}.tmp"
        cached = sqlite3.connect(temporary)
        temporary.chmod(0o600)
        try:
            cached.executescript("PRAGMA journal_mode=OFF; CREATE TABLE rows(position INTEGER PRIMARY KEY,payload TEXT); CREATE TABLE meta(payload TEXT);")
            count = 0
            started = time.monotonic()
            with history_connection(settings) as conn:
                conn.execute("BEGIN")
                if query.get("exclude_whitelisted"):
                    conn.create_function("currently_whitelisted", 1, whitelist_checker(conn))
                cursor = conn.execute(
                    "SELECT id,source_ip,proto,lport,geo,isp,first_seen,last_seen,count FROM blocked_events WHERE "
                    + where + " ORDER BY last_seen DESC,id DESC LIMIT ?", (*params, MAX_ROWS + 1))
                while True:
                    rows = cursor.fetchmany(500)
                    if not rows:
                        break
                    values = []
                    for row in rows:
                        count += 1
                        values.append((count, json.dumps(dict(row), ensure_ascii=False)))
                    if count > MAX_ROWS or time.monotonic() - started > MAX_QUERY_SECONDS:
                        raise ValueError("too many blocked records; narrow the search filters")
                    cached.executemany("INSERT INTO rows VALUES(?,?)", values)
                    if temporary.stat().st_size > MAX_SNAPSHOT_BYTES:
                        raise ValueError("blocked search is too large; narrow the filters")
            cached.execute("INSERT INTO meta VALUES(?)", (json.dumps({"filters": query, "total": count, "created_at": int(now), "token": token}),))
            cached.commit()
            if temporary.stat().st_size > MAX_SNAPSHOT_BYTES:
                raise ValueError("blocked search is too large; narrow the filters")
            cached.close()
            files = sorted(root.glob("*.db"), key=lambda p: p.stat().st_mtime)
            while len(files) >= MAX_SNAPSHOTS:
                files.pop(0).unlink(missing_ok=True)
            os.replace(temporary, root / f"{token}.db")
        finally:
            cached.close()
            temporary.unlink(missing_ok=True)
    return token


def page(settings, token: str, requested_page: int = 1) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise ValueError("invalid search token")
    if type(requested_page) is not int or not 1 <= requested_page <= 1_000_000:
        raise ValueError("page number must be a positive integer")
    path = cache_dir(settings) / f"{token}.db"
    try:
        if time.time() - path.stat().st_mtime > SNAPSHOT_TTL:
            return {"expired": True}
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    except (OSError, sqlite3.OperationalError):
        return {"expired": True}
    try:
        result = json.loads(conn.execute("SELECT payload FROM meta").fetchone()[0])
        pages = max(1, (result["total"] + PAGE_SIZE - 1) // PAGE_SIZE)
        current = min(requested_page, pages)
        rows = [json.loads(row[0]) for row in conn.execute("SELECT payload FROM rows WHERE position>? ORDER BY position LIMIT ?",
                                                        ((current - 1) * PAGE_SIZE, PAGE_SIZE))]
        return {**result, "page": current, "pages": pages, "page_size": PAGE_SIZE, "rows": rows, "expired": False}
    finally:
        conn.close()
