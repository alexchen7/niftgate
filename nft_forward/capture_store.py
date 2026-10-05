"""Rotating root-only PCAP files with separate, bounded metadata indexes."""
from __future__ import annotations

import json
from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import struct
import time

from .capture_pcap import PCAP_HEADER

FILE_ID = re.compile(r"cap-[0-9]{20}-[a-f0-9]{12}\Z")
SEGMENT_BYTES = 8 * 1024 * 1024
SEGMENT_ROWS = 10000
FREE_RESERVE = 128 * 1024 * 1024


def directory(settings):
    return settings.paths.state_db.parent / "captures"


def private_directory(root):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)


@contextmanager
def read_index(root, file_id):
    if not FILE_ID.fullmatch(file_id):
        raise ValueError("invalid capture file ID")
    conn = sqlite3.connect((root / (file_id + ".sqlite")).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def files(settings, page=1):
    root = directory(settings)
    indexes = sorted((path for path in root.glob("cap-*.sqlite") if FILE_ID.fullmatch(path.stem)), reverse=True)
    pages = max(1, math.ceil(len(indexes) / 8))
    page = min(max(1, int(page)), pages)
    rows = []
    for path in indexes[(page - 1) * 8:page * 8]:
        try:
            with read_index(root, path.stem) as conn:
                info = json.loads(conn.execute("SELECT value FROM info").fetchone()[0])
                count, first, last = conn.execute("SELECT COUNT(*),MIN(timestamp),MAX(timestamp) FROM packets").fetchone()
            rows.append({"id": path.stem, "count": count, "first": first, "last": last,
                         "bytes": path.stat().st_size + path.with_suffix(".pcap").stat().st_size,
                         "path": str(path.with_suffix(".pcap")), **info})
        except (OSError, sqlite3.Error, ValueError, TypeError):
            continue
    return {"page": page, "pages": pages, "rows": rows}


def records(settings, file_id, page=1, anchor=None):
    try:
        with read_index(directory(settings), file_id) as conn:
            conn.execute("BEGIN")
            maximum = conn.execute("SELECT COALESCE(MAX(id),0) FROM packets").fetchone()[0]
            anchor = maximum if anchor is None else min(maximum, max(0, int(anchor)))
            count = conn.execute("SELECT COUNT(*) FROM packets WHERE id<=?", (anchor,)).fetchone()[0]
            pages = max(1, math.ceil(count / 5))
            page = min(max(1, int(page)), pages)
            rows = [json.loads(row[0]) for row in conn.execute(
                "SELECT metadata FROM packets WHERE id<=? ORDER BY id DESC LIMIT 5 OFFSET ?", (anchor, (page - 1) * 5))]
        return {"file": file_id, "path": str(directory(settings) / (file_id + ".pcap")),
                "page": page, "pages": pages, "anchor": anchor, "total": count, "rows": rows}
    except (OSError, sqlite3.OperationalError):
        return {"expired": True, "rows": []}


class Store:
    def __init__(self, settings, config):
        self.root = directory(settings)
        private_directory(self.root)
        self.config = config
        self.file_id = None
        self.pcap = self.conn = None
        self.count = 0
        self.started = self.flushed = self.checked = 0
        self.used = 0
        self.prune()

    def owned(self):
        return [p for p in self.root.iterdir() if FILE_ID.fullmatch(p.name.split(".")[0]) and
                p.name.endswith((".pcap", ".sqlite", ".sqlite-journal")) and p.is_file() and not p.is_symlink()]

    def prune(self, reserve=1024 * 1024):
        paths = self.owned()
        groups = {}
        for path in paths:
            groups.setdefault(path.name.split(".")[0], []).append(path)
        used = sum(path.stat().st_size for path in paths)
        budget = self.config["max_disk_mb"] * 1024 * 1024
        cutoff = time.time() - self.config["retention_days"] * 86400
        for name, group in sorted(groups.items()):
            if name == self.file_id:
                continue
            if used + reserve <= budget and max(p.stat().st_mtime for p in group) >= cutoff:
                continue
            for path in group:
                size = path.stat().st_size
                path.unlink()
                used -= size
        self.used = used
        self.checked = time.monotonic()
        return used + reserve <= budget and shutil.disk_usage(self.root).free > FREE_RESERVE + reserve

    def start(self):
        self.file_id = f"cap-{time.time_ns():020d}-{secrets.token_hex(6)}"
        path = self.root / (self.file_id + ".pcap")
        self.pcap = path.open("xb")
        path.chmod(0o600)
        self.pcap.write(PCAP_HEADER)
        index = self.root / (self.file_id + ".sqlite")
        fd = os.open(index, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        self.conn = sqlite3.connect(index, timeout=2)
        self.conn.executescript("PRAGMA journal_mode=DELETE; PRAGMA synchronous=NORMAL; CREATE TABLE info(value TEXT); CREATE TABLE packets(id INTEGER PRIMARY KEY,timestamp REAL,metadata TEXT);")
        self.conn.execute("INSERT INTO info VALUES(?)", (json.dumps({"scope": self.config["scope"], "countries": self.config["countries"], "ports": self.config["ports"]}),))
        self.count = 0
        self.started = self.flushed = time.monotonic()

    def flush(self):
        if self.pcap:
            self.pcap.flush()
            self.conn.commit()
            self.flushed = time.monotonic()

    def tick(self):
        self.flush()
        if self.pcap and time.monotonic() - self.started > 300:
            self.close()

    def close(self):
        try:
            self.flush()
        finally:
            if self.pcap:
                self.pcap.close()
            if self.conn:
                self.conn.close()
            self.pcap = self.conn = None
            self.file_id = None

    def append(self, sec, usec, payload, metadata):
        now = time.monotonic()
        if self.pcap and (self.count >= SEGMENT_ROWS or self.pcap.tell() >= SEGMENT_BYTES or now - self.started > 300):
            self.close()
        if now - self.checked >= 1:
            self.flush()
            if not self.prune():
                self.close()
                return False
        # The metadata index is included in prune's measured usage, with margin
        # for its pages/journal and a bounded batch between checks.
        if self.used + len(payload) + 4096 > self.config["max_disk_mb"] * 1024 * 1024:
            self.close()
            if not self.prune():
                return False
        if self.pcap is None:
            if not self.prune():
                return False
            self.start()
        offset = self.pcap.tell()
        self.pcap.write(struct.pack("<IIII", sec, usec, len(payload), metadata["packet_bytes"]))
        self.pcap.write(payload)
        self.count += 1
        record = {**metadata, "id": self.count, "timestamp": sec + usec / 1_000_000, "offset": offset}
        encoded = json.dumps(record, ensure_ascii=False)
        self.used += len(payload) + len(encoded.encode("utf-8")) + 512
        self.conn.execute("INSERT INTO packets VALUES(?,?,?)", (self.count, record["timestamp"], encoded))
        if self.count % 100 == 0 or now - self.flushed >= 1:
            self.flush()
        return True
