from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from .geo_database import database_info, database_path, fetch_source, build_database, install_database, lookup_database, validate_database
from .sshutil import build_ssh_command
from .state import State

SERVICE = "nft-forward-geo-update.service"
JOB_KEY = "geo_update_job"


def job_status(settings) -> dict:
    state = State(settings.paths.state_db)
    try:
        return json.loads(state.get_meta(JOB_KEY, "{}"))
    finally:
        state.close()


def save_job(settings, job: dict) -> None:
    state = State(settings.paths.state_db)
    try:
        job["updated_at"] = int(time.time())
        state.set_meta(JOB_KEY, json.dumps(job, ensure_ascii=False))
    finally:
        state.close()


@contextlib.contextmanager
def update_lock(settings):
    import fcntl
    directory = settings.paths.state_db.parent
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "geo-update.lock").open("a") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def request_update(settings) -> dict:
    if settings.role != "exit":
        raise ValueError("start database updates on the exit node")
    with update_lock(settings) as acquired:
        current = job_status(settings)
        if not acquired:
            return current
        job = current if current.get("status") == "queued" else {
            "id": uuid.uuid4().hex, "status": "queued", "phase": "queued", "started_at": int(time.time()),
            "relay": current.get("relay", {})}
        save_job(settings, job)
    try:
        proc = subprocess.run(["systemctl", "start", "--no-block", SERVICE], text=True, capture_output=True, timeout=5)
        if proc.returncode:
            raise RuntimeError((proc.stderr or "update service unavailable").strip()[:240])
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        job.update(status="failed", error=str(exc))
        save_job(settings, job)
    return job


def refresh_labels(settings) -> dict:
    """Refresh display metadata only; never change eligibility or nftables."""
    state = State(settings.paths.state_db, settings.paths.audit_log)
    counts = {"allow_entries": 0, "blocked_events": 0}
    try:
        for table, field in (("allow_entries", "source"), ("blocked_events", "source_ip")):
            last_id = 0
            while True:
                rows = state.conn.execute(f"SELECT id,{field},geo,isp FROM {table} WHERE id>? ORDER BY id LIMIT 500", (last_id,)).fetchall()
                if not rows:
                    break
                updates = []
                for row in rows:
                    last_id = row["id"]
                    ip = row[field].split("/", 1)[0].split("-", 1)[0]
                    result = lookup_database(settings, ip)
                    if not result:
                        continue
                    geo = result[0] if result[0] != "unknown" else row["geo"]
                    isp = result[1] if result[1] != "unknown" else row["isp"]
                    if (geo, isp) != (row["geo"], row["isp"]):
                        updates.append((geo, isp, row["id"]))
                with state.conn:
                    state.conn.executemany(f"UPDATE {table} SET geo=?,isp=? WHERE id=?", updates)
                counts[table] += len(updates)
        state.audit("geo_labels_refreshed", **counts)
        return counts
    finally:
        state.close()


def push_database(settings) -> dict:
    path = database_path(settings)
    expected_source = database_info(settings).get("source_sha256")
    digest = hashlib.sha256()
    with tempfile.TemporaryFile() as packed:
        with gzip.GzipFile(fileobj=packed, mode="wb") as compressor, path.open("rb") as source:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
                compressor.write(chunk)
        args = ["nft.sh", "geo-import", "--sha256", digest.hexdigest()]
        cmd = build_ssh_command(settings.relay_host, settings.relay_user, settings.relay_port,
                                settings.relay_key, args, timeout=settings.ssh_timeout,
                                auth_method=settings.relay_auth_method, password_file=settings.relay_password_file)
        if not settings.relay_host:
            raise ValueError("relay host is not configured")
        error = "relay database update failed"
        for attempt in range(3):
            packed.seek(0)
            try:
                proc = subprocess.run(cmd, stdin=packed, text=True, capture_output=True, timeout=180)
                if proc.returncode == 0:
                    result = json.loads(proc.stdout)
                    if not isinstance(result, dict) or result.get("provider") != "ip2region" or result.get("source_sha256") != expected_source:
                        raise ValueError("relay returned an invalid update acknowledgement")
                    return result
                error = (proc.stderr or proc.stdout or error).strip()[:300]
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                error = str(exc)[:300]
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(error)


def perform_update(settings, local_only: bool = False) -> dict:
    if not local_only and settings.role != "exit":
        raise ValueError("run geo-update on the exit node; use --local-only for a standalone database")
    with update_lock(settings) as acquired:
        if not acquired:
            return job_status(settings)
        job = job_status(settings)
        if job.get("status") != "queued":
            job = {"id": uuid.uuid4().hex, "started_at": int(time.time()), "relay": job.get("relay", {})}
        def progress(phase):
            job.update(status="running", phase=phase)
            save_job(settings, job)
        try:
            progress("downloading")
            directory = database_path(settings).parent
            directory.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".geo-build-", dir=directory) as temporary:
                source, metadata = fetch_source(Path(temporary))
                current = database_info(settings)
                needs_build = current.get("source_sha256") != metadata["source_sha256"]
                if not needs_build:
                    try:
                        validate_database(database_path(settings))
                    except Exception:
                        needs_build = True
                if needs_build:
                    progress("building")
                    candidate = Path(temporary) / "geoip.db"
                    build_database(source, candidate, metadata)
                    job["database"] = install_database(settings, candidate)
                else:
                    job["database"] = current
            progress("refreshing")
            job["local_labels"] = refresh_labels(settings)
            if not local_only:
                progress("uploading")
                job["relay"] = push_database(settings)
            job.update(status="succeeded", phase="complete", completed_at=int(time.time()), error="")
        except Exception as exc:
            job.update(status="failed", error=str(exc)[:400], completed_at=int(time.time()))
        save_job(settings, job)
        return job
