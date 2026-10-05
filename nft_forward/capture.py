"""Optional, bounded packet-copy collector. Never changes packet verdicts."""
from __future__ import annotations

from collections import OrderedDict
import contextlib
import json
import ipaddress
import os
import selectors
import shutil
import signal
import subprocess
import time

from .blocked_search import country_key
from .capture_config import NFLOG_GROUP, get_config, validate_config
from .capture_pcap import Stream, decode_nflog
from .capture_store import Store, directory, private_directory
from .config import load_settings
from .geo import GeoLookup
from .geo_database import database_path, lookup_database
from .logging_util import append_jsonl
from .nft import apply_lock, render_nft, write_and_apply, write_config_atomically
from .state import State


def read_config(settings):
    state = State(settings.paths.state_db)
    try:
        return get_config(state)
    finally:
        state.close()


def configure(settings, patch, check_service=True):
    if settings.role != "relay":
        raise ValueError("packet recording must be configured on the relay")
    if not isinstance(patch, dict):
        raise ValueError("recording settings must be an object")
    patch = dict(patch)
    ports = patch.pop("ports", None)
    if ports is not None and (not isinstance(ports, list) or len(ports) > 4096 or
                              any(type(p) is not int or not 1 <= p <= 65535 for p in ports)):
        raise ValueError("ports must be an array of forwarding port numbers")
    with apply_lock(settings):
        state = State(settings.paths.state_db)
        try:
            state.conn.execute("BEGIN IMMEDIATE")
            before = render_nft(settings, state)
            old = get_config(state)
            config = validate_config({**{k: v for k, v in old.items() if k != "ports"}, **patch})
            if config["enabled"] and check_service:
                if not shutil.which("tcpdump"):
                    raise ValueError("install tcpdump on the relay before enabling recording")
                proc = subprocess.run(["systemctl", "start", "nft-forward-capture.service"], capture_output=True, text=True, timeout=10)
                if proc.returncode:
                    raise ValueError("packet recording service could not start; check systemctl status nft-forward-capture")
            if ports is not None:
                mapping = {r.lport: r.id for r in state.rules()}
                if any(p not in mapping for p in ports):
                    raise ValueError("only existing forwarding ports can be recorded")
                state.conn.execute("DELETE FROM capture_ports")
                state.conn.executemany("INSERT INTO capture_ports(rule_id) VALUES(?)", [(mapping[p],) for p in sorted(set(ports))])
            state.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('capture_config',?)", (json.dumps(config),))
            if render_nft(settings, state) != before:
                write_and_apply(settings, state, lock_held=True)
            state.conn.commit()
            result = get_config(state)
        except Exception:
            state.conn.rollback()
            raise
        finally:
            state.close()
    append_jsonl(settings.paths.audit_log, {"event": "packet_recording_settings", "settings": result})
    return result


def status(settings):
    config = read_config(settings)
    state = State(settings.paths.state_db)
    try:
        ports = [{"port": r.lport, "restricted": not r.open_access} for r in state.rules()]
    finally:
        state.close()
    runtime = {}
    try:
        runtime = json.loads((directory(settings) / "status.json").read_text())
    except (OSError, ValueError):
        pass
    if not runtime or time.time() - runtime.get("updated_at", 0) > 15:
        runtime = {"state": "not running", "error": "collector heartbeat unavailable"}
    if config["enabled"] and config["ports"]:
        try:
            output = subprocess.run(["nft", "-j", "list", "table", "ip", "nft_forward"], text=True, capture_output=True, timeout=2)
            counters = {row["counter"]["name"]: row["counter"]["packets"] for row in json.loads(output.stdout)["nftables"] if "counter" in row}
            runtime["rate_limited"] = max(0, counters["capture_seen"] - counters["capture_sent"])
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError):
            runtime["rate_limited"] = "unknown"
    return {"config": config, "forwarding_ports": ports, "runtime": runtime, "directory": str(directory(settings))}


class Countries:
    def __init__(self, settings):
        self.settings = settings
        self.cache = OrderedDict()
        self.signature = None
        self.legacy = GeoLookup(settings)
        self.legacy_index = None

    def refresh(self):
        try:
            stat = database_path(self.settings).stat()
            signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
        except OSError:
            signature = None
        if signature != self.signature:
            self.cache.clear()
            self.legacy_index = None
            self.signature = signature

    def lookup(self, ip):
        if ip in self.cache:
            self.cache.move_to_end(ip)
            return self.cache[ip]
        value = lookup_database(self.settings, ip)
        if value is None:
            if self.legacy_index is None:
                self.legacy_index = self.legacy._load_index()
            address = int(ipaddress.IPv4Address(ip))
            geo, isp = "unknown", "unknown"
            for prefix in range(32, -1, -1):
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
                match = self.legacy_index.get((prefix, address & mask))
                if match:
                    geo = geo if geo != "unknown" else match[0]
                    isp = isp if isp != "unknown" else match[1]
                if geo != "unknown" and isp != "unknown":
                    break
            value = geo, isp
        geo, isp = value
        value = {"geo": geo, "isp": isp, "country": country_key(geo.split("/")[0])}
        self.cache[ip] = value
        if len(self.cache) > 4096:
            self.cache.popitem(last=False)
        return value


def stop_process(proc):
    if proc:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        proc.stdout.close()
        proc.stderr.close()


def run(settings=None):
    settings = settings or load_settings()
    if settings.role != "relay":
        raise ValueError("capture service is relay-only")
    os.umask(0o077)
    root = directory(settings)
    private_directory(root)
    import fcntl
    lock = (root / "collector.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    stats = {"saved": 0, "country_skipped": 0, "invalid": 0, "storage_skipped": 0, "errors": 0}
    countries = Countries(settings)
    proc = store = poller = config = None
    changed_at = published_at = prune_at = retry_at = 0
    backoff, error = 2, ""
    try:
        while not stopping:
            try:
                now = time.monotonic()
                if now >= changed_at:
                    updated = read_config(settings)
                    changed_at = now + 3
                    countries.refresh()
                    if updated != config:
                        stop_process(proc)
                        proc = None
                        if poller:
                            poller.close()
                        if store:
                            store.close()
                        store = Store(settings, updated)
                        config = updated
                        retry_at = 0
                active = config["enabled"] and bool(config["ports"])
                if active and not proc and now >= retry_at:
                    proc = subprocess.Popen(["tcpdump", "-n", "-i", f"nflog:{NFLOG_GROUP}", "-s", "0", "-U", "-w", "-"],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    poller = selectors.DefaultSelector()
                    for pipe in (proc.stdout, proc.stderr):
                        os.set_blocking(pipe.fileno(), False)
                        poller.register(pipe, selectors.EVENT_READ)
                    stream = Stream()
                    started = now
                    next_stats = now + 30
                if proc:
                    for key, _ in poller.select(timeout=1):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            poller.unregister(key.fileobj)
                            continue
                        if key.fileobj is proc.stderr:
                            stats["collector_message"] = data.decode("utf-8", "replace")[-500:].strip()
                            continue
                        for sec, usec, raw in stream.feed(data):
                            decoded = decode_nflog(raw, stream.endian)
                            if not decoded:
                                stats["invalid"] += 1
                                continue
                            payload, metadata = decoded
                            if metadata["destination_port"] not in config["ports"] or metadata["scope"] != config["scope"]:
                                continue
                            geo = countries.lookup(metadata["source_ip"])
                            if config["countries"] and geo["country"] not in config["countries"]:
                                stats["country_skipped"] += 1
                                continue
                            if store.append(sec, usec, payload, {**metadata, **geo}):
                                stats["saved"] += 1
                            else:
                                stats["storage_skipped"] += 1
                    if proc.poll() is not None:
                        raise RuntimeError("tcpdump stopped; " + stats.get("collector_message", "check NFLOG support"))
                    if now - started > 10:
                        backoff, error = 2, ""
                    if now >= next_stats and stream.endian:
                        proc.send_signal(signal.SIGUSR1)
                        next_stats = now + 30
                else:
                    time.sleep(1)
                store.tick()
                if now >= prune_at:
                    store.prune()
                    prune_at = now + 30
                if now >= published_at:
                    value = {**stats, "state": "recording" if proc else "retrying" if active else "off",
                             "updated_at": int(time.time()), "disk_bytes": store.used, "error": error}
                    write_config_atomically(root / "status.json", json.dumps(value))
                    published_at = now + 5
            except Exception as exc:
                error = str(exc)[:500]
                stats["errors"] += 1
                print(f"packet recording: {error}", flush=True)
                stop_process(proc)
                proc = None
                if poller:
                    poller.close()
                if store:
                    with contextlib.suppress(Exception):
                        store.close()
                with contextlib.suppress(OSError):
                    write_config_atomically(root / "status.json", json.dumps({**stats, "state": "retrying", "error": error, "updated_at": int(time.time())}))
                retry_at = time.monotonic() + backoff
                time.sleep(min(backoff, 5))
                backoff = min(60, backoff * 2)
    finally:
        stop_process(proc)
        if poller:
            poller.close()
        if store:
            store.close()
        lock.close()
