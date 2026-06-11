from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import load_settings
from .exitnode import enqueue_relay, state_for, sync_from_relay


HIT_DEDUP_SECONDS = 10
_RECENT_HITS: dict[tuple[int, str], float] = {}
_RECENT_HITS_LOCK = threading.Lock()


def accept_hit(url_id: int, source_ip: str) -> bool:
    now = time.monotonic()
    key = (url_id, source_ip)
    with _RECENT_HITS_LOCK:
        if len(_RECENT_HITS) > 4096:
            cutoff = now - HIT_DEDUP_SECONDS
            for old_key, seen_at in list(_RECENT_HITS.items()):
                if seen_at < cutoff:
                    _RECENT_HITS.pop(old_key, None)
        last_seen = _RECENT_HITS.get(key)
        if last_seen is not None and now - last_seen < HIT_DEDUP_SECONDS:
            return False
        _RECENT_HITS[key] = now
    return True


class PhoneHandler(BaseHTTPRequestHandler):
    server_version = "nft-forward-phone/0.2"

    def do_GET(self) -> None:  # noqa: N802
        settings = self.server.settings  # type: ignore[attr-defined]
        path = urlparse(self.path).path.strip("/")
        state = state_for(settings)
        try:
            url = state.secret_url_by_path(path)
        finally:
            state.close()
        if not url:
            self.send_response(404)
            self.end_headers()
            return
        source_ip = self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if not source_ip:
            source_ip = self.client_address[0]
        note = f"secret-url:{url.label or url.id}"
        queued = False
        if accept_hit(url.id, source_ip):
            enqueue_relay(settings, "ingest", {"channel": "web", "ip": source_ip, "ruleset": url.ruleset, "note": note})
            enqueue_relay(settings, "secret_hit", {"id": url.id})
            state = state_for(settings)
            try:
                state.record_secret_url_hit(url.id)
            finally:
                state.close()
            queued = True
        body = {"ok": True, "queued": queued, "source_ip": source_ip, "ruleset": url.ruleset}
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


def run() -> None:
    settings = load_settings()
    try:
        sync_from_relay(settings)
    except Exception:
        pass
    if settings.phone_secret_path:
        state = state_for(settings)
        try:
            state.ensure_secret_url(settings.phone_secret_path, label="default")
        finally:
            state.close()
    httpd = ThreadingHTTPServer((settings.phone_bind, settings.phone_port), PhoneHandler)
    httpd.settings = settings  # type: ignore[attr-defined]
    httpd.serve_forever()
