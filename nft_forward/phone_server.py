from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import load_settings
from .exitnode import push_ingest, push_secret_hit, state_for, sync_from_relay


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
        ok = push_ingest(settings, "web", source_ip, ruleset=url.ruleset, note=note)
        state = state_for(settings)
        try:
            state.record_secret_url_hit(url.id)
        finally:
            state.close()
        push_secret_hit(settings, url.id)
        body = {"ok": ok, "source_ip": source_ip, "ruleset": url.ruleset}
        self.send_response(200 if ok else 202)
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
