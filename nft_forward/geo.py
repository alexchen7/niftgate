from __future__ import annotations

import ipaddress
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from .config import Settings
from .sshutil import ssh_command

GEO_LABELS = {
    "CN": "China",
    "HK": "Hong Kong",
    "US": "United States",
    "JP": "Japan",
    "SG": "Singapore",
    "GB": "United Kingdom",
    "DE": "Germany",
    "FR": "France",
    "CA": "Canada",
    "AU": "Australia",
    "china": "China",
    "110000": "China/Beijing",
    "310000": "China/Shanghai",
    "330000": "China/Zhejiang",
    "440000": "China/Guangdong",
    "440100": "China/Guangdong/Guangzhou",
    "440300": "China/Guangdong/Shenzhen",
}

GeoIndex = Dict[Tuple[int, int], Tuple[str, str]]
_INDEX_CACHE_LOCK = threading.Lock()
_INDEX_CACHE: dict[str, tuple[tuple[tuple[str, int, int], ...], GeoIndex]] = {}


ISP_LABELS = {
    "chinatelecom": "China Telecom",
    "chinamobile": "China Mobile",
    "chinaunicom": "China Unicom",
    "cernet": "CERNET",
    "aliyun": "Alibaba Cloud",
    "tencent": "Tencent Cloud",
    "googlecloud": "Google Cloud",
    "cloudflare": "Cloudflare",
    "amazon": "Amazon Web Services",
    "microsoft": "Microsoft",
}


@dataclass
class GeoInfo:
    geo: str = "unknown"
    isp: str = "unknown"
    source: str = "none"


class GeoLookup:
    def __init__(self, settings: Settings):
        self.settings = settings

    def lookup(self, ip: str, allow_ssh_fallback: bool = True) -> GeoInfo:
        local = self.lookup_local(ip)
        if allow_ssh_fallback and self.settings.exit_host and (
            local.geo == "unknown" or local.isp == "unknown"
        ):
            remote = self.lookup_via_exit(ip)
            if remote.geo != "unknown" or remote.isp != "unknown":
                return GeoInfo(
                    local.geo if local.geo != "unknown" else remote.geo,
                    local.isp if local.isp != "unknown" else remote.isp,
                    "cache+exit-ssh" if (local.geo != "unknown" or local.isp != "unknown") else remote.source,
                )
        if local.geo != "unknown" or local.isp != "unknown":
            return local
        return GeoInfo()

    def lookup_local(self, ip: str) -> GeoInfo:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return GeoInfo()
        value = int(addr)
        geo = "unknown"
        isp = "unknown"
        index = self._load_index()
        for prefix_len in range(32, -1, -1):
            mask = 0 if prefix_len == 0 else (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            match = index.get((prefix_len, value & mask))
            if not match:
                continue
            if geo == "unknown" and match[0] != "unknown":
                geo = match[0]
            if isp == "unknown" and match[1] != "unknown":
                isp = match[1]
            if geo != "unknown" and isp != "unknown":
                break
        return GeoInfo(geo, isp, "cache") if geo != "unknown" or isp != "unknown" else GeoInfo()

    def lookup_via_exit(self, ip: str) -> GeoInfo:
        result = ssh_command(
            self.settings.exit_host,
            self.settings.exit_user,
            self.settings.exit_port,
            self.settings.exit_key,
            ["nft-forward-exit-geo", ip],
            timeout=self.settings.ssh_timeout,
            auth_method=self.settings.exit_auth_method,
            password_file=self.settings.exit_password_file,
        )
        if not result.ok:
            return GeoInfo()
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return GeoInfo()
        return GeoInfo(data.get("geo") or "unknown", data.get("isp") or "unknown", "exit-ssh")

    def lookup_online(self, ip: str) -> GeoInfo:
        url = self.settings.geo_fallback_url.format(ip=ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nft-forward/0.2"})
            with urllib.request.urlopen(req, timeout=self.settings.geo_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
            return GeoInfo()
        if data.get("success") is False:
            return GeoInfo()
        parts = [data.get("country"), data.get("region"), data.get("city")]
        geo = "/".join(str(p) for p in parts if p) or "unknown"
        isp = data.get("isp") or data.get("org") or data.get("connection", {}).get("isp") or "unknown"
        return GeoInfo(geo, isp, "online")

    def _load_index(self) -> GeoIndex:
        root = self.settings.paths.ip_cache if self.settings.paths else Path("cache/iplist")
        if not root.exists():
            return {}
        files = sorted(root.rglob("*.txt"))
        signature_parts: list[tuple[str, int, int]] = []
        for path in files:
            try:
                stat = path.stat()
            except OSError:
                continue
            signature_parts.append((str(path), stat.st_mtime_ns, stat.st_size))
        signature = tuple(signature_parts)
        cache_key = str(root.resolve())
        with _INDEX_CACHE_LOCK:
            cached = _INDEX_CACHE.get(cache_key)
            if cached and cached[0] == signature:
                return cached[1]
            index: GeoIndex = {}
            for path in files:
                label = path.stem
                parent = path.parent.name
                geo = GEO_LABELS.get(label, label) if parent in {"country", "cncity", "special"} else "unknown"
                isp = ISP_LABELS.get(label, label) if parent == "isp" else "unknown"
                try:
                    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
                except OSError:
                    continue
                for line in lines:
                    cidr = line.strip()
                    if not cidr or cidr.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    if net.version != 4:
                        continue
                    key = (net.prefixlen, int(net.network_address))
                    old_geo, old_isp = index.get(key, ("unknown", "unknown"))
                    index[key] = (
                        old_geo if old_geo != "unknown" else geo,
                        old_isp if old_isp != "unknown" else isp,
                    )
            _INDEX_CACHE[cache_key] = (signature, index)
            return index
