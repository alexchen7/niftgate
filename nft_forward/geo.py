from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

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
        self._index: list[tuple[ipaddress.IPv4Network, str, str]] | None = None

    def lookup(self, ip: str, allow_ssh_fallback: bool = True) -> GeoInfo:
        local = self.lookup_local(ip)
        if allow_ssh_fallback:
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
        best_geo: tuple[int, str] | None = None
        best_isp: tuple[int, str] | None = None
        for network, geo, isp in self._load_index():
            if addr in network:
                if geo != "unknown" and (best_geo is None or network.prefixlen > best_geo[0]):
                    best_geo = (network.prefixlen, geo)
                if isp != "unknown" and (best_isp is None or network.prefixlen > best_isp[0]):
                    best_isp = (network.prefixlen, isp)
        if best_geo or best_isp:
            return GeoInfo(
                best_geo[1] if best_geo else "unknown",
                best_isp[1] if best_isp else "unknown",
                "cache",
            )
        return GeoInfo()

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

    def _load_index(self) -> list[tuple[ipaddress.IPv4Network, str, str]]:
        if self._index is not None:
            return self._index
        index: list[tuple[ipaddress.IPv4Network, str, str]] = []
        root = self.settings.paths.ip_cache if self.settings.paths else Path("cache/iplist")
        if not root.exists():
            self._index = []
            return self._index
        for path in root.rglob("*.txt"):
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
                if net.version == 4:
                    index.append((net, geo, isp))
        self._index = index
        return index
