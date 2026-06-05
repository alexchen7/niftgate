#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / "cache" / "iplist"
BASE = "https://raw.githubusercontent.com/metowolf/iplist/master/data"

FILES = {
    "country": ["CN", "HK", "US", "JP", "SG", "GB", "DE", "FR", "CA", "AU"],
    "special": ["china"],
    "cncity": ["110000", "310000", "330000", "440000", "440100", "440300"],
    "isp": [
        "chinatelecom",
        "chinamobile",
        "chinaunicom",
        "cernet",
        "aliyun",
        "tencent",
        "googlecloud",
        "cloudflare",
        "amazon",
        "microsoft",
    ],
}


def download(url: str, dest: pathlib.Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "nft-forward-cache-updater/0.2"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    dest.write_bytes(data)


def main() -> int:
    for group, names in FILES.items():
        for name in names:
            url = f"{BASE}/{group}/{name}.txt"
            dest = CACHE / group / f"{name}.txt"
            try:
                download(url, dest)
                print(f"ok {group}/{name}.txt")
            except Exception as exc:
                print(f"failed {group}/{name}.txt: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
