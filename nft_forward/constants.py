from __future__ import annotations

APP_NAME = "nft-forward"
TABLE_NAME = "nft_forward"
LEGACY_TABLE_NAMES = ("port_forward",)
RESERVED_PORTS = {80, 443, 8080, 8443}
CHANNELS = {"manual", "ssh_login", "ddns", "web"}
DYNAMIC_CHANNELS = {"ssh_login", "ddns", "web"}
DEFAULT_RULESET = "public"
DEFAULT_TTL_DAYS = 3650
LOG_PREFIX = "nft-forward-block "
