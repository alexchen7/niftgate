from __future__ import annotations

import json

from .blocked_search import country_key

NFLOG_GROUP = 61440
DEFAULTS = {"enabled": False, "scope": "blocked", "countries": [],
            "max_disk_mb": 256, "retention_days": 7, "rate_pps": 500}


def validate_config(data):
    if not isinstance(data, dict) or set(data) - set(DEFAULTS):
        raise ValueError("unknown packet recording setting")
    result = {**DEFAULTS, **data}
    if type(result["enabled"]) is not bool or not isinstance(result["scope"], str) or result["scope"] not in {"blocked", "all"}:
        raise ValueError("invalid recording enable/scope setting")
    for key, low, high in (("max_disk_mb", 32, 16384), ("retention_days", 1, 90), ("rate_pps", 10, 10000)):
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ValueError(f"{key} must be {low}..{high}")
    if not isinstance(result["countries"], list) or len(result["countries"]) > 32:
        raise ValueError("select at most 32 countries")
    if any(not isinstance(value, str) for value in result["countries"]):
        raise ValueError("countries must be names or country codes")
    result["countries"] = sorted({country_key(value) for value in result["countries"]})
    return result


def get_config(state):
    result = validate_config(json.loads(state.get_meta("capture_config", "{}")))
    result["ports"] = [row[0] for row in state.conn.execute(
        "SELECT f.lport FROM capture_ports c JOIN forward_rules f ON f.id=c.rule_id ORDER BY f.lport")]
    return result
