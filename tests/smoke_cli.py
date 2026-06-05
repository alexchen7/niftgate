from __future__ import annotations

import json
import pathlib
import shutil
import subprocess


def main() -> int:
    root = pathlib.Path(".tmp-smoke")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    cfg = root / "config.json"
    data = json.load(open("config/config.example.json", encoding="utf-8"))
    data["paths"]["state_db"] = str(root / "state.db")
    data["paths"]["nft_conf"] = str(root / "port-forward.conf")
    data["paths"]["audit_log"] = str(root / "audit.jsonl")
    data["paths"]["blocked_log"] = str(root / "blocked.jsonl")
    data["paths"]["ip_cache"] = str(pathlib.Path("cache/iplist").resolve())
    json.dump(data, open(cfg, "w", encoding="utf-8"), indent=2)
    commands = [
        ["./nft.sh", "--config", str(cfg), "init-db"],
        ["./nft.sh", "--config", str(cfg), "add-rule", "60001", "203.0.113.10", "60001", "--no-apply"],
        ["./nft.sh", "--config", str(cfg), "allow", "198.51.100.23", "--prefix", "24", "--no-apply"],
        ["./nft.sh", "--config", str(cfg), "apply", "--print"],
    ]
    rendered = ""
    for cmd in commands:
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode != 0:
            raise SystemExit(proc.stderr or proc.stdout)
        rendered = proc.stdout
    if "set src_60001" not in rendered:
        raise SystemExit("rendered nft config did not include expected source set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
