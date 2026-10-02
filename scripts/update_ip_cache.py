#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from nft_forward.config import Settings, default_paths
from nft_forward.geo_database import build_database, database_path, fetch_source, install_database


def main() -> int:
    settings = Settings(paths=default_paths(ROOT))
    directory = database_path(settings).parent
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".geo-build-", dir=directory) as temporary:
        source, metadata = fetch_source(Path(temporary))
        candidate = Path(temporary) / "geoip.db"
        build_database(source, candidate, metadata)
        print(json.dumps(install_database(settings, candidate), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
