from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def now_ts() -> int:
    return int(time.time())


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    ensure_parent(path)
    event = {"ts": now_ts(), **event}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
