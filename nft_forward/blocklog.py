from __future__ import annotations

import subprocess
import time

from .config import load_settings
from .constants import LOG_PREFIX
from .relay import record_block_line


def run() -> None:
    settings = load_settings()
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-kf", "-o", "cat"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                if LOG_PREFIX in line:
                    record_block_line(settings, line)
        except (OSError, AssertionError):
            time.sleep(10)
        except Exception:
            time.sleep(5)
