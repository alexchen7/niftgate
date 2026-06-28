from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nft_forward.config import Settings, default_paths
from nft_forward.relay import record_block_line
from nft_forward.state import State


class RepairStormTests(unittest.TestCase):
    def tempdir(self):
        root = Path(os.environ.get("NFT_FORWARD_TEST_TMP", str(Path.cwd() / ".tmp-tests")))
        root.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root)

    def test_block_log_stale_live_repair_is_throttled(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            paths.audit_log = Path(td) / "audit.jsonl"
            paths.nft_conf = Path(td) / "port-forward.conf"
            settings = Settings(paths=paths)
            state = State(paths.state_db, paths.audit_log)
            state.add_rule(24678, "203.0.113.20", 24678)
            state.add_allow("public", "39.144.55.0/24", "ssh_login", 24)
            state.close()

            line = "SRC=39.144.55.66 DST=10.100.129.161 PROTO=TCP SPT=9742 DPT=24678"
            with patch("nft_forward.relay.write_and_apply", return_value="ok") as apply:
                self.assertTrue(record_block_line(settings, line))
                self.assertTrue(record_block_line(settings, line))

            apply.assert_called_once()
            state = State(paths.state_db)
            self.assertEqual(state.blocked(limit=10), [])
            self.assertEqual(state.get_meta("apply_pending"), "0")
            state.close()
            self.assertIn("stale_live_repair_throttled", paths.audit_log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
