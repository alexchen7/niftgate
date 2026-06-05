from __future__ import annotations

import os
import json
import tempfile
import unittest
from pathlib import Path

from nft_forward.config import Settings, clean_secret_path, default_paths, load_settings
from nft_forward.cli import export_payload, migrate_secret_path
from nft_forward.geo import GeoLookup
from nft_forward.iputil import normalize_network, normalize_sources
from nft_forward.nft import render_nft
from nft_forward.sshutil import build_ssh_command
from nft_forward.state import State


class CoreTests(unittest.TestCase):
    def tempdir(self):
        root = Path(os.environ.get("NFT_FORWARD_TEST_TMP", str(Path.cwd() / ".tmp-tests")))
        root.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root)

    def test_ip_normalization(self) -> None:
        self.assertEqual(normalize_network("1.2.3.4").text, "1.2.3.4/32")
        self.assertEqual(normalize_network("1.2.3.4", host_policy=24).text, "1.2.3.0/24")
        self.assertEqual(normalize_network("10.0.0.1-10.0.0.20").text, "10.0.0.1-10.0.0.20")
        with self.assertRaises(ValueError):
            normalize_network("10.0.0.20-10.0.0.1")

    def test_multi_sources(self) -> None:
        values = [x.text for x in normalize_sources("1.1.1.1, 2.2.2.0/24")]
        self.assertEqual(values, ["1.1.1.1/32", "2.2.2.0/24"])

    def test_render_closed_until_allowed(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            settings = Settings(paths=paths)
            state = State(paths.state_db)
            state.add_rule(60001, "203.0.113.10", 60001)
            text = render_nft(settings, state)
            self.assertIn("当前没有有效允许来源", text)
            self.assertIn("tcp dport 60001", text)
            state.close()

    def test_render_allowed_source_set(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            settings = Settings(paths=paths)
            state = State(paths.state_db)
            state.add_rule(60001, "203.0.113.10", 60001)
            state.add_allow("public", "198.51.100.0/24", "manual", 24)
            text = render_nft(settings, state)
            self.assertIn("set src_60001", text)
            self.assertIn("ip saddr @src_60001 tcp dport 60001 dnat", text)
            state.close()

    def test_geo_cache_merges_geo_and_isp(self) -> None:
        with self.tempdir() as td:
            root = Path(td)
            paths = default_paths(root)
            paths.ip_cache = root / "iplist"
            (paths.ip_cache / "country").mkdir(parents=True)
            (paths.ip_cache / "cncity").mkdir(parents=True)
            (paths.ip_cache / "isp").mkdir(parents=True)
            (paths.ip_cache / "country" / "CN.txt").write_text("223.0.0.0/8\n", encoding="utf-8")
            (paths.ip_cache / "cncity" / "440300.txt").write_text("223.104.80.0/24\n", encoding="utf-8")
            (paths.ip_cache / "isp" / "chinamobile.txt").write_text("223.104.80.0/24\n", encoding="utf-8")
            info = GeoLookup(Settings(paths=paths)).lookup_local("223.104.80.1")
            self.assertEqual(info.geo, "China/Guangdong/Shenzhen")
            self.assertEqual(info.isp, "China Mobile")

    def test_secret_url_create_delete_and_export_redaction(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            settings = Settings(paths=paths)
            state = State(paths.state_db)
            state.create_secret_url("super-secret", ruleset="public", label="main")
            self.assertIsNotNone(state.secret_url_by_path("super-secret"))
            public_payload = export_payload(settings, include_secrets=False)
            private_payload = export_payload(settings, include_secrets=True)
            self.assertNotIn("secret_path", public_payload["secret_urls"][0])
            self.assertEqual(private_payload["secret_urls"][0]["secret_path"], "super-secret")
            self.assertEqual(state.delete_secret_urls([1]), 1)
            self.assertIsNone(state.secret_url_by_path("super-secret"))
            state.close()

    def test_placeholder_secret_path_is_not_migrated(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            cfg = Path(td) / "config.json"
            cfg.write_text(
                json.dumps({"paths": {"state_db": str(paths.state_db)}, "phone": {"secret_path": "replace-with-long-random-secret"}}),
                encoding="utf-8",
            )
            settings = load_settings(cfg)
            state = State(paths.state_db)
            self.assertEqual(clean_secret_path("replace-with-long-random-secret"), "")
            self.assertEqual(settings.phone_secret_path, "")
            migrate_secret_path(settings, state)
            self.assertEqual(state.secret_urls(), [])
            state.close()

    def test_ssh_command_builder_supports_password_file(self) -> None:
        with self.tempdir() as td:
            password = Path(td) / "pass"
            password.write_text("secret\n", encoding="utf-8")
            cmd = build_ssh_command(
                "relay.local",
                "root",
                2222,
                "",
                ["nft.sh", "status"],
                auth_method="password",
                password_file=str(password),
            )
            self.assertEqual(cmd[:3], ["sshpass", "-f", str(password)])
            self.assertIn("BatchMode=no", cmd)
            self.assertEqual(cmd[-2:], ["nft.sh", "status"])


if __name__ == "__main__":
    unittest.main()
