from __future__ import annotations

import os
import json
import tempfile
import unittest
from pathlib import Path

from nft_forward.config import Settings, clean_secret_path, default_paths, load_settings
from nft_forward.cli import export_payload, main as cli_main, migrate_secret_path
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

    def test_pair_relay_updates_only_relay_settings(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "role": "exit",
                        "paths": {"state_db": str(Path(td) / "state.db")},
                        "ssh": {"relay_host": "old", "relay_user": "root", "relay_port": 22},
                        "phone": {"public_host": "example.test", "public_port": 18443},
                    }
                ),
                encoding="utf-8",
            )
            password_file = Path(td) / "relay_password"
            self.assertEqual(
                cli_main(
                    [
                        "--config",
                        str(cfg),
                        "pair-relay",
                        "--host",
                        "10.0.0.2",
                        "--user",
                        "admin",
                        "--port",
                        "2222",
                        "--auth-method",
                        "password",
                        "--password-file",
                        str(password_file),
                        "--timeout",
                        "9",
                        "--no-restart",
                    ]
                ),
                0,
            )
            data = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(data["ssh"]["relay_host"], "10.0.0.2")
            self.assertEqual(data["ssh"]["relay_user"], "admin")
            self.assertEqual(data["ssh"]["relay_port"], 2222)
            self.assertEqual(data["ssh"]["relay_auth_method"], "password")
            self.assertEqual(data["ssh"]["relay_password_file"], str(password_file))
            self.assertEqual(data["ssh"]["timeout"], 9)
            self.assertEqual(data["phone"]["public_host"], "example.test")

    def test_ddns_cli_add_delete_cleans_ddns_allow_entries(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(
                json.dumps({"paths": {"state_db": str(state_db)}, "ddns": []}),
                encoding="utf-8",
            )
            self.assertEqual(
                cli_main(["--config", str(cfg), "ddns", "add", "mobile.example.com", "--ruleset", "public"]),
                0,
            )
            data = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(data["ddns"], [{"host": "mobile.example.com", "ruleset": "public", "enabled": True}])

            state = State(state_db)
            state.add_allow("public", "198.51.100.0/24", "ddns", 24, note="DDNS mobile.example.com")
            state.close()

            self.assertEqual(cli_main(["--config", str(cfg), "ddns", "delete", "1", "--no-apply"]), 0)
            data = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(data["ddns"], [])
            state = State(state_db)
            self.assertEqual(state.all_allow_entries(), [])
            state.close()

    def test_edit_rule_cli_updates_existing_rule_fields(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(json.dumps({"paths": {"state_db": str(state_db)}}), encoding="utf-8")

            self.assertEqual(
                cli_main(
                    [
                        "--config",
                        str(cfg),
                        "add-rule",
                        "58495",
                        "203.0.113.20",
                        "58495",
                        "--ruleset",
                        "ddns",
                        "--note",
                        "old note",
                        "--no-apply",
                    ]
                ),
                0,
            )
            self.assertEqual(
                cli_main(
                    [
                        "--config",
                        str(cfg),
                        "edit-rule",
                        "58495",
                        "--open",
                        "--no-public",
                        "--ruleset",
                        "office",
                        "--note",
                        "new note",
                        "--no-apply",
                    ]
                ),
                0,
            )
            state = State(state_db)
            rule = state.rule_by_lport(58495)
            self.assertIsNotNone(rule)
            self.assertEqual(rule.dest_ip, "203.0.113.20")
            self.assertEqual(rule.dest_port, 58495)
            self.assertEqual(rule.note, "new note")
            self.assertEqual(rule.rulesets, ["office"])
            self.assertFalse(rule.include_public)
            self.assertTrue(rule.open_access)
            state.close()

            self.assertEqual(
                cli_main(
                    [
                        "--config",
                        str(cfg),
                        "edit-rule",
                        "58495",
                        "--restricted",
                        "--public",
                        "--clear-rulesets",
                        "--clear-note",
                        "--no-apply",
                    ]
                ),
                0,
            )
            state = State(state_db)
            rule = state.rule_by_lport(58495)
            self.assertEqual(rule.note, "")
            self.assertEqual(rule.rulesets, [])
            self.assertTrue(rule.include_public)
            self.assertFalse(rule.open_access)
            state.close()

    def test_remove_allow_by_source_from_ruleset(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(json.dumps({"paths": {"state_db": str(state_db)}}), encoding="utf-8")
            state = State(state_db)
            state.add_allow("ddns", "198.51.100.0/24", "manual", 24, note="home")
            state.add_allow("public", "198.51.100.0/24", "manual", 24, note="public")
            state.close()

            self.assertEqual(
                cli_main(
                    [
                        "--config",
                        str(cfg),
                        "remove-allow",
                        "198.51.100.42",
                        "--ruleset",
                        "ddns",
                        "--prefix",
                        "24",
                        "--no-apply",
                    ]
                ),
                0,
            )
            state = State(state_db)
            rows = state.all_allow_entries()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].ruleset, "public")
            state.close()


if __name__ == "__main__":
    unittest.main()
