from __future__ import annotations

import os
import json
import subprocess
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from nft_forward.config import Settings, clean_secret_path, default_paths, load_settings
from nft_forward.cli import export_payload, main as cli_main, migrate_secret_path
from nft_forward.geo import GeoInfo, GeoLookup
from nft_forward.iputil import collapse_sources_for_nft, normalize_ip, normalize_network, normalize_sources
from nft_forward.legacy import import_legacy_conf
from nft_forward.nft import render_nft, validate_nft, write_and_apply
from nft_forward.phone_server import _RECENT_HITS, _RECENT_HITS_LOCK, accept_hit, source_ip_for_request
from nft_forward.relay import ingest_source, record_block_line, retry_pending_apply, sync_ddns
from nft_forward.sshutil import build_ssh_command, ssh_command
from nft_forward.state import State


class CoreTests(unittest.TestCase):
    def tempdir(self):
        root = Path(os.environ.get("NFT_FORWARD_TEST_TMP", str(Path.cwd() / ".tmp-tests")))
        root.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root)

    def test_ip_normalization(self) -> None:
        self.assertEqual(normalize_network("1.2.3.4").text, "1.2.3.4/32")
        self.assertEqual(normalize_network("1.2.3.4", host_policy=24).text, "1.2.3.0/24")
        with self.assertRaises(ValueError):
            normalize_ip("2001:db8::1")
        self.assertEqual(normalize_network("10.0.0.1-10.0.0.20").text, "10.0.0.1-10.0.0.20")
        with self.assertRaises(ValueError):
            normalize_network("10.0.0.20-10.0.0.1")

    def test_multi_sources(self) -> None:
        values = [x.text for x in normalize_sources("1.1.1.1, 2.2.2.0/24")]
        self.assertEqual(values, ["1.1.1.1/32", "2.2.2.0/24"])

    def test_collapse_sources_for_nft_removes_overlaps(self) -> None:
        sources = collapse_sources_for_nft(["82.40.32.0/24", "82.40.32.151/32", "198.51.100.1-198.51.100.2"])
        self.assertEqual(sources, ["82.40.32.0/24", "198.51.100.1/32", "198.51.100.2/32"])

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
            self.assertIn("    chain source_guard {\n", text)
            self.assertNotIn("type filter hook prerouting", text)
            self.assertIn("        jump source_guard", text)
            self.assertIn("ip saddr @src_60001 tcp dport 60001 dnat", text)
            state.close()

    def test_render_collapses_overlapping_source_set(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            settings = Settings(paths=paths)
            state = State(paths.state_db)
            state.add_rule(24680, "203.0.113.10", 24678)
            state.add_allow("public", "82.40.32.0/24", "manual", 24)
            state.add_allow("public", "82.40.32.151/32", "manual", 32)
            text = render_nft(settings, state)
            self.assertIn("82.40.32.0/24", text)
            self.assertNotIn("82.40.32.151/32", text)
            state.close()

    def test_validate_uses_temporary_table_name(self) -> None:
        checked: dict[str, str] = {}

        def fake_run(cmd, text, capture_output, timeout):  # noqa: ANN001
            checked["body"] = Path(cmd[-1]).read_text(encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        nft_text = "table ip nft_forward {\n    set src_1935 { type ipv4_addr; flags interval; elements = { 82.40.32.151/32 } }\n}\n"
        with patch("nft_forward.nft.shutil.which", return_value="/usr/sbin/nft"), patch("nft_forward.nft.subprocess.run", fake_run):
            ok, _ = validate_nft(nft_text)
        self.assertTrue(ok)
        self.assertIn("table ip nft_forward_check_", checked["body"])
        self.assertNotIn("table ip nft_forward {", checked["body"])

    def test_apply_removes_legacy_live_table(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            paths.nft_conf = Path(td) / "port-forward.conf"
            settings = Settings(paths=paths)
            state = State(paths.state_db)
            calls: list[list[str]] = []
            apply_batches: list[str] = []

            def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
                calls.append(list(cmd))
                if list(cmd[:2]) == ["nft", "-f"]:
                    apply_batches.append(Path(cmd[-1]).read_text(encoding="utf-8"))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with patch("nft_forward.nft.shutil.which", return_value="/usr/sbin/nft"), patch("nft_forward.nft.subprocess.run", fake_run):
                write_and_apply(settings, state, apply=True)
            self.assertIn(["nft", "delete", "table", "ip", "port_forward"], calls)
            self.assertIn(["nft", "list", "table", "ip", "nft_forward"], calls)
            self.assertNotIn(["nft", "flush", "table", "ip", "nft_forward"], calls)
            self.assertTrue(any(batch.startswith("delete table ip nft_forward\n") for batch in apply_batches))
            state.close()

    def test_ingest_marks_pending_apply_on_reload_failure(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            paths.audit_log = Path(td) / "audit.jsonl"
            paths.nft_conf = Path(td) / "port-forward.conf"
            settings = Settings(paths=paths)

            with patch("nft_forward.relay.GeoLookup.lookup", return_value=GeoInfo()), patch(
                "nft_forward.relay.write_and_apply", side_effect=RuntimeError("reload failed")
            ):
                with self.assertRaises(RuntimeError):
                    ingest_source(settings, "ssh_login", "198.51.100.8", apply_rules=True)

            state = State(paths.state_db)
            self.assertEqual(state.get_meta("apply_pending"), "1")
            self.assertEqual(state.active_allow_entries()[0].source, "198.51.100.0/24")
            state.close()

    def test_retry_pending_apply_clears_marker_on_success(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            paths.audit_log = Path(td) / "audit.jsonl"
            paths.nft_conf = Path(td) / "port-forward.conf"
            settings = Settings(paths=paths)
            state = State(paths.state_db, paths.audit_log)
            state.set_meta("apply_pending", "1")
            state.close()

            with patch("nft_forward.relay.write_and_apply", return_value="ok"):
                self.assertTrue(retry_pending_apply(settings))

            state = State(paths.state_db)
            self.assertEqual(state.get_meta("apply_pending"), "0")
            state.close()

    def test_add_allow_duplicate_active_source_does_not_request_apply(self) -> None:
        with self.tempdir() as td:
            state = State(Path(td) / "state.db")
            self.assertTrue(state.add_allow("public", "198.51.100.0/24", "ddns", 24, note="DDNS home.example.com"))
            self.assertFalse(state.add_allow("public", "198.51.100.0/24", "ddns", 24, note="DDNS home.example.com"))
            self.assertEqual([entry.source for entry in state.active_allow_entries()], ["198.51.100.0/24"])
            state.close()

    def test_sync_ddns_skips_nft_apply_when_source_already_active(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            paths.audit_log = Path(td) / "audit.jsonl"
            paths.nft_conf = Path(td) / "port-forward.conf"
            paths.config_file = Path(td) / "config.json"
            paths.config_file.write_text(
                json.dumps(
                    {
                        "paths": {
                            "state_db": str(paths.state_db),
                            "audit_log": str(paths.audit_log),
                            "nft_conf": str(paths.nft_conf),
                        },
                        "ddns": [{"host": "home.example.com", "ruleset": "public", "enabled": True}],
                    }
                ),
                encoding="utf-8",
            )
            settings = load_settings(paths.config_file)
            addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("198.51.100.8", 0))]

            with patch("nft_forward.relay.socket.getaddrinfo", return_value=addrinfo), patch(
                "nft_forward.relay.GeoLookup.lookup", return_value=GeoInfo(geo="Testland", isp="Test ISP")
            ), patch("nft_forward.relay.write_and_apply", return_value="ok") as apply:
                self.assertEqual(sync_ddns(settings), 1)
                self.assertEqual(sync_ddns(settings), 0)

            apply.assert_called_once()
            state = State(paths.state_db)
            entries = state.active_allow_entries()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].source, "198.51.100.0/24")
            state.close()

    def test_block_log_repairs_stale_live_when_state_allows(self) -> None:
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

            apply.assert_called_once()
            state = State(paths.state_db)
            self.assertEqual(state.blocked(limit=10), [])
            self.assertEqual(state.get_meta("apply_pending"), "0")
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

    def test_exit_queue_deduplicates_matching_payloads(self) -> None:
        with self.tempdir() as td:
            state = State(Path(td) / "state.db")
            state.enqueue("ingest", {"ip": "198.51.100.10", "channel": "web", "ruleset": "public"})
            state.enqueue("ingest", {"ruleset": "public", "channel": "web", "ip": "198.51.100.10"})
            count = state.conn.execute("SELECT count(*) FROM exit_queue").fetchone()[0]
            self.assertEqual(count, 1)
            state.close()

    def test_secret_url_hit_throttle(self) -> None:
        with _RECENT_HITS_LOCK:
            _RECENT_HITS.clear()
        self.assertTrue(accept_hit(1, "198.51.100.10"))
        self.assertFalse(accept_hit(1, "198.51.100.10"))
        self.assertTrue(accept_hit(1, "198.51.100.11"))

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

    def test_ssh_command_retries_transient_kex_close(self) -> None:
        with self.tempdir() as td:
            password = Path(td) / "pass"
            password.write_text("secret\n", encoding="utf-8")
            calls = 0

            def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
                nonlocal calls
                calls += 1
                if calls == 1:
                    return subprocess.CompletedProcess(
                        cmd,
                        255,
                        "",
                        "kex_exchange_identification: Connection closed by remote host\n",
                    )
                return subprocess.CompletedProcess(cmd, 0, "ok\n", "")

            with patch("nft_forward.sshutil.subprocess.run", fake_run), patch("nft_forward.sshutil.time.sleep"):
                result = ssh_command(
                    "relay.local",
                    "root",
                    22,
                    "",
                    ["nft.sh", "bot-status"],
                    auth_method="password",
                    password_file=str(password),
                )
            self.assertTrue(result.ok)
            self.assertEqual(result.stdout, "ok\n")
            self.assertEqual(calls, 2)

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
                json.dumps({"paths": {"state_db": str(state_db), "audit_log": str(Path(td) / "audit.jsonl")}, "ddns": []}),
                encoding="utf-8",
            )
            self.assertEqual(
                cli_main(["--config", str(cfg), "ddns", "add", "mobile.example.com", "--ruleset", "public"]),
                0,
            )
            data = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(data["ddns"], [{"id": 1, "host": "mobile.example.com", "ruleset": "public", "enabled": True}])

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
            cfg.write_text(
                json.dumps({"paths": {"state_db": str(state_db), "audit_log": str(Path(td) / "audit.jsonl")}}),
                encoding="utf-8",
            )

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
            cfg.write_text(
                json.dumps({"paths": {"state_db": str(state_db), "audit_log": str(Path(td) / "audit.jsonl")}}),
                encoding="utf-8",
            )
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

    def test_ruleset_create_and_delete_cleans_references(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(
                json.dumps(
                    {
                        "paths": {"state_db": str(state_db), "audit_log": str(Path(td) / "audit.jsonl")},
                        "ddns": [{"host": "mobile.example.com", "ruleset": "office", "enabled": True}],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                cli_main(["--config", str(cfg), "ruleset", "create", "office", "--note", "work exits"]),
                0,
            )
            state = State(state_db)
            state.add_rule(58495, "203.0.113.20", 58495, rulesets=["office"])
            state.add_allow("office", "198.51.100.0/24", "manual", 24)
            state.create_secret_url("office-secret", ruleset="office", label="office")
            state.close()

            self.assertEqual(cli_main(["--config", str(cfg), "ruleset", "delete", "office", "--no-apply"]), 0)
            data = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(data["ddns"], [])
            state = State(state_db)
            self.assertNotIn("office", [row["name"] for row in state.rulesets()])
            rule = state.rule_by_lport(58495)
            self.assertEqual(rule.rulesets, [])
            self.assertEqual(state.all_allow_entries(), [])
            self.assertEqual(state.secret_urls(), [])
            state.close()

    def test_public_ruleset_cannot_be_deleted(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(
                json.dumps({"paths": {"state_db": str(state_db), "audit_log": str(Path(td) / "audit.jsonl")}}),
                encoding="utf-8",
            )
            self.assertEqual(cli_main(["--config", str(cfg), "ruleset", "delete", "public", "--no-apply"]), 1)


    def test_generated_or_existing_legacy_rule_cannot_downgrade_restriction(self) -> None:
        with self.tempdir() as td:
            state = State(Path(td) / "state.db")
            state.add_rule(58495, "203.0.113.10", 58495, open_access=False)
            generated = Path(td) / "generated.conf"
            generated.write_text(
                "# Generated by nft-forward. Do not edit by hand.\n"
                "tcp dport 58495 dnat to 203.0.113.20:58495\n",
                encoding="utf-8",
            )
            self.assertEqual(import_legacy_conf(generated, state), 0)
            legacy = Path(td) / "legacy.conf"
            legacy.write_text("tcp dport 58495 dnat to 203.0.113.30:58495\n", encoding="utf-8")
            self.assertEqual(import_legacy_conf(legacy, state), 0)
            rule = state.rule_by_lport(58495)
            self.assertFalse(rule.open_access)
            self.assertEqual(rule.dest_ip, "203.0.113.10")
            state.close()

    def test_guard_logging_is_limited_but_drop_is_unconditional(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.state_db = Path(td) / "state.db"
            state = State(paths.state_db)
            state.add_rule(60001, "203.0.113.10", 60001)
            text = render_nft(Settings(paths=paths), state)
            self.assertIn("tcp dport 60001 limit rate 12/minute", text)
            self.assertIn("tcp dport 60001 drop", text)
            self.assertNotIn('log prefix "nft-forward-block port=60001 " drop', text)
            self.assertIn("ct status dnat masquerade", text)
            self.assertNotIn("LOCAL_IP", text)
            state.close()

    def test_geo_complete_cache_does_not_call_exit(self) -> None:
        with self.tempdir() as td:
            paths = default_paths(Path(td))
            paths.ip_cache = Path(td) / "iplist"
            (paths.ip_cache / "country").mkdir(parents=True)
            (paths.ip_cache / "isp").mkdir(parents=True)
            (paths.ip_cache / "country" / "CN.txt").write_text("198.51.100.0/24\n", encoding="utf-8")
            (paths.ip_cache / "isp" / "chinamobile.txt").write_text("198.51.100.0/24\n", encoding="utf-8")
            lookup = GeoLookup(Settings(paths=paths, exit_host="exit.example.com"))
            with patch.object(lookup, "lookup_via_exit", side_effect=AssertionError("unexpected SSH fallback")):
                info = lookup.lookup("198.51.100.42")
            self.assertEqual(info.geo, "China")
            self.assertEqual(info.isp, "China Mobile")
            self.assertEqual(info.source, "cache")

    def test_phone_source_ip_only_trusts_local_proxy_and_validates_ipv4(self) -> None:
        local = SimpleNamespace(client_address=("127.0.0.1", 1234), headers={"X-Real-IP": "198.51.100.9"})
        self.assertEqual(source_ip_for_request(local, "127.0.0.1"), "198.51.100.9")
        local.headers["X-Real-IP"] = "not-an-ip"
        self.assertIsNone(source_ip_for_request(local, "127.0.0.1"))
        public = SimpleNamespace(
            client_address=("203.0.113.7", 1234),
            headers={"X-Real-IP": "198.51.100.9", "X-Forwarded-For": "192.0.2.1"},
        )
        self.assertEqual(source_ip_for_request(public, "0.0.0.0"), "203.0.113.7")

    def test_exit_queue_discards_entries_after_retry_cap(self) -> None:
        with self.tempdir() as td:
            state = State(Path(td) / "state.db")
            state.enqueue("ingest", {"ip": "bad"})
            row = state.due_queue()[0]
            state.conn.execute("UPDATE exit_queue SET attempts=99 WHERE id=?", (row["id"],))
            state.conn.commit()
            self.assertFalse(state.retry_queue(row["id"]))
            self.assertEqual(state.conn.execute("SELECT COUNT(*) FROM exit_queue").fetchone()[0], 0)
            state.close()

    def test_ddns_change_removes_previous_network(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(
                json.dumps(
                    {
                        "paths": {
                            "state_db": str(state_db),
                            "audit_log": str(Path(td) / "audit.jsonl"),
                            "nft_conf": str(Path(td) / "port-forward.conf"),
                        },
                        "ddns": [{"id": 1, "host": "home.example.com", "ruleset": "public", "enabled": True}],
                    }
                ),
                encoding="utf-8",
            )
            settings_obj = load_settings(cfg)
            answers = [
                [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("198.51.100.10", 0))],
                [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0))],
            ]
            with patch("nft_forward.relay.socket.getaddrinfo", side_effect=answers), patch(
                "nft_forward.relay.GeoLookup.lookup", return_value=GeoInfo()
            ), patch("nft_forward.relay.write_and_apply", return_value="ok"):
                self.assertEqual(sync_ddns(settings_obj), 1)
                self.assertEqual(sync_ddns(settings_obj), 2)
            state = State(state_db)
            rows = [entry.source for entry in state.active_allow_entries()]
            self.assertEqual(rows, ["203.0.113.0/24"])
            state.close()

    def test_remove_plain_ip_matches_dynamic_prefix(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(json.dumps({"paths": {"state_db": str(state_db)}}), encoding="utf-8")
            state = State(state_db)
            state.add_allow("public", "198.51.100.0/24", "ddns", 24)
            state.close()
            self.assertEqual(
                cli_main(
                    [
                        "--config",
                        str(cfg),
                        "remove-allow",
                        "198.51.100.42",
                        "--ruleset",
                        "public",
                        "--channel",
                        "ddns",
                        "--no-apply",
                    ]
                ),
                0,
            )
            state = State(state_db)
            self.assertEqual(state.all_allow_entries(), [])
            state.close()

    def test_allow_upsert_updates_prefix_and_rule_note_is_single_line(self) -> None:
        with self.tempdir() as td:
            state = State(Path(td) / "state.db")
            state.add_allow("public", "198.51.100.0/24", "manual", 24)
            state.add_allow("public", "198.51.100.0/24", "manual", 32)
            self.assertEqual(state.all_allow_entries()[0].prefix_len, 32)
            state.add_rule(60001, "203.0.113.10", 60001, note="line one\nadd table ip bad")
            self.assertEqual(state.rule_by_lport(60001).note, "line one add table ip bad")
            state.close()

    def test_import_rejects_reserved_port_before_replace(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            state_db = Path(td) / "state.db"
            cfg.write_text(json.dumps({"paths": {"state_db": str(state_db)}}), encoding="utf-8")
            state = State(state_db)
            state.add_rule(60001, "203.0.113.10", 60001)
            state.close()
            payload = Path(td) / "import.json"
            payload.write_text(
                json.dumps({"forward_rules": [{"lport": 80, "dest_ip": "203.0.113.20", "dest_port": 80}]}),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                cli_main(["--config", str(cfg), "import", str(payload), "--replace"])
            state = State(state_db)
            self.assertIsNotNone(state.rule_by_lport(60001))
            self.assertIsNone(state.rule_by_lport(80))
            state.close()


    def test_ddns_ids_remain_stable_after_deletion(self) -> None:
        with self.tempdir() as td:
            cfg = Path(td) / "config.json"
            cfg.write_text(json.dumps({"paths": {"state_db": str(Path(td) / "state.db")}}), encoding="utf-8")
            self.assertEqual(cli_main(["--config", str(cfg), "ddns", "add", "one.example.com"]), 0)
            self.assertEqual(cli_main(["--config", str(cfg), "ddns", "add", "two.example.com"]), 0)
            self.assertEqual(cli_main(["--config", str(cfg), "ddns", "delete", "1", "--no-apply"]), 0)
            rows = json.loads(cfg.read_text(encoding="utf-8"))["ddns"]
            self.assertEqual(rows, [{"id": 2, "host": "two.example.com", "ruleset": "public", "enabled": True}])


if __name__ == "__main__":
    unittest.main()
