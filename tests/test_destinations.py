from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import sqlite3
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from nft_forward import telegram_bot
from nft_forward.cli import export_payload, main
from nft_forward.config import load_settings
from nft_forward.destination import normalize_destination, resolve_ipv4
from nft_forward.destination_sync import sync_destinations
from nft_forward.nft import render_nft, write_and_apply
from nft_forward.sshutil import build_ssh_command
from nft_forward.state import State


class DestinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = self.root / "config.json"
        self.cfg.write_text(json.dumps({"paths": {
            "state_db": str(self.root / "state.db"),
            "audit_log": str(self.root / "audit.jsonl"),
            "nft_conf": str(self.root / "forward.conf"),
        }}), encoding="utf-8")
        self.settings = load_settings(self.cfg)
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        telegram_bot.PENDING_ACTIONS.clear()

    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(["--config", str(self.cfg), *args])

    def rule(self, port=58001):
        state = State(self.settings.paths.state_db)
        try:
            return state.rule_by_lport(port)
        finally:
            state.close()

    def add_hostname(self, port=58001, host="exit.example.com"):
        with patch("nft_forward.destination.resolve_ipv4", return_value=["192.0.2.1"]):
            self.assertEqual(self.cli("add-rule", str(port), host, "58002", "--note", "keep me",
                                      "--ruleset", "custom", "--no-public", "--no-apply"), 0)

    def test_url_parsing_and_rejected_destinations(self):
        self.assertEqual(normalize_destination("https://Exit.Example.com:9443/path?q=x"), "exit.example.com")
        self.assertEqual(normalize_destination("Exit.Example.com."), "exit.example.com")
        self.assertEqual(normalize_destination("192.0.2.1"), "192.0.2.1")
        for value in ("", "999.1.1.1", "2001:db8::1", "https://[::1]/", "x;reboot", "a\nb",
                      "https://user:secret@example.com", "ftp://example.com", "a..b", "-host", "http://x:bad", "a" * 64 + ".com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_destination(value)

    def test_resolver_timeout_and_invalid_answer(self):
        with patch("nft_forward.destination.subprocess.run", side_effect=subprocess.TimeoutExpired("lookup", 5)):
            with self.assertRaisesRegex(ValueError, "DNS lookup failed"):
                resolve_ipv4("exit.example.com")
        for answer in ("[]", '["::1"]', '{}', 'null'):
            with patch("nft_forward.destination.subprocess.run", return_value=subprocess.CompletedProcess([], 0, answer, "")):
                with self.assertRaises(ValueError):
                    resolve_ipv4("exit.example.com")

    def test_old_database_migrates_without_changing_rules(self):
        db = self.root / "old.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE forward_rules (id INTEGER PRIMARY KEY, lport INTEGER UNIQUE, dest_ip TEXT, "
                     "dest_port INTEGER, note TEXT, rulesets TEXT, include_public INTEGER, open_access INTEGER)")
        conn.execute("INSERT INTO forward_rules VALUES (7,58001,'192.0.2.1',58002,'keep','[\"custom\"]',0,0)")
        conn.commit()
        conn.close()
        state = State(db)
        rule = state.rules()[0]
        self.assertEqual((rule.id, rule.dest_host, rule.dest_ip, rule.note, rule.rulesets, rule.include_public),
                         (7, "", "192.0.2.1", "keep", ["custom"], False))
        state.close()
        State(db).close()

    def test_port_edit_preserves_identity_and_policy_and_removes_old_port(self):
        self.add_hostname()
        before = self.rule()
        self.assertEqual(self.cli("edit-rule", "58001", "--new-lport", "58003", "--dest-port", "58004", "--no-apply"), 0)
        self.assertIsNone(self.rule())
        after = self.rule(58003)
        self.assertEqual((after.id, after.rulesets, after.note, after.include_public, after.open_access, after.dest_host),
                         (before.id, before.rulesets, before.note, False, False, before.dest_host))
        state = State(self.settings.paths.state_db)
        state.add_allow("custom", "198.51.100.1/32", "manual", 32)
        rendered = render_nft(self.settings, state)
        state.close()
        self.assertNotIn("58001", rendered)
        self.assertIn("dnat to 192.0.2.1:58004", rendered)
        self.assertIn("src_58003", rendered)
        self.assertNotIn("exit.example.com", rendered)

    def test_invalid_or_duplicate_ports_leave_both_rules_unchanged(self):
        self.add_hostname()
        self.assertEqual(self.cli("add-rule", "58003", "192.0.2.2", "58003", "--no-apply"), 0)
        before = self.rule()
        for port in ("0", "65536", "80", "443", "8080", "8443", "58003"):
            self.assertEqual(self.cli("edit-rule", "58001", "--new-lport", port, "--no-apply"), 1)
            self.assertEqual(self.rule(), before)
        self.assertEqual(self.rule(58003).dest_ip, "192.0.2.2")
        for port in ("0", "65536"):
            self.assertEqual(self.cli("edit-rule", "58001", "--dest-port", port, "--no-apply"), 1)

    def test_dns_failure_on_edit_and_nft_failure_roll_back_rule_and_file(self):
        self.add_hostname()
        before = self.rule()
        with patch("nft_forward.destination.resolve_ipv4", side_effect=ValueError("timeout")):
            self.assertEqual(self.cli("edit-rule", "58001", "--dest-ip", "other.example.com"), 1)
        self.assertEqual(self.rule(), before)
        self.settings.paths.nft_conf.write_text("existing", encoding="utf-8")
        with patch("nft_forward.nft.validate_nft", return_value=(False, "invalid")):
            self.assertEqual(self.cli("edit-rule", "58001", "--new-lport", "58003"), 1)
        self.assertEqual(self.rule(), before)
        self.assertIsNone(self.rule(58003))
        self.assertEqual(self.settings.paths.nft_conf.read_text(), "existing")
        state = State(self.settings.paths.state_db)
        with patch("nft_forward.nft.validate_nft", return_value=(True, "")), patch("nft_forward.nft.shutil.which", return_value="nft"), \
             patch("nft_forward.nft.table_exists", return_value=True), \
             patch("nft_forward.nft.run_nft_batch", return_value=subprocess.CompletedProcess([], 1, "", "failed")):
            with self.assertRaises(RuntimeError):
                write_and_apply(self.settings, state)
        state.close()
        self.assertEqual(self.settings.paths.nft_conf.read_text(), "existing")

    def test_refresh_changes_only_selected_address_and_batches_rules(self):
        self.add_hostname()
        self.add_hostname(58003)
        state = State(self.settings.paths.state_db)
        state.set_mode("attack")
        state.close()
        with patch("nft_forward.destination_sync.resolve_ipv4", return_value=["192.0.2.1", "192.0.2.2"]) as dns, \
             patch("nft_forward.destination_sync.write_and_apply") as apply:
            self.assertEqual(sync_destinations(self.settings), 0)
            dns.assert_called_once()
            apply.assert_not_called()
        with patch("nft_forward.destination_sync.resolve_ipv4", return_value=["192.0.2.2"]), \
             patch("nft_forward.destination_sync.write_and_apply") as apply:
            self.assertEqual(sync_destinations(self.settings), 2)
            self.assertEqual(sync_destinations(self.settings), 0)
            apply.assert_called_once()
        self.assertEqual(self.rule().dest_ip, "192.0.2.2")
        self.assertEqual(self.rule(58003).dest_ip, "192.0.2.2")

    def test_refresh_failure_retains_last_good_address_and_retries(self):
        self.add_hostname()
        with patch("nft_forward.destination_sync.resolve_ipv4", side_effect=ValueError("timeout")), \
             patch("nft_forward.destination_sync.write_and_apply") as apply:
            self.assertEqual(sync_destinations(self.settings), 0)
            apply.assert_not_called()
        self.assertEqual(self.rule().dest_ip, "192.0.2.1")
        with patch("nft_forward.destination_sync.resolve_ipv4", return_value=["192.0.2.2"]), \
             patch("nft_forward.destination_sync.write_and_apply", side_effect=RuntimeError("nft failed")):
            with self.assertRaises(RuntimeError):
                sync_destinations(self.settings)
        self.assertEqual(self.rule().dest_ip, "192.0.2.1")
        with patch("nft_forward.destination_sync.resolve_ipv4", return_value=["192.0.2.2"]), \
             patch("nft_forward.destination_sync.write_and_apply"):
            self.assertEqual(sync_destinations(self.settings), 1)

    def test_refresh_ignores_a_concurrent_destination_edit_or_deletion(self):
        self.add_hostname()
        def resolve_after_edit(*args):
            state = State(self.settings.paths.state_db)
            with state.conn:
                state.update_rule(replace(state.rule_by_lport(58001), dest_host="new.example.com", dest_ip="192.0.2.3"))
            state.close()
            return ["192.0.2.2"]
        with patch("nft_forward.destination_sync.resolve_ipv4", side_effect=resolve_after_edit), \
             patch("nft_forward.destination_sync.write_and_apply") as apply:
            self.assertEqual(sync_destinations(self.settings), 0)
            apply.assert_not_called()
        self.assertEqual(self.rule().dest_ip, "192.0.2.3")
        def resolve_after_delete(*args):
            state = State(self.settings.paths.state_db)
            state.delete_rule(58001)
            state.close()
            return ["192.0.2.2"]
        with patch("nft_forward.destination_sync.resolve_ipv4", side_effect=resolve_after_delete):
            self.assertEqual(sync_destinations(self.settings), 0)
        self.assertIsNone(self.rule())

    def test_export_import_keeps_hostname_and_cached_ip_without_dns(self):
        self.add_hostname()
        payload = export_payload(self.settings, False)
        export = self.root / "export.json"
        export.write_text(json.dumps(payload), encoding="utf-8")
        with patch("nft_forward.destination.resolve_ipv4", side_effect=AssertionError("offline")):
            self.assertEqual(self.cli("import", str(export), "--replace"), 0)
        self.assertEqual((self.rule().dest_host, self.rule().dest_ip), ("exit.example.com", "192.0.2.1"))
        self.assertEqual(self.cli("edit-rule", "58001", "--dest-ip", "192.0.2.8", "--no-apply"), 0)
        self.assertEqual(self.rule().dest_host, "")

    def test_telegram_edits_all_fields_and_retains_pending_on_error(self):
        self.add_hostname()
        self.settings.language = "zh"
        calls = []
        def relay(_settings, args):
            calls.append(args)
            with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
                result = main(["--config", str(self.cfg), *args, *([] if args == ["list"] else ["--no-apply"])])
            return result == 0, output.getvalue() if result == 0 else errors.getvalue()
        with patch.object(telegram_bot, "relay_args", relay):
            detail, keys = telegram_bot.render_edit_rule_detail(self.settings, 58001)
            self.assertIn("当前解析 IPv4：192.0.2.1", detail)
            for field, value in (("new_lport", "58003"), ("dest_port", "58004"), ("dest_ip", "https://new.example.com/path")):
                port = 58001 if field == "new_lport" else 58003
                telegram_bot.handle_callback_for_chat(self.settings, 123, f"edit_rule:field:{port}:{field}")
                if field == "new_lport":
                    telegram_bot.handle_message(self.settings, 123, "0")
                    self.assertIn(123, telegram_bot.PENDING_ACTIONS)
                with patch("nft_forward.destination.resolve_ipv4", return_value=["192.0.2.9"]):
                    detail, _ = telegram_bot.handle_message(self.settings, 123, value)
                self.assertIn("编辑转发规则", detail)
            telegram_bot.handle_callback_for_chat(self.settings, 123, "edit_rule:field:58003:new_lport")
            telegram_bot.handle_callback_for_chat(self.settings, 123, "edit_rule:select:58003")
            self.assertNotIn(123, telegram_bot.PENDING_ACTIONS)
        self.assertIsNone(self.rule())
        self.assertEqual((self.rule(58003).dest_host, self.rule(58003).dest_port), ("new.example.com", 58004))
        self.assertIn(["edit-rule", "58003", "--dest-ip", "new.example.com"], calls)

    def test_ssh_quotes_url_and_notes_as_single_arguments(self):
        args = ["nft.sh", "edit-rule", "58001", "--dest-ip", "https://x.example/a?q=1&x=2", "--note", "keep $(whoami); note"]
        cmd = build_ssh_command("relay", "root", 22, "", args)
        self.assertEqual(shlex.split(" ".join(cmd[-len(args):])), args)
