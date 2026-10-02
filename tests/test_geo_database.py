from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nft_forward.config import Settings, default_paths
from nft_forward.geo import GeoLookup
from nft_forward import geo_database as db
from nft_forward import geo_update as updater
from nft_forward import telegram_bot
from nft_forward.state import State


SOURCE = (
    "0.0.0.0|0.255.255.255|Reserved|Reserved|Reserved|0|0\n"
    "1.0.0.0|1.255.255.255|Country|Province|City|Example ISP|XX\n"
    "2.0.0.0|255.255.255.255|Other|0|0|0|YY\n"
)


class GeoDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        paths = default_paths(self.root)
        paths.ip_cache = self.root / "cache"
        paths.state_db = self.root / "state.db"
        paths.audit_log = self.root / "audit.jsonl"
        paths.nft_conf = self.root / "forward.conf"
        self.settings = Settings(role="exit", paths=paths, relay_host="relay.example.com")
        minimum = patch.object(db, "MIN_ROWS", 1)
        minimum.start()
        self.addCleanup(minimum.stop)
        self.metadata = {"source_sha256": "a" * 64, "revision": "b" * 40,
                         "source_date": "2026-01-01T00:00:00Z", "license": "fixture license", "built_at": 1}

    def candidate(self, content=SOURCE, name="candidate.db"):
        source = self.root / "source.txt"
        source.write_text(content, encoding="utf-8")
        target = self.root / name
        db.build_database(source, target, self.metadata)
        return target

    def install(self):
        return db.install_database(self.settings, self.candidate())

    def test_lookup_boundaries_metadata_and_live_replacement(self):
        self.install()
        lookup = GeoLookup(self.settings)
        self.assertEqual(lookup.lookup_local("1.0.0.0").geo, "Country/Province/City")
        self.assertEqual(lookup.lookup_local("1.255.255.255").isp, "Example ISP")
        self.assertEqual(db.lookup_database(self.settings, "2.0.0.0"), ("Other", "unknown"))
        self.assertEqual(db.lookup_database(self.settings, "255.255.255.255"), ("Other", "unknown"))
        self.assertEqual(db.validate_database(db.database_path(self.settings))["rows"], 3)
        self.assertNotIn("license", db.database_info(self.settings))
        new = self.candidate(SOURCE.replace("City", "New City"), "new.db")
        db.install_database(self.settings, new)
        self.assertEqual(lookup.lookup_local("1.2.3.4").geo, "Country/Province/New City")
        self.assertTrue((self.settings.paths.ip_cache / "geoip.previous.db").exists())

    def test_malformed_ranges_cannot_replace_working_database(self):
        self.install()
        before = db.database_path(self.settings).read_bytes()
        for number, content in enumerate(("<html>failed</html>", SOURCE.replace("2.0.0.0|", "1.0.0.0|"),
                                           SOURCE.replace("255.255.255.255", "254.255.255.255"), SOURCE.replace("|XX", "|extra|XX"))):
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.candidate(content, f"bad{number}.db")
        self.assertEqual(db.database_path(self.settings).read_bytes(), before)

    def test_transfer_checksum_truncation_and_size_limits(self):
        self.install()
        old = db.database_path(self.settings).read_bytes()
        candidate = self.candidate(SOURCE.replace("City", "New City"), "new.db")
        content = candidate.read_bytes()
        packed = gzip.compress(content)
        sha = hashlib.sha256(content).hexdigest()
        with self.assertRaisesRegex(ValueError, "checksum"):
            db.receive_database(self.settings, io.BytesIO(packed), "0" * 64)
        with self.assertRaises((EOFError, OSError)):
            db.receive_database(self.settings, io.BytesIO(packed[:20]), sha)
        with patch.object(db, "MAX_DATABASE_BYTES", 100), self.assertRaises(ValueError):
            db.receive_database(self.settings, io.BytesIO(packed), sha)
        self.assertEqual(db.database_path(self.settings).read_bytes(), old)
        result = db.receive_database(self.settings, io.BytesIO(packed), sha)
        self.assertEqual(result["rows"], 3)
        self.assertEqual(db.lookup_database(self.settings, "1.2.3.4")[0], "Country/Province/New City")

    def test_refresh_only_changes_labels(self):
        self.install()
        state = State(self.settings.paths.state_db)
        state.add_rule(58001, "192.0.2.1", 58002)
        state.add_allow("public", "1.2.3.0/24", "ddns", 24, ttl_days=10, geo="old", isp="old")
        state.record_block("1.2.3.4", "tcp", 58001, "old", "old")
        before_allow = state.conn.execute("SELECT source,channel,created_at,expires_at,prefix_len FROM allow_entries").fetchall()
        before_block = state.conn.execute("SELECT source_ip,lport,proto,first_seen,last_seen,count,hidden FROM blocked_events").fetchall()
        state.close()
        self.settings.paths.nft_conf.write_text("keep the active firewall")
        with patch("nft_forward.nft.write_and_apply", side_effect=AssertionError("must not apply nft")):
            self.assertEqual(updater.refresh_labels(self.settings), {"allow_entries": 1, "blocked_events": 1})
        state = State(self.settings.paths.state_db)
        self.assertEqual(state.conn.execute("SELECT source,channel,created_at,expires_at,prefix_len FROM allow_entries").fetchall(), before_allow)
        self.assertEqual(state.conn.execute("SELECT source_ip,lport,proto,first_seen,last_seen,count,hidden FROM blocked_events").fetchall(), before_block)
        self.assertEqual(state.active_allow_entries()[0].geo, "Country/Province/City")
        self.assertEqual(len(state.rules()), 1)
        state.close()
        self.assertEqual(self.settings.paths.nft_conf.read_text(), "keep the active firewall")

    def test_download_failure_preserves_installed_database_and_records_error(self):
        self.install()
        original = db.database_path(self.settings).read_bytes()
        with patch.object(updater, "fetch_source", side_effect=OSError("download timeout")):
            result = updater.perform_update(self.settings)
        self.assertEqual(result["status"], "failed")
        self.assertIn("timeout", updater.job_status(self.settings)["error"])
        self.assertEqual(db.database_path(self.settings).read_bytes(), original)

    def test_successful_update_and_relay_outage_are_reported_separately(self):
        source = self.root / "upstream.txt"
        source.write_text(SOURCE)
        with patch.object(updater, "fetch_source", return_value=(source, self.metadata)), \
             patch.object(updater, "push_database", side_effect=RuntimeError("SSH timeout")):
            result = updater.perform_update(self.settings)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["phase"], "uploading")
        self.assertTrue(db.database_info(self.settings)["installed"])
        with patch.object(updater, "fetch_source", return_value=(source, self.metadata)), \
             patch.object(updater, "build_database", side_effect=AssertionError("unchanged source must not rebuild")), \
             patch.object(updater, "push_database", return_value={"provider": "ip2region", "revision": "b" * 40}):
            self.assertEqual(updater.perform_update(self.settings)["status"], "succeeded")

    def test_one_click_is_nonblocking_deduplicated_and_recovers_start_failure(self):
        with patch.object(updater.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as start:
            first = updater.request_update(self.settings)
            second = updater.request_update(self.settings)
            self.assertEqual(first["id"], second["id"])
            self.assertIn("--no-block", start.call_args.args[0])
            with updater.update_lock(self.settings) as acquired:
                self.assertTrue(acquired)
                before = start.call_count
                self.assertEqual(updater.request_update(self.settings)["id"], first["id"])
                self.assertEqual(start.call_count, before)
        with patch.object(updater.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemctl", 5)):
            self.assertEqual(updater.request_update(self.settings)["status"], "failed")

    def test_telegram_menu_queues_update_without_ssh_or_download(self):
        self.settings.language = "zh"
        with patch.object(telegram_bot, "relay_args", side_effect=AssertionError("must not block on SSH")), \
             patch.object(updater.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            body, keys = telegram_bot.handle_callback_for_chat(self.settings, 123, "geo:update")
        self.assertIn("IP 归属地库", body)
        self.assertIn("等待更新", body)
        self.assertIn("更新数据库", str(keys))
        self.assertIn("geo:status", str(keys))

    def test_upload_rewinds_data_after_timeout_and_requires_acknowledgement(self):
        self.install()
        received = []
        def remote(args, **kwargs):
            received.append(gzip.decompress(kwargs["stdin"].read()))
            if len(received) == 1:
                raise subprocess.TimeoutExpired(args, 180)
            return subprocess.CompletedProcess(args, 0, json.dumps({"provider": "ip2region", "source_sha256": "a" * 64}), "")
        with patch.object(updater.subprocess, "run", side_effect=remote), patch.object(updater.time, "sleep"):
            self.assertEqual(updater.push_database(self.settings)["provider"], "ip2region")
        self.assertEqual(received[0], received[1])

    def test_legacy_lookup_remains_available_without_database(self):
        root = self.settings.paths.ip_cache
        (root / "country").mkdir(parents=True)
        (root / "country/CN.txt").write_text("1.0.0.0/8\n")
        self.assertEqual(GeoLookup(self.settings).lookup_local("1.2.3.4").geo, "China")
        self.assertFalse(db.database_info(self.settings)["installed"])

    def test_in_progress_downloads_are_not_parsed_as_legacy_cache(self):
        shadow = self.settings.paths.ip_cache / ".geo-build-test" / "country"
        shadow.mkdir(parents=True)
        (shadow / "CN.txt").write_text("8.0.0.0/8\n")
        self.assertEqual(GeoLookup(self.settings).lookup_local("8.8.8.8").geo, "unknown")
