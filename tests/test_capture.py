from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from nft_forward import capture, capture_store, telegram_bot as bot, telegram_capture as ui
from nft_forward.capture_config import DEFAULTS, get_config, validate_config
from nft_forward.capture_pcap import Stream, decode_nflog, decode_ipv4
from nft_forward.cli import main
from nft_forward.config import load_settings
from nft_forward.nft import render_nft
from nft_forward.state import State


def packet(payload=b"private-payload", proto=17):
    transport = struct.pack("!HHHH", 12345, 58001, 8 + len(payload), 0) if proto == 17 else struct.pack("!HHIIBBHHH", 12345, 58001, 1, 0, 5 << 4, 2, 8192, 0, 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport) + len(payload), 1, 0, 64, proto, 0, b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x01")
    return header + transport + payload


def nflog(payload, endian="<", prefix=b"NGCAP:B\0"):
    def tlv(kind, value):
        size = len(value) + 4
        return struct.pack(endian + "HH", size, kind) + value + b"\0" * ((-size) % 4)
    return b"\x02\x00\xf0\x00" + tlv(10, prefix) + tlv(9, payload)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = self.root / "config.json"
        self.cfg.write_text(json.dumps({"paths": {"state_db": str(self.root / "state.db"), "audit_log": str(self.root / "audit.jsonl"),
                                                   "nft_conf": str(self.root / "forward.conf"), "ip_cache": str(self.root / "cache")}}))
        self.settings = load_settings(self.cfg)
        self.state = State(self.settings.paths.state_db)
        self.addCleanup(self.state.close)
        self.state.add_rule(58001, "198.51.100.2", 58002)
        self.state.add_rule(58003, "198.51.100.2", 58002, open_access=True)
        self.state.add_allow("public", "192.0.2.0/24", "manual", 24)
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)

    def configure(self, **data):
        with patch("nft_forward.capture.write_and_apply"):
            return capture.configure(self.settings, data, check_service=False)

    def test_defaults_and_validation(self):
        self.assertEqual(get_config(self.state), {**DEFAULTS, "ports": []})
        self.assertNotIn("capture", render_nft(self.settings, self.state))
        for data in ({"enabled": 1}, {"scope": []}, {"ports": [True]}, {"ports": [80]}, {"rate_pps": 0},
                     {"retention_days": 0}, {"max_disk_mb": 1000000}, {"unknown": 1}, {"countries": [1]}):
            with self.assertRaises(ValueError):
                self.configure(**data)
        self.assertEqual(validate_config({"countries": ["中国", "CN", "UK", "AU"]})["countries"], ["AU", "CN", "GB"])

    def test_hooks_do_not_change_drop_or_unselected_ports(self):
        self.configure(enabled=True, ports=[58001])
        nft = render_nft(self.settings, self.state)
        self.assertIn('ip saddr != @src_58001 tcp dport 58001 jump packet_capture', nft)
        self.assertIn('ip saddr != @src_58001 tcp dport 58001 drop', nft)
        self.assertNotIn('58003 jump packet_capture', nft)
        self.assertIn('group 61440', nft)
        self.assertNotIn('capture_ingress', nft)
        self.configure(scope="all")
        nft = render_nft(self.settings, self.state)
        self.assertIn('fib daddr type local tcp dport { 58001 } jump packet_capture', nft)
        self.assertIn('priority -110', nft)
        self.assertIn('ip saddr != @src_58001 tcp dport 58001 drop', nft)
        self.configure(enabled=False)
        self.assertNotIn('packet_capture', render_nft(self.settings, self.state))

    def test_selection_follows_port_edit_and_deletion(self):
        self.configure(ports=[58001])
        rule = self.state.rule_by_lport(58001)
        rule.lport = 58009
        self.state.update_rule(rule)
        self.state.conn.commit()
        self.assertEqual(get_config(self.state)["ports"], [58009])
        self.state.delete_rule(58009)
        self.state.add_rule(58009, "198.51.100.2", 58002)
        self.assertEqual(get_config(self.state)["ports"], [])

    def test_config_rollback_and_country_only_no_firewall_apply(self):
        self.configure(enabled=True, ports=[58001])
        with patch("nft_forward.capture.write_and_apply") as apply:
            capture.configure(self.settings, {"countries": ["CN"]}, check_service=False)
            apply.assert_not_called()
        with patch("nft_forward.capture.write_and_apply", side_effect=RuntimeError("nft failed")):
            with self.assertRaisesRegex(RuntimeError, "nft failed"):
                capture.configure(self.settings, {"scope": "all", "ports": [58003]}, check_service=False)
        result = get_config(self.state)
        self.assertEqual(result["scope"], "blocked")
        self.assertEqual(result["ports"], [58001])

    def test_enable_without_dependency_or_service_fails_closed(self):
        with patch("nft_forward.capture.shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "tcpdump"):
                capture.configure(self.settings, {"enabled": True, "ports": [58001]})
        self.assertFalse(get_config(self.state)["enabled"])

    def test_decoder_split_endian_nanosecond_and_payload_separation(self):
        for endian, magic in (("<", 0xA1B2C3D4), (">", 0xA1B2C3D4), ("<", 0xA1B23C4D)):
            raw = nflog(packet(), endian)
            stamp = 123000 if magic == 0xA1B23C4D else 123
            data = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 262144, 239) + struct.pack(endian + "IIII", 100, stamp, len(raw), len(raw)) + raw
            stream, values = Stream(), []
            for byte in data:
                values += list(stream.feed(bytes([byte])))
            self.assertEqual(values[0][:2], (100, 123))
            payload, meta = decode_nflog(values[0][2], endian)
            self.assertEqual(payload, packet())
            self.assertEqual(meta["source_ip"], "192.0.2.1")
            self.assertNotIn("private-payload", json.dumps(meta))
        self.assertEqual(decode_ipv4(packet(proto=6))["flags"], "SYN")

    def test_malformed_packet_rejected_and_truncation_marked(self):
        self.assertIsNone(decode_nflog(nflog(packet(), prefix=b"other\0")))
        self.assertIsNone(decode_nflog(b"\x02\0\0\0\x01\0\x09\0"))
        for cut in range(28):
            self.assertIsNone(decode_ipv4(packet()[:cut]))
        self.assertTrue(decode_ipv4(packet()[:-3])["truncated"])
        fragment = bytearray(packet())
        fragment[7] = 1
        self.assertIsNone(decode_ipv4(fragment))
        bad = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 239) + struct.pack("<IIII", 1, 0, 2**30, 2**30)
        with self.assertRaises(ValueError):
            list(Stream().feed(bad))

    def record(self, store, count):
        data = packet()
        for _ in range(count):
            self.assertTrue(store.append(100, 123, data, {**decode_ipv4(data), "scope": "blocked", "geo": "China", "isp": "test", "country": "CN"}))
        store.flush()

    def test_storage_rotation_permissions_and_stable_metadata_pages(self):
        config = {**DEFAULTS, "ports": [58001]}
        store = capture_store.Store(self.settings, config)
        self.addCleanup(store.close)
        self.record(store, 8)
        listing = capture_store.files(self.settings)
        file_id = listing["rows"][0]["id"]
        first = capture_store.records(self.settings, file_id)
        self.record(store, 1)
        second = capture_store.records(self.settings, file_id, 2, first["anchor"])
        self.assertEqual([r["id"] for r in first["rows"]], [8, 7, 6, 5, 4])
        self.assertEqual([r["id"] for r in second["rows"]], [3, 2, 1])
        self.assertNotIn("private-payload", json.dumps(first))
        pcap = Path(first["path"])
        self.assertIn(b"private-payload", pcap.read_bytes())
        self.assertEqual(pcap.stat().st_mode & 0o777, 0o600)
        self.assertEqual(pcap.parent.stat().st_mode & 0o777, 0o700)
        with patch("nft_forward.capture_store.SEGMENT_ROWS", 8):
            self.record(store, 1)
        self.assertEqual(len(capture_store.files(self.settings)["rows"]), 2)
        self.assertTrue(capture_store.records(self.settings, "cap-" + "0" * 20 + "-" + "0" * 12)["expired"])
        with self.assertRaises(ValueError):
            capture_store.records(self.settings, "../../config.json")

    def test_retention_quota_and_low_disk_skip(self):
        store = capture_store.Store(self.settings, {**DEFAULTS, "ports": [58001], "max_disk_mb": 32})
        self.addCleanup(store.close)
        self.record(store, 1)
        store.close()
        paths = store.owned()
        for path in paths:
            os.utime(path, (1, 1))
        unrelated = store.root / "keep.txt"
        unrelated.write_text("keep")
        store.prune()
        self.assertEqual(store.owned(), [])
        self.assertTrue(unrelated.exists())
        self.record(store, 1)
        store.close()
        pcap = next(store.root.glob("*.pcap"))
        with pcap.open("ab") as handle:
            handle.truncate(33 * 1024 * 1024)
        self.assertTrue(store.prune())
        self.assertFalse(pcap.exists())
        with patch("nft_forward.capture_store.shutil.disk_usage") as usage:
            usage.return_value.free = 0
            self.assertFalse(store.append(1, 0, packet(), decode_ipv4(packet())))

    def test_idle_segment_closes_for_retention(self):
        store = capture_store.Store(self.settings, {**DEFAULTS, "ports": [58001]})
        self.addCleanup(store.close)
        self.record(store, 1)
        store.started -= 301
        store.tick()
        self.assertIsNone(store.pcap)
        for path in store.owned():
            os.utime(path, (1, 1))
        store.prune()
        self.assertEqual(store.owned(), [])

    def test_geo_uses_local_cache_without_ssh_or_online(self):
        geo = capture.Countries(self.settings)
        with patch("nft_forward.capture.lookup_database", return_value=("中国/广东", "unknown")) as lookup, patch.object(geo.legacy, "lookup_local") as legacy:
            self.assertEqual(geo.lookup("192.0.2.1")["country"], "CN")
            geo.lookup("192.0.2.1")
            self.assertEqual(lookup.call_count, 1)
            legacy.assert_not_called()

    def relay(self, settings, args):
        configure = capture.configure
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error:
            with patch("nft_forward.capture.write_and_apply"), patch("nft_forward.capture.configure", side_effect=lambda s, p: configure(s, p, check_service=False)):
                code = main(["--config", str(self.cfg), *args])
        return code == 0, output.getvalue() if code == 0 else error.getvalue()

    def test_telegram_menu_metadata_and_callbacks(self):
        # Exercise real CLI reads; settings writes are kept away from host nftables.
        with patch.object(bot, "relay_text", side_effect=self.relay):
            body, keys = bot.handle_callback_for_chat(self.settings, 1, "manage:settings")
            self.assertIn("cap:home", json.dumps(keys))
            body, keys = bot.handle_callback_for_chat(self.settings, 1, "cap:home")
            self.assertIn("OFF", body)
            body, keys = bot.handle_callback_for_chat(self.settings, 1, "cap:countries:0")
            self.assertIn("China", json.dumps(keys))
            bot.handle_callback_for_chat(self.settings, 1, "cap:toggle:ports:58001:0")
            bot.handle_callback_for_chat(self.settings, 1, "cap:toggle:countries:0:0")
            bot.handle_callback_for_chat(self.settings, 1, "cap:enable:1")
            self.assertTrue(get_config(self.state)["enabled"])
            self.assertEqual(get_config(self.state)["ports"], [58001])
            self.assertEqual(get_config(self.state)["countries"], ["CN"])
            bot.handle_callback_for_chat(self.settings, 1, "cap:scope:all")
            self.assertEqual(get_config(self.state)["scope"], "all")
            store = capture_store.Store(self.settings, {**DEFAULTS, "ports": [58001]})
            self.record(store, 7)
            store.close()
            body, keys = bot.handle_callback_for_chat(self.settings, 1, "cap:files:1")
            callback = keys["inline_keyboard"][0][0]["callback_data"]
            body, keys = bot.handle_callback_for_chat(self.settings, 1, callback)
            self.assertNotIn("private-payload", body)
            self.assertIn("12345", body)
            self.assertIn("58001", body)
            for row in keys["inline_keyboard"]:
                for button in row:
                    self.assertLessEqual(len(button["callback_data"].encode()), 64)
