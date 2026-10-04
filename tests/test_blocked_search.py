from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import io
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nft_forward import blocked_search as search
from nft_forward import telegram_bot as bot
from nft_forward import telegram_log as ui
from nft_forward.cli import main
from nft_forward.config import load_settings
from nft_forward.relay import bot_status
from nft_forward.state import State


class BlockedSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = self.root / "config.json"
        self.cfg.write_text(json.dumps({"ui": {"language": "zh"}, "paths": {
            "state_db": str(self.root / "state.db"), "audit_log": str(self.root / "audit.jsonl"),
            "nft_conf": str(self.root / "forward.conf"),
        }}))
        self.settings = load_settings(self.cfg)
        state = State(self.settings.paths.state_db)
        state.add_rule(58001, "192.0.2.1", 58002)
        state.close()
        self.settings.paths.nft_conf.write_text("preserve forwarding")
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        bot.PENDING_ACTIONS.clear()
        ui.DRAFTS.clear()
        ui.VIEWS.clear()

    def add(self, port=1935, geo="中国/广东省/深圳市", last=200, proto="TCP", hidden=0, isp="ISP"):
        state = State(self.settings.paths.state_db)
        index = state.conn.execute("SELECT COALESCE(MAX(id),0)+1 FROM blocked_events").fetchone()[0]
        address = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("192.0.2.0")) + index))
        state.conn.execute("INSERT INTO blocked_events(source_ip,proto,lport,geo,isp,first_seen,last_seen,count,hidden) VALUES(?,?,?,?,?,?,?,?,?)",
                           (address, proto, port, geo, isp, 1, last, 20, hidden))
        state.conn.commit()
        state.close()
        return index

    def ids(self, query):
        token = search.snapshot(self.settings, query)
        first = search.page(self.settings, token)
        result = []
        for page in range(1, first["pages"] + 1):
            result += [row["id"] for row in search.page(self.settings, token, page)["rows"]]
        return set(result)

    def relay(self, _settings, args):
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error:
            code = main(["--config", str(self.cfg), *args])
        return code == 0, output.getvalue() if code == 0 else error.getvalue()

    def test_and_or_grouping_and_hidden_records(self):
        self.add(last=200)
        self.add(geo="United States/California", last=300)
        self.add(port=24678, last=400)
        self.add(port=58000, geo="United Kingdom/England", last=500)
        self.add(hidden=1, last=250)
        self.add(geo="Canada/Ontario", last=100, proto="UDP")
        self.add(port=58000, geo="United Kingdom/England", last=50)
        query = {"ports": [1935], "countries": ["CN"], "since": 150, "until": 450}
        self.assertEqual(self.ids(query), {1})
        self.assertEqual(self.ids({**query, "operator": "OR"}), {1, 2, 3, 6})
        self.assertEqual(self.ids({"ports": [1935, 24678], "countries": ["中国", "US"], "protocol": "TCP"}), {1, 2, 3})

    def test_source_ranges_and_boundaries(self):
        for _ in range(4):
            self.add()
        self.assertEqual(self.ids({"sources": ["192.0.2.1-192.0.2.2"]}), {1, 2})
        self.assertEqual(self.ids({"sources": ["192.0.2.0/30", "192.0.2.4"]}), {1, 2, 3, 4})
        self.assertEqual(self.ids({"sources": ["198.51.100.0/24"]}), set())
        self.assertEqual(self.ids({"since": 200, "until": 200}), {1, 2, 3, 4})

    def test_country_names_are_exact_and_aliases_work(self):
        self.add(geo="China/Guangdong")
        self.add(geo="中国/广东省")
        self.add(geo="United States/China Township")
        self.add(geo="South Africa/Gauteng")
        self.assertEqual(self.ids({"countries": ["CN"]}), {1, 2})
        self.assertEqual(self.ids({"countries": ["美国"]}), {3})
        self.assertEqual(self.ids({"countries": ["South Africa"]}), {4})
        self.assertEqual(self.ids({"countries": ["CN') OR 1=1 --"]}), set())
        facets = search.facets(self.settings)
        self.assertIn({"key": "CN", "count": 2}, facets["countries"])
        self.assertEqual(facets["ports"], [1935])

    def test_timezone_parsing_and_relative_windows(self):
        expected = int(datetime(2026, 10, 1, 9, tzinfo=timezone.utc).timestamp())
        self.assertEqual(search.parse_time("2026-10-01T17:00:00+08:00"), expected)
        self.assertEqual(search.parse_time("2026-10-01 09:00"), expected)
        self.assertEqual(search.parse_time("2026-10-01", end=True) + 1, search.parse_time("2026-10-02"))
        self.assertEqual(search.normalize_query({"window": 60}, now=1000), {"operator": "AND", "window": 60, "since": 940, "until": 1000})
        with self.assertRaises(ValueError):
            search.parse_time("2026-13-50")
        with self.assertRaises(ValueError):
            search.parse_time("2026-10-01+08:00")
        self.assertIn("1s", ui.summary(self.settings, {"window": 1}))

    def test_query_rejects_invalid_values_without_writing_policy(self):
        bad_queries = [[], "x", {"operator": "AND; DROP TABLE blocked_events"}, {"operator": []},
                       {"ports": [0]}, {"ports": [65536]}, {"ports": [True]}, {"ports": ["1935 OR 1=1"]},
                       {"countries": "CN"}, {"countries": ["a" * 81]}, {"sources": ["::1"]},
                       {"sources": ["192.0.2.2-192.0.2.1"]}, {"protocol": "ICMP"}, {"since": 3, "until": 2},
                       {"window": -1}, {"unknown": 1}, {"ports": list(range(1, 18))}]
        for query in bad_queries:
            with self.subTest(query=query), self.assertRaises(ValueError):
                search.normalize_query(query)
        self.assertEqual(self.settings.paths.nft_conf.read_text(), "preserve forwarding")
        state = State(self.settings.paths.state_db)
        self.assertEqual(len(state.rules()), 1)
        state.close()

    def test_pages_are_complete_deterministic_and_clamp_stale_numbers(self):
        for _ in range(12):
            self.add()
        token = search.snapshot(self.settings)
        pages = [search.page(self.settings, token, index) for index in (1, 2, 3)]
        self.assertEqual([len(page["rows"]) for page in pages], [5, 5, 2])
        self.assertEqual([row["id"] for page in pages for row in page["rows"]], list(range(12, 0, -1)))
        self.assertEqual(search.page(self.settings, token, 100)["page"], 3)
        for number in (0, -1, 10 ** 30):
            with self.assertRaises(ValueError):
                search.page(self.settings, token, number)

    def test_new_activity_cannot_shuffle_an_open_result_set(self):
        for _ in range(12):
            self.add()
        token = search.snapshot(self.settings)
        before = [search.page(self.settings, token, page)["rows"] for page in (1, 2, 3)]
        state = State(self.settings.paths.state_db)
        state.conn.execute("UPDATE blocked_events SET last_seen=999,count=999 WHERE id=1")
        state.conn.execute("UPDATE blocked_events SET hidden=1 WHERE id=2")
        state.conn.execute("DELETE FROM blocked_events WHERE id=3")
        state.conn.commit()
        state.close()
        self.add(last=1000)
        self.assertEqual([search.page(self.settings, token, page)["rows"] for page in (1, 2, 3)], before)
        fresh = search.page(self.settings, search.snapshot(self.settings))
        self.assertEqual(fresh["total"], 11)
        self.assertEqual(fresh["rows"][0]["last_seen"], 1000)

    def test_empty_expired_invalid_and_bounded_snapshots(self):
        token = search.snapshot(self.settings)
        empty = search.page(self.settings, token)
        self.assertEqual((empty["total"], empty["page"], empty["pages"], empty["rows"]), (0, 1, 1, []))
        path = search.cache_dir(self.settings) / f"{token}.db"
        os.utime(path, (1, 1))
        self.assertTrue(search.page(self.settings, token)["expired"])
        with self.assertRaises(ValueError):
            search.page(self.settings, "../state")
        with patch.object(search, "MAX_SNAPSHOTS", 2):
            tokens = [search.snapshot(self.settings) for _ in range(3)]
        self.assertTrue(search.page(self.settings, tokens[0])["expired"])
        self.assertEqual(len(list(search.cache_dir(self.settings).glob("*.db"))), 2)
        self.add()
        with patch.object(search, "MAX_ROWS", 0), self.assertRaisesRegex(ValueError, "narrow"):
            search.snapshot(self.settings)
        self.assertFalse(list(search.cache_dir(self.settings).glob("*.tmp")))
        with patch.object(search, "MAX_SNAPSHOT_BYTES", 1), self.assertRaisesRegex(ValueError, "narrow"):
            search.snapshot(self.settings)

    def test_status_counts_beyond_the_previous_thousand_record_cap(self):
        state = State(self.settings.paths.state_db)
        state.conn.executemany("INSERT INTO blocked_events(source_ip,proto,lport,first_seen,last_seen) VALUES(?,?,?,?,?)",
                               [(str(ipaddress.IPv4Address(0xC0000200 + n)), "TCP", 1935, 1, 2) for n in range(1201)])
        state.conn.commit()
        state.close()
        self.assertEqual(bot_status(self.settings)["blocked"], 1201)
        self.assertEqual(search.page(self.settings, search.snapshot(self.settings))["total"], 1201)

    def test_telegram_next_previous_page_jump_and_cancel(self):
        for _ in range(12):
            self.add()
        with patch.object(bot, "relay_args", self.relay):
            body, keys = bot.handle_callback_for_chat(self.settings, 123, "log:browse")
            self.assertIn("第 1/3 页", body)
            token = keys["inline_keyboard"][1][0]["callback_data"].split(":")[2]
            body, _ = bot.handle_callback_for_chat(self.settings, 123, f"log:p:{token}:2")
            self.assertIn("第 2/3 页", body)
            bot.handle_callback_for_chat(self.settings, 123, f"log:j:{token}:2")
            body, _ = bot.handle_message(self.settings, 123, "0")
            self.assertIn("无效", body)
            self.assertIn(123, bot.PENDING_ACTIONS)
            body, _ = bot.handle_message(self.settings, 123, "3")
            self.assertIn("第 3/3 页", body)
            bot.handle_callback_for_chat(self.settings, 123, f"log:j:{token}:3")
            bot.handle_message(self.settings, 123, "/menu")
            self.assertNotIn(123, bot.PENDING_ACTIONS)

    def test_guided_filters_reach_the_real_query_and_preserve_invalid_input(self):
        self.add(last=search.parse_time("2026-10-01T17:00+08:00"))
        self.add(port=24678, geo="United States", last=search.parse_time("2026-10-01T18:00+08:00"))
        with patch.object(bot, "relay_args", self.relay):
            _, keys = bot.handle_callback_for_chat(self.settings, 123, "log:search")
            draft = keys["inline_keyboard"][0][0]["callback_data"].split(":")[2]
            for field, message in (("ports", "1935"), ("countries", "CN"),
                                   ("since", "2026-10-01T16:00+08:00"), ("until", "2026-10-01T19:00+08:00")):
                bot.handle_callback_for_chat(self.settings, 123, f"log:input:{draft}:{field}")
                body, _ = bot.handle_message(self.settings, 123, message)
                self.assertIn("高级搜索", body)
            body, _ = bot.handle_callback_for_chat(self.settings, 123, f"log:run:{draft}")
            self.assertIn("拦截记录：1 条", body)
            bot.handle_callback_for_chat(self.settings, 123, f"log:op:{draft}:OR")
            body, _ = bot.handle_callback_for_chat(self.settings, 123, f"log:run:{draft}")
            self.assertIn("拦截记录：2 条", body)
            bot.handle_callback_for_chat(self.settings, 123, f"log:input:{draft}:ports")
            body, _ = bot.handle_message(self.settings, 123, "65536")
            self.assertIn("无效", body)
            self.assertEqual(ui.DRAFTS[draft]["filters"]["ports"], [1935])
            bot.handle_callback_for_chat(self.settings, 123, f"log:window:{draft}:3600")
            bot.handle_callback_for_chat(self.settings, 123, f"log:input:{draft}:since")
            bot.handle_message(self.settings, 123, "-")
            self.assertNotIn("window", ui.DRAFTS[draft]["filters"])

    def test_selector_multi_select_and_chat_isolation(self):
        self.add()
        self.add(port=24678, geo="United States")
        token = ui.new_draft(123)
        with patch.object(bot, "relay_args", self.relay):
            _, keys = bot.handle_callback_for_chat(self.settings, 123, f"log:select:{token}:ports:0")
            for index in (0, 1):
                bot.handle_callback_for_chat(self.settings, 123, keys["inline_keyboard"][index][0]["callback_data"])
            self.assertEqual(ui.DRAFTS[token]["filters"]["ports"], [1935, 24678])
            body, _ = bot.handle_callback_for_chat(self.settings, 456, f"log:clear:{token}:all")
            self.assertIn("expired", body)
            self.assertEqual(ui.DRAFTS[token]["filters"]["ports"], [1935, 24678])
            _, country_keys = bot.handle_callback_for_chat(self.settings, 123, f"log:select:{token}:countries:0")
            bot.handle_callback_for_chat(self.settings, 123, country_keys["inline_keyboard"][0][0]["callback_data"])
            self.assertEqual(len(ui.DRAFTS[token]["filters"]["countries"]), 1)

    def test_expired_results_can_refresh_and_callbacks_survive_bot_restart(self):
        self.add()
        with patch.object(bot, "relay_args", self.relay):
            _, keys = bot.handle_callback_for_chat(self.settings, 123, "log:browse")
            token = keys["inline_keyboard"][1][0]["callback_data"].split(":")[2]
            ui.VIEWS.clear()
            body, _ = bot.handle_callback_for_chat(self.settings, 123, f"log:p:{token}:1")
            self.assertIn("拦截记录：1 条", body)
            os.utime(search.cache_dir(self.settings) / f"{token}.db", (1, 1))
            body, _ = bot.handle_callback_for_chat(self.settings, 123, f"log:p:{token}:1")
            self.assertIn("过期", body)
            body, _ = bot.handle_callback_for_chat(self.settings, 123, f"log:r:{token}")
            self.assertIn("拦截记录：1 条", body)

    def test_long_unicode_labels_fit_telegram_limits(self):
        for _ in range(5):
            self.add(geo="中国/" + chr(0x20000) * 1000, isp=chr(0x20000) * 1000)
        with patch.object(bot, "relay_args", self.relay):
            body, keys = bot.handle_callback_for_chat(self.settings, 123, "log:browse")
        self.assertLessEqual(len(body.encode("utf-16-le")) // 2, bot.MAX_MESSAGE)
        for row in keys["inline_keyboard"]:
            for button in row:
                self.assertLessEqual(len(button["callback_data"].encode()), 64)

    def test_old_blocked_cli_still_returns_array(self):
        self.add()
        ok, body = self.relay(self.settings, ["blocked", "--limit", "5"])
        self.assertTrue(ok)
        self.assertIsInstance(json.loads(body), list)

    def test_busy_cache_fails_quickly_and_does_not_lose_filters(self):
        token = ui.new_draft(123, {"ports": [1935]})
        with search.cache_lock(search.cache_dir(self.settings)), patch.object(bot, "relay_args", self.relay):
            body, keys = bot.handle_callback_for_chat(self.settings, 123, f"log:run:{token}")
        self.assertIn("another blocked-history search", body)
        self.assertIn(f"log:f:{token}", str(keys))
        self.assertEqual(ui.DRAFTS[token]["filters"]["ports"], [1935])

    def test_english_ui_and_malformed_callbacks(self):
        self.settings.language = "en"
        self.add()
        with patch.object(bot, "relay_args", self.relay):
            body, _ = bot.handle_callback_for_chat(self.settings, 123, "log:browse")
            self.assertIn("Page 1/1", body)
            self.assertIn("Count: lifetime total", body)
            for callback in ("log:", "log:p:bad:2", "log:p:" + "a" * 32 + ":-1", "log:select:invalid:ports:0"):
                body, keys = bot.handle_callback_for_chat(self.settings, 123, callback)
                self.assertTrue(keys)
                self.assertIn("Blocked history", body)
