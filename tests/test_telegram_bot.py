from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from nft_forward import telegram_bot
from nft_forward.config import Settings, default_paths


def settings() -> Settings:
    return Settings(paths=default_paths(Path(".tmp-telegram-tests")))


def zh_settings() -> Settings:
    return Settings(paths=default_paths(Path(".tmp-telegram-tests")), language="zh")


class TelegramBotTests(unittest.TestCase):
    def setUp(self) -> None:
        telegram_bot.PENDING_ACTIONS.clear()

    def fake_relay(self, calls: list[list[str]]):
        def _fake(_settings: Settings, args: list[str]) -> tuple[bool, str]:
            calls.append(args)
            if args == ["bot-status"]:
                return True, json.dumps({"mode": "regular", "allow": 2, "rules": 1, "rulesets": 1, "blocked": 1})
            if args == ["status"]:
                return True, json.dumps({"mode": "regular", "active_allow_entries": 2, "rules": 1, "blocked_visible": 1})
            if args == ["allow-list"]:
                return True, json.dumps(
                    [
                        {
                            "id": 1,
                            "ruleset": "public",
                            "source": "198.51.100.0/24",
                            "channel": "ddns",
                            "prefix_len": 24,
                            "geo": "Example A",
                            "isp": "ISP A",
                            "created_at": 100,
                            "expires_at": 200,
                            "note": "old",
                        },
                        {
                            "id": 2,
                            "ruleset": "ddns",
                            "source": "203.0.113.10/32",
                            "channel": "manual",
                            "prefix_len": 32,
                            "geo": "Example B",
                            "isp": "ISP B",
                            "created_at": 300,
                            "expires_at": None,
                            "note": "new",
                        },
                    ]
                )
            if args == ["list"]:
                return True, json.dumps(
                    [
                        {
                            "lport": 58495,
                            "target": "203.0.113.20:58495",
                            "note": "live",
                            "rulesets": [],
                            "include_public": True,
                            "open_access": False,
                            "effective_sources": ["198.51.100.0/24"],
                        }
                    ]
                )
            if args == ["blocked", "--limit", "1000"] or args == ["blocked", "--limit", "5"] or args == ["blocked", "--limit", "20"]:
                return True, json.dumps(
                    [
                        {
                            "id": 9,
                            "source_ip": "192.0.2.44",
                            "proto": "TCP",
                            "lport": 58495,
                            "geo": "Example C",
                            "isp": "ISP C",
                            "first_seen": 10,
                            "last_seen": 20,
                            "count": 3,
                        }
                    ]
                )
            if args == ["ruleset", "list"]:
                return True, (
                    'public\tchannels=["ddns","manual","ssh_login","web"]\tprefixes={}\t\n'
                    'ddns\tchannels=["manual"]\tprefixes={}\tddns'
                )
            if args == ["secret-url", "list", "--include-secrets"]:
                return True, json.dumps(
                    [
                        {
                            "id": 5,
                            "label": "main",
                            "secret_path": "secret-path",
                            "ruleset": "public",
                            "active": True,
                            "created_at": 500,
                            "last_used_at": None,
                            "hit_count": 0,
                        }
                    ]
                )
            if args[:2] == ["secret-url", "create"]:
                return True, json.dumps(
                    {
                        "id": 6,
                        "label": "url",
                        "secret_path": "new-secret",
                        "ruleset": args[-1],
                        "active": True,
                        "created_at": 600,
                        "last_used_at": None,
                        "hit_count": 0,
                    }
                )
            if args == ["ddns", "list"]:
                return True, json.dumps(
                    [
                        {
                            "id": 1,
                            "host": "mobile.example.com",
                            "ruleset": "public",
                            "enabled": True,
                        }
                    ]
                )
            if args[:2] == ["ddns", "add"]:
                return True, json.dumps({"id": 2, "host": args[2], "ruleset": args[-1], "enabled": True})
            if args[:2] == ["ddns", "delete"]:
                ids = [x for x in args[2:] if not x.startswith("--")]
                removed = 0 if "--keep-allowlist" in args else 1
                return True, json.dumps({"deleted": len(ids), "removed_allow_entries": removed})
            if args == ["sync-ddns"]:
                return True, "ddns entries updated: 1"
            if args and args[0] == "add-rule":
                return True, "rule upserted"
            return False, "unexpected command"

        return _fake

    def test_status_menu_counts_custom_rulesets(self) -> None:
        calls: list[list[str]] = []
        with patch.object(telegram_bot, "relay_args", self.fake_relay(calls)):
            text, markup = telegram_bot.render_status_menu(settings())
        self.assertIn("Mode: regular", text)
        self.assertIn("Relay SSH:", text)
        labels = [button["text"] for row in markup["inline_keyboard"] for button in row]
        self.assertIn("Whitelisted IPs (2)", labels)
        self.assertIn("Forwarding Rules (1)", labels)
        self.assertIn("Custom Rule Sets (1)", labels)
        self.assertIn("Blocked IPs (1)", labels)
        self.assertEqual(calls, [["bot-status"]])

    def test_status_menu_shows_timeout(self) -> None:
        calls: list[list[str]] = []

        def timeout_relay(_settings: Settings, args: list[str]) -> tuple[bool, str]:
            calls.append(args)
            return False, "ssh timeout"

        with patch.object(telegram_bot, "relay_args", timeout_relay):
            text, _markup = telegram_bot.render_status_menu(settings())
        self.assertIn("Relay SSH: timeout after", text)
        self.assertEqual(calls, [["bot-status"], ["status"]])

    def test_chinese_menu_labels(self) -> None:
        calls: list[list[str]] = []
        with patch.object(telegram_bot, "relay_args", self.fake_relay(calls)):
            text, markup = telegram_bot.render_status_menu(zh_settings())
        self.assertIn("当前模式：regular", text)
        labels = [button["text"] for row in markup["inline_keyboard"] for button in row]
        self.assertIn("白名单 IP (2)", labels)
        self.assertIn("转发规则 (1)", labels)
        self.assertIn("自定义规则集 (1)", labels)
        self.assertIn("拦截 IP (1)", labels)

    def test_log_uses_most_recent_whitelist_entry(self) -> None:
        calls: list[list[str]] = []
        with patch.object(telegram_bot, "relay_args", self.fake_relay(calls)):
            text = telegram_bot.render_log(settings())
        self.assertIn("#2 203.0.113.10/32", text)
        self.assertIn("Most Recent Blocked IPs", text)

    def test_guided_add_rule_generates_relay_command(self) -> None:
        calls: list[list[str]] = []
        with patch.object(telegram_bot, "relay_args", self.fake_relay(calls)):
            telegram_bot.handle_callback_for_chat(settings(), 123, "manage:add_rule")
            text, _markup = telegram_bot.handle_message(
                settings(), 123, "58495 203.0.113.20 58495 public+ddns live rule"
            )
        self.assertEqual(text, "rule upserted")
        self.assertEqual(
            calls[-1],
            ["add-rule", "58495", "203.0.113.20", "58495", "--note", "live rule", "--ruleset", "ddns"],
        )

    def test_secret_url_menu_lists_and_creates(self) -> None:
        calls: list[list[str]] = []
        with patch.object(telegram_bot, "relay_args", self.fake_relay(calls)):
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "secret:list")
            self.assertIn("secret-path", text)
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "secret:create:public")
            self.assertIn("new-secret", text)

    def test_ddns_menu_lists_adds_and_deletes(self) -> None:
        calls: list[list[str]] = []
        with patch.object(telegram_bot, "relay_args", self.fake_relay(calls)):
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:list")
            self.assertIn("mobile.example.com", text)
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:add_ruleset:public")
            self.assertIn("Send the DDNS hostname", text)
            text, _markup = telegram_bot.handle_message(settings(), 123, "home.example.com")
            self.assertIn("DDNS record added", text)
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:delete")
            self.assertIn("mobile.example.com", str(_markup))
            telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:toggle:1")
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:delete_keep_allowlist")
            self.assertIn('"deleted": 1', text)
            self.assertIn('"removed_allow_entries": 0', text)
            telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:delete")
            telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:toggle:1")
            text, _markup = telegram_bot.handle_callback_for_chat(settings(), 123, "ddns:delete_with_allowlist")
            self.assertIn('"removed_allow_entries": 1', text)
        self.assertIn(["ddns", "add", "home.example.com", "--ruleset", "public"], calls)
        self.assertIn(["ddns", "delete", "1", "--keep-allowlist"], calls)
        self.assertIn(["ddns", "delete", "1"], calls)


if __name__ == "__main__":
    unittest.main()
