from __future__ import annotations

import json
import shlex
import time
import urllib.parse
import urllib.request
from typing import Any

from .config import Settings, load_settings
from .exitnode import relay_args, sync_from_relay

PENDING_ACTIONS: dict[int, dict[str, str]] = {}
MAX_MESSAGE = 3900


def api(settings: Settings, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not settings.telegram_token:
        raise RuntimeError("telegram token is missing")
    url = f"https://api.telegram.org/bot{settings.telegram_token}/{method}"
    if isinstance(payload.get("reply_markup"), dict):
        payload = {**payload, "reply_markup": json.dumps(payload["reply_markup"], ensure_ascii=False)}
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=settings.telegram_timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send(settings: Settings, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
    try:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text[:MAX_MESSAGE]}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        api(settings, "sendMessage", payload)
    except Exception:
        pass


def edit(settings: Settings, chat_id: int, message_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
    try:
        payload: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text[:MAX_MESSAGE]}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        api(settings, "editMessageText", payload)
    except Exception:
        send(settings, chat_id, text, reply_markup)


def answer_callback(settings: Settings, callback_id: str, text: str = "") -> None:
    try:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text
        api(settings, "answerCallbackQuery", payload)
    except Exception:
        pass


def authorized(settings: Settings, chat_id: int) -> bool:
    return not settings.telegram_admin_ids or chat_id in settings.telegram_admin_ids


def keyboard(rows: list[list[tuple[str, str]]]) -> dict[str, Any]:
    return {"inline_keyboard": [[{"text": text, "callback_data": data} for text, data in row] for row in rows]}


def main_menu_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            [("Status", "menu:status"), ("Manage", "menu:manage")],
            [("Log", "menu:log"), ("Attack Mode", "menu:attack")],
        ]
    )


def status_keyboard(counts: dict[str, int]) -> dict[str, Any]:
    return keyboard(
        [
            [(f"Whitelisted IPs ({counts.get('allow', 0)})", "status:allow")],
            [(f"Forwarding Rules ({counts.get('rules', 0)})", "status:rules")],
            [(f"Custom Rule Sets ({counts.get('rulesets', 0)})", "status:rulesets")],
            [(f"Blocked IPs ({counts.get('blocked', 0)})", "status:blocked")],
            [("Back", "menu:main")],
        ]
    )


def back_keyboard(target: str = "menu:main") -> dict[str, Any]:
    return keyboard([[("Back", target)]])


def manage_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            [("Add Forwarding Rule", "manage:add_rule")],
            [("Remove Forwarding Rule", "manage:remove_rule")],
            [("Change Rule Sets", "manage:change_rulesets")],
            [("Secret URL", "manage:secret_url")],
            [("Back", "menu:main")],
        ]
    )


def secret_url_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            [("View Active URLs", "secret:list")],
            [("Generate URL", "secret:generate")],
            [("Delete URLs", "secret:delete")],
            [("Back", "menu:manage")],
        ]
    )


def attack_keyboard(mode: str) -> dict[str, Any]:
    on_label = "Attack Mode: ON" if mode == "attack" else "Turn Attack Mode ON"
    off_label = "Regular Mode: ON" if mode == "regular" else "Turn Attack Mode OFF"
    return keyboard(
        [
            [(on_label, "mode:set:attack")],
            [(off_label, "mode:set:regular")],
            [("Back", "menu:main")],
        ]
    )


def relay_text(settings: Settings, args: list[str]) -> tuple[bool, str]:
    ok, out = relay_args(settings, args)
    if not out:
        out = "ok" if ok else "relay command failed without output"
    return ok, out


def relay_json(settings: Settings, args: list[str], fallback: Any) -> tuple[bool, Any, str]:
    ok, out = relay_text(settings, args)
    if not ok:
        return False, fallback, out
    try:
        return True, json.loads(out), out
    except json.JSONDecodeError:
        return False, fallback, f"relay returned non-JSON output:\n{out[:1000]}"


def short_time(value: Any) -> str:
    if value in (None, "", 0):
        return "never"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(value)))
    except (TypeError, ValueError, OSError):
        return str(value)


def one_line(value: Any, default: str = "-") -> str:
    text = str(value if value not in (None, "") else default)
    return " ".join(text.split())


def format_source(entry: dict[str, Any]) -> str:
    return (
        f"#{entry.get('id')} {entry.get('source')} "
        f"({entry.get('ruleset')}/{entry.get('channel')}, /{entry.get('prefix_len') or '?'})\n"
        f"  geo: {one_line(entry.get('geo'), 'unknown')}; isp: {one_line(entry.get('isp'), 'unknown')}\n"
        f"  created: {short_time(entry.get('created_at'))}; expires: {short_time(entry.get('expires_at'))}\n"
        f"  note: {one_line(entry.get('note'))}"
    )


def format_rule(rule: dict[str, Any]) -> str:
    source_count = len(rule.get("effective_sources") or [])
    custom = ",".join(rule.get("rulesets") or []) or "none"
    public = "yes" if rule.get("include_public") else "no"
    access = "open" if rule.get("open_access") else f"restricted ({source_count} sources)"
    return (
        f"{rule.get('lport')} -> {rule.get('target')}\n"
        f"  access: {access}; public ruleset: {public}; custom: {custom}\n"
        f"  note: {one_line(rule.get('note'))}"
    )


def format_block(row: dict[str, Any]) -> str:
    return (
        f"#{row.get('id')} {row.get('source_ip')} -> {row.get('proto')}/{row.get('lport')} "
        f"count={row.get('count')}\n"
        f"  first: {short_time(row.get('first_seen'))}; last: {short_time(row.get('last_seen'))}\n"
        f"  geo: {one_line(row.get('geo'), 'unknown')}; isp: {one_line(row.get('isp'), 'unknown')}"
    )


def public_secret_url(settings: Settings, row: dict[str, Any]) -> str:
    if row.get("url"):
        return str(row["url"])
    path = row.get("secret_path")
    if not path:
        return "(hidden)"
    host = settings.phone_public_host or settings.relay_host or "configured-host"
    port = f":{settings.phone_public_port}" if settings.phone_public_port not in {80, 443} else ""
    return f"{settings.phone_public_scheme}://{host}{port}/{path}"


def format_secret_url(settings: Settings, row: dict[str, Any]) -> str:
    return (
        f"#{row.get('id')} {one_line(row.get('label'), 'url')} -> {row.get('ruleset', 'public')}\n"
        f"  hits: {row.get('hit_count', 0)}; created: {short_time(row.get('created_at'))}; last used: {short_time(row.get('last_used_at'))}\n"
        f"  {public_secret_url(settings, row)}"
    )


def status_counts(settings: Settings) -> tuple[dict[str, int], str]:
    start = time.monotonic()
    ok_status, raw_status = relay_text(settings, ["status"])
    latency_ms = int((time.monotonic() - start) * 1000)
    if not ok_status:
        low = raw_status.lower()
        if "timeout" in low:
            latency = f"Relay SSH: timeout after {settings.ssh_timeout}s"
        else:
            latency = f"Relay SSH: failed ({one_line(raw_status, 'unknown')[:120]})"
        return {"allow": 0, "rules": 0, "rulesets": 0, "blocked": 0}, f"Status\n{latency}\n\nRelay status error:\n{raw_status}"
    try:
        status_data = json.loads(raw_status)
    except json.JSONDecodeError:
        return {"allow": 0, "rules": 0, "rulesets": 0, "blocked": 0}, f"Status\nRelay SSH: {latency_ms} ms\n\nRelay returned non-JSON status."
    latency = f"Relay SSH: {latency_ms} ms"
    ok_allow, allow_rows, _ = relay_json(settings, ["allow-list"], [])
    ok_rules, rule_rows, _ = relay_json(settings, ["list"], [])
    ok_blocked, blocked_rows, _ = relay_json(settings, ["blocked", "--limit", "1000"], [])
    ok_rulesets, rulesets_text = relay_text(settings, ["ruleset", "list"])
    ruleset_count = (
        len([line for line in rulesets_text.splitlines() if line.strip() and not line.startswith("public\t")])
        if ok_rulesets
        else 0
    )
    counts = {
        "allow": len(allow_rows) if ok_allow and isinstance(allow_rows, list) else int(status_data.get("active_allow_entries", 0)),
        "rules": len(rule_rows) if ok_rules and isinstance(rule_rows, list) else int(status_data.get("rules", 0)),
        "rulesets": ruleset_count,
        "blocked": len(blocked_rows) if ok_blocked and isinstance(blocked_rows, list) else int(status_data.get("blocked_visible", 0)),
    }
    mode = one_line(status_data.get("mode"), "unknown")
    return counts, f"Status\nMode: {mode}\n{latency}\n\nChoose a category for details."


def render_status_menu(settings: Settings) -> tuple[str, dict[str, Any]]:
    counts, text = status_counts(settings)
    return text, status_keyboard(counts)


def render_status_detail(settings: Settings, category: str) -> str:
    if category == "allow":
        ok, rows, out = relay_json(settings, ["allow-list"], [])
        if not ok:
            return f"Whitelisted IPs\n{out}"
        rows = sorted(rows, key=lambda x: int(x.get("created_at") or 0), reverse=True)
        body = "\n\n".join(format_source(row) for row in rows[:20]) or "No whitelist entries."
        return f"Whitelisted IPs ({len(rows)})\n\n{body}"
    if category == "rules":
        ok, rows, out = relay_json(settings, ["list"], [])
        if not ok:
            return f"Forwarding Rules\n{out}"
        body = "\n\n".join(format_rule(row) for row in rows[:20]) or "No forwarding rules."
        return f"Forwarding Rules ({len(rows)})\n\n{body}"
    if category == "rulesets":
        ok, out = relay_text(settings, ["ruleset", "list"])
        if not ok:
            return f"Custom Rule Sets\nrelay error: {out}"
        rows = [line for line in out.splitlines() if line.strip() and not line.startswith("public\t")]
        return f"Custom Rule Sets ({len(rows)})\n\n" + ("\n".join(rows[:30]) or "No custom rule sets.")
    if category == "blocked":
        ok, rows, out = relay_json(settings, ["blocked", "--limit", "20"], [])
        if not ok:
            return f"Blocked IPs\n{out}"
        body = "\n\n".join(format_block(row) for row in rows) or "No visible blocked IPs."
        return f"Blocked IPs ({len(rows)} shown)\n\n{body}"
    return "Unknown status category."


def render_log(settings: Settings) -> str:
    ok_allow, allow_rows, allow_out = relay_json(settings, ["allow-list"], [])
    ok_blocked, blocked_rows, blocked_out = relay_json(settings, ["blocked", "--limit", "5"], [])
    if ok_allow and isinstance(allow_rows, list) and allow_rows:
        latest = sorted(allow_rows, key=lambda x: int(x.get("created_at") or 0), reverse=True)[0]
        allow_text = format_source(latest)
    elif ok_allow:
        allow_text = "No whitelist entries."
    else:
        allow_text = f"relay error: {allow_out}"
    if ok_blocked and isinstance(blocked_rows, list):
        blocked_text = "\n\n".join(format_block(row) for row in blocked_rows) or "No visible blocked IPs."
    else:
        blocked_text = f"relay error: {blocked_out}"
    return f"Log\n\nMost Recent Whitelist Entry\n{allow_text}\n\nMost Recent Blocked IPs\n{blocked_text}"


def render_secret_url_menu() -> tuple[str, dict[str, Any]]:
    return "Secret URL\nChoose an action.", secret_url_keyboard()


def render_secret_url_list(settings: Settings) -> tuple[str, dict[str, Any]]:
    ok, rows, out = relay_json(settings, ["secret-url", "list", "--include-secrets"], [])
    if not ok:
        return f"Secret URL\nrelay error: {out}", secret_url_keyboard()
    body = "\n\n".join(format_secret_url(settings, row) for row in rows) or "No active Secret URLs."
    return f"Active Secret URLs ({len(rows)})\n\n{body}", secret_url_keyboard()


def ruleset_names(settings: Settings) -> list[str]:
    ok, out = relay_text(settings, ["ruleset", "list"])
    names = ["public"]
    if ok:
        for line in out.splitlines():
            name = line.split("\t", 1)[0].strip()
            if name and name not in names:
                names.append(name)
    return names


def render_secret_generate(settings: Settings) -> tuple[str, dict[str, Any]]:
    rows = [[(name, f"secret:create:{name}")] for name in ruleset_names(settings)[:20]]
    rows.append([("Back", "manage:secret_url")])
    return "Generate Secret URL\nChoose the target ruleset.", keyboard(rows)


def render_secret_delete(settings: Settings, chat_id: int) -> tuple[str, dict[str, Any]]:
    ok, rows, out = relay_json(settings, ["secret-url", "list", "--include-secrets"], [])
    if not ok:
        return f"Delete Secret URLs\nrelay error: {out}", secret_url_keyboard()
    selected = set()
    pending = PENDING_ACTIONS.get(chat_id)
    if pending and pending.get("action") == "secret_delete":
        selected = {int(x) for x in pending.get("selected", "").split(",") if x}
    PENDING_ACTIONS[chat_id] = {"action": "secret_delete", "selected": ",".join(str(x) for x in sorted(selected))}
    button_rows: list[list[tuple[str, str]]] = []
    for row in rows[:20]:
        rid = int(row["id"])
        mark = "[x]" if rid in selected else "[ ]"
        button_rows.append([(f"{mark} #{rid} {one_line(row.get('label'), 'url')}", f"secret:toggle:{rid}")])
    button_rows.append([("Delete Selected", "secret:delete_selected"), ("Clear", "secret:clear_delete")])
    button_rows.append([("Back", "manage:secret_url")])
    return "Delete Secret URLs\nSelect one or more URLs, then delete selected.", keyboard(button_rows)


def render_attack(settings: Settings) -> tuple[str, dict[str, Any]]:
    ok, out = relay_text(settings, ["mode"])
    mode = out.strip() if ok else "unknown"
    text = (
        "Attack Mode\n"
        f"Current mode: {mode}\n\n"
        "Attack mode freezes automatic SSH/DDNS/web additions. Manual edits still work."
    )
    return text, attack_keyboard(mode)


def parse_ruleset_token(value: str | None) -> tuple[bool, list[str]]:
    if not value or value.lower() in {"public", "default", "-"}:
        return True, []
    if value.lower() in {"none", "no-public"}:
        return False, []
    if value.lower().startswith("public+"):
        names = [x for x in value[7:].split(",") if x]
        return True, names
    return False, [x for x in value.split(",") if x]


def rule_by_lport(settings: Settings, lport: int) -> tuple[dict[str, Any] | None, str]:
    ok, rows, out = relay_json(settings, ["list"], [])
    if not ok:
        return None, out
    for row in rows:
        if int(row.get("lport", -1)) == lport:
            return row, ""
    return None, f"rule not found: {lport}"


def set_pending(chat_id: int, action: str) -> str:
    PENDING_ACTIONS[chat_id] = {"action": action}
    if action == "add_rule":
        return (
            "Add Forwarding Rule\n"
            "Send one line:\n"
            "local_port target_ip target_port [rulesets] [note]\n\n"
            "Rulesets examples:\n"
            "public = public ruleset only\n"
            "public+ddns = public plus custom ddns\n"
            "ddns = custom ddns ruleset only\n"
            "none = no ruleset sources yet"
        )
    if action == "remove_rule":
        return "Remove Forwarding Rule\nSend the local listening port to delete."
    if action == "change_rulesets":
        return (
            "Change Rule Sets\n"
            "Send one line:\n"
            "local_port rulesets\n\n"
            "Examples:\n"
            "58495 public\n"
            "58495 public+ddns\n"
            "58495 ddns\n"
            "58495 none"
        )
    return "Unknown manage action."


def handle_pending(settings: Settings, chat_id: int, text: str) -> tuple[str, dict[str, Any]]:
    pending = PENDING_ACTIONS.pop(chat_id, None)
    if not pending:
        return handle_command(settings, text), main_menu_keyboard()
    try:
        parts = shlex.split(text)
    except ValueError as exc:
        return f"Could not parse input: {exc}", manage_keyboard()
    action = pending.get("action")
    if action == "add_rule":
        if len(parts) < 3:
            return set_pending(chat_id, "add_rule"), manage_keyboard()
        lport, dest_ip, dest_port = parts[0], parts[1], parts[2]
        include_public, rulesets = parse_ruleset_token(parts[3] if len(parts) >= 4 else "public")
        note = " ".join(parts[4:]) if len(parts) >= 5 else ""
        args = ["add-rule", lport, dest_ip, dest_port]
        if note:
            args += ["--note", note]
        for ruleset in rulesets:
            args += ["--ruleset", ruleset]
        if not include_public:
            args += ["--no-public"]
        ok, out = relay_text(settings, args)
        return (out if ok else f"relay error: {out}"), manage_keyboard()
    if action == "remove_rule":
        if len(parts) != 1:
            return set_pending(chat_id, "remove_rule"), manage_keyboard()
        ok, out = relay_text(settings, ["delete-rule", parts[0]])
        return (out if ok else f"relay error: {out}"), manage_keyboard()
    if action == "change_rulesets":
        if len(parts) != 2:
            return set_pending(chat_id, "change_rulesets"), manage_keyboard()
        try:
            lport = int(parts[0])
        except ValueError:
            return "Local port must be a number.", manage_keyboard()
        rule, err = rule_by_lport(settings, lport)
        if not rule:
            return f"relay error: {err}", manage_keyboard()
        include_public, rulesets = parse_ruleset_token(parts[1])
        target = str(rule.get("target", ""))
        if ":" not in target:
            return f"relay error: malformed target for {lport}: {target}", manage_keyboard()
        dest_ip, dest_port = target.rsplit(":", 1)
        args = ["add-rule", str(lport), dest_ip, dest_port]
        if rule.get("note"):
            args += ["--note", str(rule["note"])]
        for ruleset in rulesets:
            args += ["--ruleset", ruleset]
        if not include_public:
            args += ["--no-public"]
        if rule.get("open_access"):
            args += ["--open"]
        ok, out = relay_text(settings, args)
        return (out if ok else f"relay error: {out}"), manage_keyboard()
    return "Unknown pending action.", manage_keyboard()


def handle_command(settings: Settings, text: str) -> str:
    parts = text.strip().split()
    if not parts:
        return "empty command"
    cmd = parts[0].lower()
    if cmd in {"/start", "/help", "/menu"}:
        return (
            "Open the button menu with /menu.\n\n"
            "Text commands still work:\n"
            "/status\n/mode regular|attack\n/allow <ip|cidr|range> [ruleset]\n"
            "/remove_allow <id>\n/blocked [limit]\n/promote <blocked_id> [32|24] [ruleset]\n/delete_block <id>\n/ddns"
        )
    if cmd == "/status":
        ok, out = relay_args(settings, ["status"])
        return out if ok else f"relay error: {out}"
    if cmd == "/mode" and len(parts) == 2:
        ok, out = relay_args(settings, ["mode", parts[1]])
        return out if ok else f"relay error: {out}"
    if cmd == "/allow" and len(parts) >= 2:
        ruleset = parts[2] if len(parts) >= 3 else "public"
        ok, out = relay_args(settings, ["allow", parts[1], "--ruleset", ruleset, "--channel", "manual"])
        return out if ok else f"relay error: {out}"
    if cmd == "/remove_allow" and len(parts) == 2:
        ok, out = relay_args(settings, ["remove-allow", parts[1]])
        return out if ok else f"relay error: {out}"
    if cmd == "/blocked":
        limit = parts[1] if len(parts) > 1 else "20"
        ok, out = relay_args(settings, ["blocked", "--limit", limit])
        return out if ok else f"relay error: {out}"
    if cmd == "/promote" and len(parts) >= 2:
        prefix = parts[2] if len(parts) >= 3 else "24"
        ruleset = parts[3] if len(parts) >= 4 else "public"
        ok, out = relay_args(settings, ["promote-block", parts[1], "--prefix", prefix, "--ruleset", ruleset])
        return out if ok else f"relay error: {out}"
    if cmd == "/delete_block" and len(parts) == 2:
        ok, out = relay_args(settings, ["delete-block", parts[1]])
        return out if ok else f"relay error: {out}"
    if cmd == "/ddns":
        ok, out = relay_args(settings, ["sync-ddns"])
        return out if ok else f"relay error: {out}"
    return "unknown or malformed command; use /help"


def handle_callback(settings: Settings, data: str) -> tuple[str, dict[str, Any] | None]:
    if data == "menu:main":
        return "nft-forward menu", main_menu_keyboard()
    if data == "menu:status":
        return render_status_menu(settings)
    if data.startswith("status:"):
        return render_status_detail(settings, data.split(":", 1)[1]), back_keyboard("menu:status")
    if data == "menu:manage":
        return "Manage\nChoose an action.", manage_keyboard()
    if data == "menu:log":
        return render_log(settings), back_keyboard("menu:main")
    if data == "menu:attack":
        return render_attack(settings)
    if data.startswith("mode:set:"):
        mode = data.rsplit(":", 1)[1]
        ok, out = relay_text(settings, ["mode", mode])
        if not ok:
            return f"Attack Mode\nrelay error: {out}", back_keyboard("menu:attack")
        return render_attack(settings)
    return "Unknown menu action.", main_menu_keyboard()


def handle_callback_for_chat(settings: Settings, chat_id: int, data: str) -> tuple[str, dict[str, Any] | None]:
    if data == "manage:secret_url":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_secret_url_menu()
    if data == "secret:list":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_secret_url_list(settings)
    if data == "secret:generate":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_secret_generate(settings)
    if data.startswith("secret:create:"):
        ruleset = data.split(":", 2)[2]
        ok, out = relay_text(settings, ["secret-url", "create", "--ruleset", ruleset])
        if ok:
            sync_from_relay(settings)
            try:
                row = json.loads(out)
                return "Secret URL created\n\n" + format_secret_url(settings, row), secret_url_keyboard()
            except json.JSONDecodeError:
                return f"Secret URL created\n{out}", secret_url_keyboard()
        return f"Secret URL\nrelay error: {out}", secret_url_keyboard()
    if data == "secret:delete":
        return render_secret_delete(settings, chat_id)
    if data.startswith("secret:toggle:"):
        rid = int(data.rsplit(":", 1)[1])
        pending = PENDING_ACTIONS.get(chat_id, {"action": "secret_delete", "selected": ""})
        selected = {int(x) for x in pending.get("selected", "").split(",") if x}
        if rid in selected:
            selected.remove(rid)
        else:
            selected.add(rid)
        PENDING_ACTIONS[chat_id] = {"action": "secret_delete", "selected": ",".join(str(x) for x in sorted(selected))}
        return render_secret_delete(settings, chat_id)
    if data == "secret:clear_delete":
        PENDING_ACTIONS[chat_id] = {"action": "secret_delete", "selected": ""}
        return render_secret_delete(settings, chat_id)
    if data == "secret:delete_selected":
        pending = PENDING_ACTIONS.get(chat_id, {"selected": ""})
        ids = [x for x in pending.get("selected", "").split(",") if x]
        if not ids:
            return "Delete Secret URLs\nNo URLs selected.", secret_url_keyboard()
        ok, out = relay_text(settings, ["secret-url", "delete"] + ids)
        PENDING_ACTIONS.pop(chat_id, None)
        sync_from_relay(settings)
        return (out if ok else f"relay error: {out}"), secret_url_keyboard()
    if data.startswith("manage:"):
        action = data.split(":", 1)[1]
        return set_pending(chat_id, action), manage_keyboard()
    if not data.startswith("manage:"):
        PENDING_ACTIONS.pop(chat_id, None)
    return handle_callback(settings, data)


def handle_message(settings: Settings, chat_id: int, text: str) -> tuple[str, dict[str, Any] | None]:
    if chat_id in PENDING_ACTIONS and not text.startswith("/"):
        return handle_pending(settings, chat_id, text)
    if text.strip().lower() in {"/start", "/help", "/menu"}:
        return "nft-forward menu", main_menu_keyboard()
    return handle_command(settings, text), None


def run() -> None:
    settings = load_settings()
    offset = 0
    backoff = 2
    while True:
        try:
            data = api(settings, "getUpdates", {"timeout": 20, "offset": offset})
            for item in data.get("result", []):
                offset = max(offset, int(item["update_id"]) + 1)
                callback = item.get("callback_query")
                if callback:
                    callback_id = callback.get("id", "")
                    msg = callback.get("message") or {}
                    chat = msg.get("chat") or {}
                    chat_id = int(chat.get("id", 0))
                    message_id = int(msg.get("message_id", 0))
                    if not authorized(settings, chat_id):
                        answer_callback(settings, callback_id, "unauthorized")
                        continue
                    answer_callback(settings, callback_id)
                    text, markup = handle_callback_for_chat(settings, chat_id, callback.get("data") or "")
                    edit(settings, chat_id, message_id, text, markup)
                    continue
                msg = item.get("message") or {}
                chat = msg.get("chat") or {}
                chat_id = int(chat.get("id", 0))
                if not authorized(settings, chat_id):
                    send(settings, chat_id, "unauthorized")
                    continue
                text = msg.get("text") or ""
                if text:
                    reply, markup = handle_message(settings, chat_id, text)
                    send(settings, chat_id, reply, markup)
            backoff = 2
        except Exception:
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
