from __future__ import annotations

import json
import shlex
import time
import traceback
import urllib.parse
import urllib.request
from typing import Any

from .config import Settings, load_settings
from .exitnode import relay_args, sync_from_relay

PENDING_ACTIONS: dict[int, dict[str, str]] = {}
MAX_MESSAGE = 3900


LABELS = {
    "status": ("Status", "状态"),
    "manage": ("Manage", "管理"),
    "log": ("Log", "日志"),
    "attack_mode": ("Attack Mode", "攻击模式"),
    "back": ("Back", "返回"),
    "whitelist": ("Whitelisted IPs", "白名单 IP"),
    "rules": ("Forwarding Rules", "转发规则"),
    "rulesets": ("Custom Rule Sets", "自定义规则集"),
    "blocked": ("Blocked IPs", "拦截 IP"),
    "add_rule": ("Add Forwarding Rule", "新增转发规则"),
    "remove_rule": ("Remove Forwarding Rule", "删除转发规则"),
    "change_rulesets": ("Change Rule Sets", "修改规则集"),
    "secret_url": ("Secret URL", "Secret URL"),
    "ddns": ("DDNS", "DDNS"),
    "view_urls": ("View Active URLs", "查看启用 URL"),
    "generate_url": ("Generate URL", "生成 URL"),
    "delete_urls": ("Delete URLs", "删除 URL"),
    "view_records": ("View Records", "查看记录"),
    "add_record": ("Add Record", "新增记录"),
    "delete_records": ("Delete Records", "删除记录"),
    "refresh_now": ("Refresh Now", "立即刷新"),
    "delete_records_only": ("Delete Records Only", "仅删除记录"),
    "delete_with_whitelist": ("Delete + Whitelist", "删除记录和白名单"),
    "clear": ("Clear", "清空选择"),
    "turn_attack_on": ("Turn Attack Mode ON", "开启攻击模式"),
    "turn_attack_off": ("Turn Attack Mode OFF", "关闭攻击模式"),
    "attack_on": ("Attack Mode: ON", "攻击模式：已开启"),
    "regular_on": ("Regular Mode: ON", "常规模式：已开启"),
}


def is_zh(settings: Settings | None) -> bool:
    return bool(settings and settings.language == "zh")


def text(settings: Settings | None, en: str, zh: str) -> str:
    return zh if is_zh(settings) else en


def label(settings: Settings | None, key: str) -> str:
    en, zh = LABELS[key]
    return zh if is_zh(settings) else en


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
        traceback.print_exc()


def edit(settings: Settings, chat_id: int, message_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
    try:
        payload: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text[:MAX_MESSAGE]}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        api(settings, "editMessageText", payload)
    except Exception:
        traceback.print_exc()
        send(settings, chat_id, text, reply_markup)


def answer_callback(settings: Settings, callback_id: str, text: str = "") -> None:
    try:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text
        api(settings, "answerCallbackQuery", payload)
    except Exception:
        traceback.print_exc()


def authorized(settings: Settings, chat_id: int) -> bool:
    return not settings.telegram_admin_ids or chat_id in settings.telegram_admin_ids


def keyboard(rows: list[list[tuple[str, str]]]) -> dict[str, Any]:
    return {"inline_keyboard": [[{"text": text, "callback_data": data} for text, data in row] for row in rows]}


def main_menu_keyboard(settings: Settings | None = None) -> dict[str, Any]:
    return keyboard(
        [
            [(label(settings, "status"), "menu:status"), (label(settings, "manage"), "menu:manage")],
            [(label(settings, "log"), "menu:log"), (label(settings, "attack_mode"), "menu:attack")],
        ]
    )


def status_keyboard(settings: Settings | None, counts: dict[str, int]) -> dict[str, Any]:
    return keyboard(
        [
            [(f"{label(settings, 'whitelist')} ({counts.get('allow', 0)})", "status:allow")],
            [(f"{label(settings, 'rules')} ({counts.get('rules', 0)})", "status:rules")],
            [(f"{label(settings, 'rulesets')} ({counts.get('rulesets', 0)})", "status:rulesets")],
            [(f"{label(settings, 'blocked')} ({counts.get('blocked', 0)})", "status:blocked")],
            [(label(settings, "back"), "menu:main")],
        ]
    )


def back_keyboard(target: str = "menu:main", settings: Settings | None = None) -> dict[str, Any]:
    return keyboard([[(label(settings, "back"), target)]])


def manage_keyboard(settings: Settings | None = None) -> dict[str, Any]:
    return keyboard(
        [
            [(label(settings, "add_rule"), "manage:add_rule")],
            [(label(settings, "remove_rule"), "manage:remove_rule")],
            [(label(settings, "change_rulesets"), "manage:change_rulesets")],
            [(label(settings, "secret_url"), "manage:secret_url")],
            [(label(settings, "ddns"), "manage:ddns")],
            [(label(settings, "back"), "menu:main")],
        ]
    )


def secret_url_keyboard(settings: Settings | None = None) -> dict[str, Any]:
    return keyboard(
        [
            [(label(settings, "view_urls"), "secret:list")],
            [(label(settings, "generate_url"), "secret:generate")],
            [(label(settings, "delete_urls"), "secret:delete")],
            [(label(settings, "back"), "menu:manage")],
        ]
    )


def ddns_keyboard(settings: Settings | None = None) -> dict[str, Any]:
    return keyboard(
        [
            [(label(settings, "view_records"), "ddns:list")],
            [(label(settings, "add_record"), "ddns:add")],
            [(label(settings, "delete_records"), "ddns:delete")],
            [(label(settings, "refresh_now"), "ddns:refresh")],
            [(label(settings, "back"), "menu:manage")],
        ]
    )


def attack_keyboard(settings: Settings | None, mode: str) -> dict[str, Any]:
    on_label = label(settings, "attack_on") if mode == "attack" else label(settings, "turn_attack_on")
    off_label = label(settings, "regular_on") if mode == "regular" else label(settings, "turn_attack_off")
    return keyboard(
        [
            [(on_label, "mode:set:attack")],
            [(off_label, "mode:set:regular")],
            [(label(settings, "back"), "menu:main")],
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


def format_source(settings: Settings, entry: dict[str, Any]) -> str:
    if is_zh(settings):
        return (
            f"#{entry.get('id')} {entry.get('source')} "
            f"({entry.get('ruleset')}/{entry.get('channel')}, /{entry.get('prefix_len') or '?'})\n"
            f"  地理: {one_line(entry.get('geo'), 'unknown')}; ISP: {one_line(entry.get('isp'), 'unknown')}\n"
            f"  创建: {short_time(entry.get('created_at'))}; 过期: {short_time(entry.get('expires_at'))}\n"
            f"  备注: {one_line(entry.get('note'))}"
        )
    return (
        f"#{entry.get('id')} {entry.get('source')} "
        f"({entry.get('ruleset')}/{entry.get('channel')}, /{entry.get('prefix_len') or '?'})\n"
        f"  geo: {one_line(entry.get('geo'), 'unknown')}; isp: {one_line(entry.get('isp'), 'unknown')}\n"
        f"  created: {short_time(entry.get('created_at'))}; expires: {short_time(entry.get('expires_at'))}\n"
        f"  note: {one_line(entry.get('note'))}"
    )


def format_rule(settings: Settings, rule: dict[str, Any]) -> str:
    source_count = len(rule.get("effective_sources") or [])
    custom = ",".join(rule.get("rulesets") or []) or "none"
    if is_zh(settings):
        public = "是" if rule.get("include_public") else "否"
        access = "开放" if rule.get("open_access") else f"受限（{source_count} 个来源）"
        return (
            f"{rule.get('lport')} -> {rule.get('target')}\n"
            f"  访问: {access}; 公共规则集: {public}; 自定义: {custom}\n"
            f"  备注: {one_line(rule.get('note'))}"
        )
    public = "yes" if rule.get("include_public") else "no"
    access = "open" if rule.get("open_access") else f"restricted ({source_count} sources)"
    return (
        f"{rule.get('lport')} -> {rule.get('target')}\n"
        f"  access: {access}; public ruleset: {public}; custom: {custom}\n"
        f"  note: {one_line(rule.get('note'))}"
    )


def format_block(settings: Settings, row: dict[str, Any]) -> str:
    if is_zh(settings):
        return (
            f"#{row.get('id')} {row.get('source_ip')} -> {row.get('proto')}/{row.get('lport')} "
            f"次数={row.get('count')}\n"
            f"  首次: {short_time(row.get('first_seen'))}; 最近: {short_time(row.get('last_seen'))}\n"
            f"  地理: {one_line(row.get('geo'), 'unknown')}; ISP: {one_line(row.get('isp'), 'unknown')}"
        )
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
    if is_zh(settings):
        return (
            f"#{row.get('id')} {one_line(row.get('label'), 'url')} -> {row.get('ruleset', 'public')}\n"
            f"  命中: {row.get('hit_count', 0)}; 创建: {short_time(row.get('created_at'))}; 最近使用: {short_time(row.get('last_used_at'))}\n"
            f"  {public_secret_url(settings, row)}"
        )
    return (
        f"#{row.get('id')} {one_line(row.get('label'), 'url')} -> {row.get('ruleset', 'public')}\n"
        f"  hits: {row.get('hit_count', 0)}; created: {short_time(row.get('created_at'))}; last used: {short_time(row.get('last_used_at'))}\n"
        f"  {public_secret_url(settings, row)}"
    )


def format_ddns(settings: Settings, row: dict[str, Any]) -> str:
    status = text(settings, "enabled", "启用") if row.get("enabled", True) else text(settings, "disabled", "停用")
    return f"#{row.get('id')} {row.get('host')} -> {row.get('ruleset', 'public')} ({status})"


def status_counts(settings: Settings) -> tuple[dict[str, int], str]:
    start = time.monotonic()
    ok_status, raw_status = relay_text(settings, ["bot-status"])
    latency_ms = int((time.monotonic() - start) * 1000)
    if not ok_status:
        ok_status, raw_status = relay_text(settings, ["status"])
        latency_ms = int((time.monotonic() - start) * 1000)
        if not ok_status:
            low = raw_status.lower()
            if "timeout" in low:
                latency = text(settings, f"Relay SSH: timeout after {settings.ssh_timeout}s", f"Relay SSH：{settings.ssh_timeout} 秒后超时")
            else:
                latency = text(
                    settings,
                    f"Relay SSH: failed ({one_line(raw_status, 'unknown')[:120]})",
                    f"Relay SSH：失败（{one_line(raw_status, 'unknown')[:120]}）",
                )
            return {"allow": 0, "rules": 0, "rulesets": 0, "blocked": 0}, text(
                settings,
                f"Status\n{latency}\n\nRelay status error:\n{raw_status}",
                f"状态\n{latency}\n\n中继状态错误：\n{raw_status}",
            )
    try:
        status_data = json.loads(raw_status)
    except json.JSONDecodeError:
        return {"allow": 0, "rules": 0, "rulesets": 0, "blocked": 0}, text(
            settings,
            f"Status\nRelay SSH: {latency_ms} ms\n\nRelay returned non-JSON status.",
            f"状态\nRelay SSH：{latency_ms} ms\n\n中继返回的状态不是 JSON。",
        )
    latency = text(settings, f"Relay SSH: {latency_ms} ms", f"Relay SSH：{latency_ms} ms")
    counts = {
        "allow": int(status_data.get("allow", status_data.get("active_allow_entries", 0))),
        "rules": int(status_data.get("rules", 0)),
        "rulesets": int(status_data.get("rulesets", 0)),
        "blocked": int(status_data.get("blocked", status_data.get("blocked_visible", 0))),
    }
    mode = one_line(status_data.get("mode"), "unknown")
    return counts, text(
        settings,
        f"Status\nMode: {mode}\n{latency}\n\nChoose a category for details.",
        f"状态\n当前模式：{mode}\n{latency}\n\n请选择类别查看详情。",
    )


def render_status_menu(settings: Settings) -> tuple[str, dict[str, Any]]:
    counts, text = status_counts(settings)
    return text, status_keyboard(settings, counts)


def render_status_detail(settings: Settings, category: str) -> str:
    if category == "allow":
        ok, rows, out = relay_json(settings, ["allow-list"], [])
        if not ok:
            return text(settings, f"Whitelisted IPs\n{out}", f"白名单 IP\n{out}")
        rows = sorted(rows, key=lambda x: int(x.get("created_at") or 0), reverse=True)
        body = "\n\n".join(format_source(settings, row) for row in rows[:20]) or text(settings, "No whitelist entries.", "没有白名单记录。")
        return text(settings, f"Whitelisted IPs ({len(rows)})\n\n{body}", f"白名单 IP（{len(rows)}）\n\n{body}")
    if category == "rules":
        ok, rows, out = relay_json(settings, ["list"], [])
        if not ok:
            return text(settings, f"Forwarding Rules\n{out}", f"转发规则\n{out}")
        body = "\n\n".join(format_rule(settings, row) for row in rows[:20]) or text(settings, "No forwarding rules.", "没有转发规则。")
        return text(settings, f"Forwarding Rules ({len(rows)})\n\n{body}", f"转发规则（{len(rows)}）\n\n{body}")
    if category == "rulesets":
        ok, out = relay_text(settings, ["ruleset", "list"])
        if not ok:
            return text(settings, f"Custom Rule Sets\nrelay error: {out}", f"自定义规则集\n中继错误：{out}")
        rows = [line for line in out.splitlines() if line.strip() and not line.startswith("public\t")]
        body = "\n".join(rows[:30]) or text(settings, "No custom rule sets.", "没有自定义规则集。")
        return text(settings, f"Custom Rule Sets ({len(rows)})\n\n{body}", f"自定义规则集（{len(rows)}）\n\n{body}")
    if category == "blocked":
        ok, rows, out = relay_json(settings, ["blocked", "--limit", "20"], [])
        if not ok:
            return text(settings, f"Blocked IPs\n{out}", f"拦截 IP\n{out}")
        body = "\n\n".join(format_block(settings, row) for row in rows) or text(settings, "No visible blocked IPs.", "没有可见的拦截 IP。")
        return text(settings, f"Blocked IPs ({len(rows)} shown)\n\n{body}", f"拦截 IP（显示 {len(rows)} 条）\n\n{body}")
    return text(settings, "Unknown status category.", "未知状态类别。")


def render_log(settings: Settings) -> str:
    ok_allow, allow_rows, allow_out = relay_json(settings, ["allow-list"], [])
    ok_blocked, blocked_rows, blocked_out = relay_json(settings, ["blocked", "--limit", "5"], [])
    if ok_allow and isinstance(allow_rows, list) and allow_rows:
        latest = sorted(allow_rows, key=lambda x: int(x.get("created_at") or 0), reverse=True)[0]
        allow_text = format_source(settings, latest)
    elif ok_allow:
        allow_text = text(settings, "No whitelist entries.", "没有白名单记录。")
    else:
        allow_text = text(settings, f"relay error: {allow_out}", f"中继错误：{allow_out}")
    if ok_blocked and isinstance(blocked_rows, list):
        blocked_text = "\n\n".join(format_block(settings, row) for row in blocked_rows) or text(settings, "No visible blocked IPs.", "没有可见的拦截 IP。")
    else:
        blocked_text = text(settings, f"relay error: {blocked_out}", f"中继错误：{blocked_out}")
    return text(
        settings,
        f"Log\n\nMost Recent Whitelist Entry\n{allow_text}\n\nMost Recent Blocked IPs\n{blocked_text}",
        f"日志\n\n最近白名单记录\n{allow_text}\n\n最近拦截 IP\n{blocked_text}",
    )


def render_secret_url_menu(settings: Settings) -> tuple[str, dict[str, Any]]:
    return text(settings, "Secret URL\nChoose an action.", "Secret URL\n请选择操作。"), secret_url_keyboard(settings)


def render_secret_url_list(settings: Settings) -> tuple[str, dict[str, Any]]:
    ok, rows, out = relay_json(settings, ["secret-url", "list", "--include-secrets"], [])
    if not ok:
        return text(settings, f"Secret URL\nrelay error: {out}", f"Secret URL\n中继错误：{out}"), secret_url_keyboard(settings)
    body = "\n\n".join(format_secret_url(settings, row) for row in rows) or text(settings, "No active Secret URLs.", "没有启用的 Secret URL。")
    return text(settings, f"Active Secret URLs ({len(rows)})\n\n{body}", f"启用的 Secret URL（{len(rows)}）\n\n{body}"), secret_url_keyboard(settings)


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
    rows.append([(label(settings, "back"), "manage:secret_url")])
    return text(settings, "Generate Secret URL\nChoose the target ruleset.", "生成 Secret URL\n请选择目标规则集。"), keyboard(rows)


def render_secret_delete(settings: Settings, chat_id: int) -> tuple[str, dict[str, Any]]:
    ok, rows, out = relay_json(settings, ["secret-url", "list", "--include-secrets"], [])
    if not ok:
        return text(settings, f"Delete Secret URLs\nrelay error: {out}", f"删除 Secret URL\n中继错误：{out}"), secret_url_keyboard(settings)
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
    button_rows.append([(text(settings, "Delete Selected", "删除所选"), "secret:delete_selected"), (label(settings, "clear"), "secret:clear_delete")])
    button_rows.append([(label(settings, "back"), "manage:secret_url")])
    return text(
        settings,
        "Delete Secret URLs\nSelect one or more URLs, then delete selected.",
        "删除 Secret URL\n请选择一个或多个 URL，然后删除所选。",
    ), keyboard(button_rows)


def render_ddns_menu(settings: Settings) -> tuple[str, dict[str, Any]]:
    return text(
        settings,
        "DDNS\nChoose an action. Relay refresh runs every 10 seconds.",
        "DDNS\n请选择操作。中继端每 10 秒刷新一次。",
    ), ddns_keyboard(settings)


def render_ddns_list(settings: Settings) -> tuple[str, dict[str, Any]]:
    ok, rows, out = relay_json(settings, ["ddns", "list"], [])
    if not ok:
        return text(settings, f"DDNS\nrelay error: {out}", f"DDNS\n中继错误：{out}"), ddns_keyboard(settings)
    body = "\n".join(format_ddns(settings, row) for row in rows) or text(settings, "No DDNS records.", "没有 DDNS 记录。")
    return text(settings, f"DDNS Records ({len(rows)})\n\n{body}", f"DDNS 记录（{len(rows)}）\n\n{body}"), ddns_keyboard(settings)


def render_ddns_add(settings: Settings) -> tuple[str, dict[str, Any]]:
    rows = [[(name, f"ddns:add_ruleset:{name}")] for name in ruleset_names(settings)[:20]]
    rows.append([(label(settings, "back"), "manage:ddns")])
    return text(settings, "Add DDNS Record\nChoose the target ruleset.", "新增 DDNS 记录\n请选择目标规则集。"), keyboard(rows)


def render_ddns_delete(settings: Settings, chat_id: int) -> tuple[str, dict[str, Any]]:
    ok, rows, out = relay_json(settings, ["ddns", "list"], [])
    if not ok:
        return text(settings, f"Delete DDNS Records\nrelay error: {out}", f"删除 DDNS 记录\n中继错误：{out}"), ddns_keyboard(settings)
    selected = set()
    pending = PENDING_ACTIONS.get(chat_id)
    if pending and pending.get("action") == "ddns_delete":
        selected = {int(x) for x in pending.get("selected", "").split(",") if x}
    PENDING_ACTIONS[chat_id] = {"action": "ddns_delete", "selected": ",".join(str(x) for x in sorted(selected))}
    button_rows: list[list[tuple[str, str]]] = []
    for row in rows[:20]:
        rid = int(row["id"])
        mark = "[x]" if rid in selected else "[ ]"
        button_rows.append([(f"{mark} #{rid} {one_line(row.get('host'), 'host')}", f"ddns:toggle:{rid}")])
    button_rows.append([(label(settings, "delete_records_only"), "ddns:delete_keep_allowlist")])
    button_rows.append([(label(settings, "delete_with_whitelist"), "ddns:delete_with_allowlist"), (label(settings, "clear"), "ddns:clear_delete")])
    button_rows.append([(label(settings, "back"), "manage:ddns")])
    return text(
        settings,
        "Delete DDNS Records\nSelect one or more records, then choose whether to keep or remove the whitelist entries created by them.",
        "删除 DDNS 记录\n请选择一个或多个记录，然后选择是否同时删除由它们创建的白名单条目。",
    ), keyboard(button_rows)


def render_attack(settings: Settings) -> tuple[str, dict[str, Any]]:
    ok, out = relay_text(settings, ["mode"])
    mode = out.strip() if ok else "unknown"
    body = text(
        settings,
        "Attack Mode\n"
        f"Current mode: {mode}\n\n"
        "Attack mode freezes automatic SSH/DDNS/web additions. Manual edits still work.",
        "攻击模式\n"
        f"当前模式：{mode}\n\n"
        "攻击模式会冻结 SSH/DDNS/Secret URL 自动添加，手动编辑仍然可用。",
    )
    return body, attack_keyboard(settings, mode)


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


def set_pending(chat_id: int, action: str, settings: Settings) -> str:
    PENDING_ACTIONS[chat_id] = {"action": action}
    if action == "add_rule":
        return text(
            settings,
            "Add Forwarding Rule\n"
            "Send one line:\n"
            "local_port target_ip target_port [rulesets] [note]\n\n"
            "Rulesets examples:\n"
            "public = public ruleset only\n"
            "public+ddns = public plus custom ddns\n"
            "ddns = custom ddns ruleset only\n"
            "none = no ruleset sources yet",
            "新增转发规则\n"
            "发送一行：\n"
            "本机端口 目标IP 目标端口 [规则集] [备注]\n\n"
            "规则集示例：\n"
            "public = 只使用公共规则集\n"
            "public+ddns = 公共规则集加自定义 ddns\n"
            "ddns = 只使用自定义 ddns 规则集\n"
            "none = 暂不绑定规则集来源",
        )
    if action == "remove_rule":
        return text(settings, "Remove Forwarding Rule\nSend the local listening port to delete.", "删除转发规则\n发送要删除的本机监听端口。")
    if action == "change_rulesets":
        return text(
            settings,
            "Change Rule Sets\n"
            "Send one line:\n"
            "local_port rulesets\n\n"
            "Examples:\n"
            "58495 public\n"
            "58495 public+ddns\n"
            "58495 ddns\n"
            "58495 none",
            "修改规则集\n"
            "发送一行：\n"
            "本机端口 规则集\n\n"
            "示例：\n"
            "58495 public\n"
            "58495 public+ddns\n"
            "58495 ddns\n"
            "58495 none",
        )
    return text(settings, "Unknown manage action.", "未知管理操作。")


def handle_pending(settings: Settings, chat_id: int, message_text: str) -> tuple[str, dict[str, Any]]:
    pending = PENDING_ACTIONS.pop(chat_id, None)
    if not pending:
        return handle_command(settings, message_text), main_menu_keyboard(settings)
    try:
        parts = shlex.split(message_text)
    except ValueError as exc:
        return text(settings, f"Could not parse input: {exc}", f"无法解析输入：{exc}"), manage_keyboard(settings)
    action = pending.get("action")
    if action == "add_rule":
        if len(parts) < 3:
            return set_pending(chat_id, "add_rule", settings), manage_keyboard(settings)
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
        return (out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")), manage_keyboard(settings)
    if action == "remove_rule":
        if len(parts) != 1:
            return set_pending(chat_id, "remove_rule", settings), manage_keyboard(settings)
        ok, out = relay_text(settings, ["delete-rule", parts[0]])
        return (out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")), manage_keyboard(settings)
    if action == "change_rulesets":
        if len(parts) != 2:
            return set_pending(chat_id, "change_rulesets", settings), manage_keyboard(settings)
        try:
            lport = int(parts[0])
        except ValueError:
            return text(settings, "Local port must be a number.", "本机端口必须是数字。"), manage_keyboard(settings)
        rule, err = rule_by_lport(settings, lport)
        if not rule:
            return text(settings, f"relay error: {err}", f"中继错误：{err}"), manage_keyboard(settings)
        include_public, rulesets = parse_ruleset_token(parts[1])
        target = str(rule.get("target", ""))
        if ":" not in target:
            return text(settings, f"relay error: malformed target for {lport}: {target}", f"中继错误：端口 {lport} 的目标格式异常：{target}"), manage_keyboard(settings)
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
        return (out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")), manage_keyboard(settings)
    if action == "ddns_add":
        if len(parts) != 1:
            return text(
                settings,
                "Add DDNS Record\nSend only the hostname, for example:\nmobile.wl.example.com",
                "新增 DDNS 记录\n只发送主机名，例如：\nmobile.wl.example.com",
            ), ddns_keyboard(settings)
        ruleset = pending.get("ruleset") or "public"
        ok, out = relay_text(settings, ["ddns", "add", parts[0], "--ruleset", ruleset])
        if not ok:
            return text(settings, f"DDNS\nrelay error: {out}", f"DDNS\n中继错误：{out}"), ddns_keyboard(settings)
        refresh_ok, refresh_out = relay_text(settings, ["sync-ddns"])
        suffix = text(settings, f"\n\nRefresh: {refresh_out}", f"\n\n刷新：{refresh_out}") if refresh_ok else text(settings, f"\n\nRefresh failed: {refresh_out}", f"\n\n刷新失败：{refresh_out}")
        return text(settings, f"DDNS record added\n{out}{suffix}", f"DDNS 记录已添加\n{out}{suffix}"), ddns_keyboard(settings)
    return text(settings, "Unknown pending action.", "未知待处理操作。"), manage_keyboard(settings)


def handle_command(settings: Settings, text: str) -> str:
    parts = text.strip().split()
    if not parts:
        return text(settings, "empty command", "空命令")
    cmd = parts[0].lower()
    if cmd in {"/start", "/help", "/menu"}:
        return text(
            settings,
            "Open the button menu with /menu.\n\n"
            "Text commands still work:\n"
            "/status\n/mode regular|attack\n/allow <ip|cidr|range> [ruleset]\n"
            "/remove_allow <id>\n/blocked [limit]\n/promote <blocked_id> [32|24] [ruleset]\n/delete_block <id>\n/ddns",
            "使用 /menu 打开按钮菜单。\n\n"
            "文本命令仍可使用：\n"
            "/status\n/mode regular|attack\n/allow <ip|cidr|range> [ruleset]\n"
            "/remove_allow <id>\n/blocked [limit]\n/promote <blocked_id> [32|24] [ruleset]\n/delete_block <id>\n/ddns",
        )
    if cmd == "/status":
        ok, out = relay_args(settings, ["status"])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/mode" and len(parts) == 2:
        ok, out = relay_args(settings, ["mode", parts[1]])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/allow" and len(parts) >= 2:
        ruleset = parts[2] if len(parts) >= 3 else "public"
        ok, out = relay_args(settings, ["allow", parts[1], "--ruleset", ruleset, "--channel", "manual"])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/remove_allow" and len(parts) == 2:
        ok, out = relay_args(settings, ["remove-allow", parts[1]])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/blocked":
        limit = parts[1] if len(parts) > 1 else "20"
        ok, out = relay_args(settings, ["blocked", "--limit", limit])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/promote" and len(parts) >= 2:
        prefix = parts[2] if len(parts) >= 3 else "24"
        ruleset = parts[3] if len(parts) >= 4 else "public"
        ok, out = relay_args(settings, ["promote-block", parts[1], "--prefix", prefix, "--ruleset", ruleset])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/delete_block" and len(parts) == 2:
        ok, out = relay_args(settings, ["delete-block", parts[1]])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    if cmd == "/ddns":
        ok, out = relay_args(settings, ["sync-ddns"])
        return out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")
    return text(settings, "unknown or malformed command; use /help", "未知或格式错误的命令；请使用 /help")


def handle_callback(settings: Settings, data: str) -> tuple[str, dict[str, Any] | None]:
    if data == "menu:main":
        return text(settings, "NiftGate menu", "NiftGate 菜单"), main_menu_keyboard(settings)
    if data == "menu:status":
        return render_status_menu(settings)
    if data.startswith("status:"):
        return render_status_detail(settings, data.split(":", 1)[1]), back_keyboard("menu:status", settings)
    if data == "menu:manage":
        return text(settings, "Manage\nChoose an action.", "管理\n请选择操作。"), manage_keyboard(settings)
    if data == "menu:log":
        return render_log(settings), back_keyboard("menu:main", settings)
    if data == "menu:attack":
        return render_attack(settings)
    if data.startswith("mode:set:"):
        mode = data.rsplit(":", 1)[1]
        ok, out = relay_text(settings, ["mode", mode])
        if not ok:
            return text(settings, f"Attack Mode\nrelay error: {out}", f"攻击模式\n中继错误：{out}"), back_keyboard("menu:attack", settings)
        return render_attack(settings)
    return text(settings, "Unknown menu action.", "未知菜单操作。"), main_menu_keyboard(settings)


def handle_callback_for_chat(settings: Settings, chat_id: int, data: str) -> tuple[str, dict[str, Any] | None]:
    if data == "manage:secret_url":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_secret_url_menu(settings)
    if data == "manage:ddns":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_ddns_menu(settings)
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
                return text(settings, "Secret URL created\n\n", "Secret URL 已创建\n\n") + format_secret_url(settings, row), secret_url_keyboard(settings)
            except json.JSONDecodeError:
                return text(settings, f"Secret URL created\n{out}", f"Secret URL 已创建\n{out}"), secret_url_keyboard(settings)
        return text(settings, f"Secret URL\nrelay error: {out}", f"Secret URL\n中继错误：{out}"), secret_url_keyboard(settings)
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
            return text(settings, "Delete Secret URLs\nNo URLs selected.", "删除 Secret URL\n尚未选择 URL。"), secret_url_keyboard(settings)
        ok, out = relay_text(settings, ["secret-url", "delete"] + ids)
        PENDING_ACTIONS.pop(chat_id, None)
        sync_from_relay(settings)
        return (out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")), secret_url_keyboard(settings)
    if data == "ddns:list":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_ddns_list(settings)
    if data == "ddns:add":
        PENDING_ACTIONS.pop(chat_id, None)
        return render_ddns_add(settings)
    if data.startswith("ddns:add_ruleset:"):
        ruleset = data.split(":", 2)[2]
        PENDING_ACTIONS[chat_id] = {"action": "ddns_add", "ruleset": ruleset}
        return text(settings, f"Add DDNS Record\nRuleset: {ruleset}\n\nSend the DDNS hostname.", f"新增 DDNS 记录\n规则集：{ruleset}\n\n请发送 DDNS 主机名。"), ddns_keyboard(settings)
    if data == "ddns:delete":
        return render_ddns_delete(settings, chat_id)
    if data.startswith("ddns:toggle:"):
        rid = int(data.rsplit(":", 1)[1])
        pending = PENDING_ACTIONS.get(chat_id, {"action": "ddns_delete", "selected": ""})
        selected = {int(x) for x in pending.get("selected", "").split(",") if x}
        if rid in selected:
            selected.remove(rid)
        else:
            selected.add(rid)
        PENDING_ACTIONS[chat_id] = {"action": "ddns_delete", "selected": ",".join(str(x) for x in sorted(selected))}
        return render_ddns_delete(settings, chat_id)
    if data == "ddns:clear_delete":
        PENDING_ACTIONS[chat_id] = {"action": "ddns_delete", "selected": ""}
        return render_ddns_delete(settings, chat_id)
    if data in {"ddns:delete_selected", "ddns:delete_with_allowlist", "ddns:delete_keep_allowlist"}:
        pending = PENDING_ACTIONS.get(chat_id, {"selected": ""})
        ids = [x for x in pending.get("selected", "").split(",") if x]
        if not ids:
            return text(settings, "Delete DDNS Records\nNo records selected.", "删除 DDNS 记录\n尚未选择记录。"), ddns_keyboard(settings)
        args = ["ddns", "delete"] + ids
        if data == "ddns:delete_keep_allowlist":
            args.append("--keep-allowlist")
        ok, out = relay_text(settings, args)
        PENDING_ACTIONS.pop(chat_id, None)
        return (out if ok else text(settings, f"relay error: {out}", f"中继错误：{out}")), ddns_keyboard(settings)
    if data == "ddns:refresh":
        PENDING_ACTIONS.pop(chat_id, None)
        ok, out = relay_text(settings, ["sync-ddns"])
        return (
            text(settings, f"DDNS Refresh\n{out}", f"DDNS 刷新\n{out}") if ok else text(settings, f"DDNS Refresh\nrelay error: {out}", f"DDNS 刷新\n中继错误：{out}")
        ), ddns_keyboard(settings)
    if data.startswith("manage:"):
        action = data.split(":", 1)[1]
        return set_pending(chat_id, action, settings), manage_keyboard(settings)
    if not data.startswith("manage:"):
        PENDING_ACTIONS.pop(chat_id, None)
    return handle_callback(settings, data)


def handle_message(settings: Settings, chat_id: int, message_text: str) -> tuple[str, dict[str, Any] | None]:
    if chat_id in PENDING_ACTIONS and not message_text.startswith("/"):
        return handle_pending(settings, chat_id, message_text)
    if message_text.strip().lower() in {"/start", "/help", "/menu"}:
        return text(settings, "NiftGate menu", "NiftGate 菜单"), main_menu_keyboard(settings)
    return handle_command(settings, message_text), None


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
            traceback.print_exc()
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
