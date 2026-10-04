from __future__ import annotations

import json
import re
import secrets
import time
from datetime import datetime, timezone

from . import telegram_bot as bot
from .blocked_search import country_key, country_label, normalize_query, parse_time

DRAFTS: dict[str, dict] = {}
VIEWS: dict[str, dict] = {}
UI_TTL = 1800
OPTIONS_PER_PAGE = 8


def tr(settings, en, zh):
    return bot.text(settings, en, zh)


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log_keyboard(settings):
    return bot.keyboard([
        [(tr(settings, "Blocked History", "拦截记录（分页）"), "log:browse"),
         (tr(settings, "Advanced Search", "高级搜索"), "log:search")],
        [(bot.label(settings, "back"), "menu:main")],
    ])


def prune():
    for cache in (DRAFTS, VIEWS):
        for key in list(cache):
            if time.monotonic() - cache[key]["touched"] > UI_TTL:
                del cache[key]
        while len(cache) >= 64:
            del cache[min(cache, key=lambda key: cache[key]["touched"])]


def new_draft(chat, filters=None):
    prune()
    token = secrets.token_hex(6)
    DRAFTS[token] = {"chat": chat, "filters": dict(filters or {}), "touched": time.monotonic()}
    return token


def draft(chat, token):
    value = DRAFTS.get(token)
    if not value or value["chat"] != chat or time.monotonic() - value["touched"] > UI_TTL:
        raise ValueError("search editor expired; open Advanced Search again")
    value["touched"] = time.monotonic()
    return value


def summary(settings, query):
    items = []
    for field, name in (("ports", tr(settings, "Ports", "端口")), ("countries", tr(settings, "Countries", "国家")),
                        ("sources", tr(settings, "Source IP", "来源 IP"))):
        values = query.get(field, [])
        if values:
            values = [country_label(value, settings.language) if field == "countries" else str(value) for value in values]
            shown = " OR ".join(values)[:150]
            items.append(f"[{name}: {shown}]")
    if query.get("protocol"):
        items.append(f"[{query['protocol']}]")
    if query.get("window"):
        seconds = query["window"]
        duration = f"{seconds // 86400}d" if seconds % 86400 == 0 else f"{seconds // 3600}h" if seconds % 3600 == 0 else f"{seconds // 60}m" if seconds % 60 == 0 else f"{seconds}s"
        items.append(tr(settings, f"[Last blocked: last {duration}]", f"[最近拦截: 过去 {duration}]"))
    elif "since" in query or "until" in query:
        start = timestamp(query["since"]) if "since" in query else "-"
        end = timestamp(query["until"]) if "until" in query else "-"
        items.append(tr(settings, f"[Last blocked: {start} .. {end}]", f"[最近拦截: {start} 至 {end}]"))
    return (f" {query.get('operator', 'AND')} ".join(items)) or tr(settings, "All visible records", "全部可见记录")


def render_form(settings, chat, token):
    query = draft(chat, token)["filters"]
    mode = query.get("operator", "AND")
    return tr(settings, "Advanced Search\n", "高级搜索\n") + summary(settings, query), bot.keyboard([
        [(tr(settings, f"Ports ({len(query.get('ports', []))})", f"端口（{len(query.get('ports', []))}）"), f"log:select:{token}:ports:0"),
         (tr(settings, f"Countries ({len(query.get('countries', []))})", f"国家（{len(query.get('countries', []))}）"), f"log:select:{token}:countries:0")],
        [(tr(settings, "Last Blocked Time", "最近拦截时间"), f"log:time:{token}"),
         (tr(settings, "Source IP / CIDR", "来源 IP / 网段"), f"log:input:{token}:sources")],
        [(f"{'[x]' if query.get('protocol') == value else '[ ]'} {value}", f"log:proto:{token}:{value}") for value in ("TCP", "UDP")]
        + [(tr(settings, "Any protocol", "全部协议"), f"log:proto:{token}:all")],
        [(f"{'[x]' if mode == 'AND' else '[ ]'} AND", f"log:op:{token}:AND"),
         (f"{'[x]' if mode == 'OR' else '[ ]'} OR", f"log:op:{token}:OR")],
        [(tr(settings, "Search", "搜索"), f"log:run:{token}"), (tr(settings, "Reset Filters", "重置条件"), f"log:clear:{token}:all")],
        [(bot.label(settings, "back"), "menu:log")],
    ])


def render_selector(settings, chat, token, field, page):
    value = draft(chat, token)
    if field not in {"ports", "countries"}:
        raise ValueError("unknown search field")
    if "facets" not in value:
        ok, data, error = bot.relay_json(settings, ["blocked-filters"], {})
        if not ok:
            raise ValueError(error)
        value["facets"] = {"ports": data.get("ports", []), "countries": [row["key"] for row in data.get("countries", [])]}
    choices = value["facets"][field]
    selected = value["filters"].get(field, [])
    for item in selected:
        if item not in choices:
            choices.append(item)
    page = min(max(page, 0), max(0, (len(choices) - 1) // OPTIONS_PER_PAGE))
    buttons = []
    for index in range(page * OPTIONS_PER_PAGE, min(len(choices), (page + 1) * OPTIONS_PER_PAGE)):
        item = choices[index]
        title = country_label(item, settings.language) if field == "countries" else str(item)
        buttons.append([(f"{'[x]' if item in selected else '[ ]'} {title[:48]}", f"log:toggle:{token}:{field}:{index}:{page}")])
    navigation = []
    if page:
        navigation.append((tr(settings, "< Previous", "< 上一页"), f"log:select:{token}:{field}:{page - 1}"))
    if (page + 1) * OPTIONS_PER_PAGE < len(choices):
        navigation.append((tr(settings, "Next >", "下一页 >"), f"log:select:{token}:{field}:{page + 1}"))
    if navigation:
        buttons.append(navigation)
    buttons += [[(tr(settings, "Enter Values", "手动输入"), f"log:input:{token}:{field}"),
                 (tr(settings, "Clear", "清空"), f"log:clear:{token}:{field}")],
                [(tr(settings, "Done", "完成"), f"log:f:{token}")]]
    title = tr(settings, "Countries", "国家") if field == "countries" else tr(settings, "Ports", "端口")
    return title + "\n" + summary(settings, value["filters"]), bot.keyboard(buttons)


def render_time(settings, chat, token):
    query = draft(chat, token)["filters"]
    return tr(settings, "Last Blocked Time\n", "最近拦截时间\n") + summary(settings, query), bot.keyboard([
        [(tr(settings, "Last hour", "最近 1 小时"), f"log:window:{token}:3600"),
         (tr(settings, "Last 6 hours", "最近 6 小时"), f"log:window:{token}:21600")],
        [(tr(settings, "Last 24 hours", "最近 24 小时"), f"log:window:{token}:86400"),
         (tr(settings, "Last 7 days", "最近 7 天"), f"log:window:{token}:604800")],
        [(tr(settings, "Last 30 days", "最近 30 天"), f"log:window:{token}:2592000"),
         (tr(settings, "All time", "全部时间"), f"log:clear:{token}:time")],
        [(tr(settings, "Custom Duration", "自定义时长"), f"log:input:{token}:window")],
        [(tr(settings, "From (UTC)", "开始时间（UTC）"), f"log:input:{token}:since"),
         (tr(settings, "Until (UTC)", "结束时间（UTC）"), f"log:input:{token}:until")],
        [(bot.label(settings, "back"), f"log:f:{token}")],
    ])


def fetch_page(settings, token, page=1):
    ok, result, error = bot.relay_json(settings, ["blocked-search", "--token", token, "--page", str(page)], {})
    if not ok:
        raise ValueError(error)
    return result


def result_query(settings, chat, token):
    cached = VIEWS.get(token)
    if cached and cached["chat"] == chat:
        return dict(cached["filters"])
    result = fetch_page(settings, token)
    if result.get("expired"):
        raise ValueError("search snapshot expired; open Advanced Search again")
    return result["filters"]


def render_results(settings, chat, query=None, token=None, page=1):
    if token is None:
        ok, data, error = bot.relay_json(settings, ["blocked-search", "--query", json.dumps(query or {}, ensure_ascii=False)], {})
        if not ok:
            raise ValueError(error)
    else:
        data = fetch_page(settings, token, page)
    if data.get("expired"):
        return tr(settings, "This search expired. Refresh it or start a new search.", "本次查询已过期，请刷新或重新搜索。"), bot.keyboard([
            [(tr(settings, "Refresh", "刷新结果"), f"log:r:{token}"), (tr(settings, "Advanced Search", "高级搜索"), "log:search")],
            [(bot.label(settings, "back"), "menu:log")],
        ])
    token, page, pages = data["token"], data["page"], data["pages"]
    prune()
    VIEWS[token] = {"chat": chat, "filters": data["filters"], "touched": time.monotonic()}
    heading = tr(settings, f"Blocked History: {data['total']} records\nPage {page}/{pages}", f"拦截记录：{data['total']} 条\n第 {page}/{pages} 页")
    heading += "\n" + summary(settings, data["filters"])
    heading += tr(settings, f"\nSnapshot: {bot.short_time(data['created_at'])}\nCount: lifetime total",
                  f"\n查询快照：{bot.short_time(data['created_at'])}\n次数：历史累计")
    rows = []
    for row in data["rows"]:
        safe = {**row, "geo": bot.one_line(row.get("geo"))[:65], "isp": bot.one_line(row.get("isp"))[:65],
                "source_ip": bot.one_line(row.get("source_ip"))[:40], "proto": bot.one_line(row.get("proto"))[:8]}
        rows.append(bot.format_block(settings, safe))
    body = heading + "\n\n" + ("\n\n".join(rows) or tr(settings, "No matching records.", "没有匹配的记录。"))
    nav = []
    if page > 1:
        nav.append((tr(settings, "< Previous", "< 上一页"), f"log:p:{token}:{page - 1}"))
    nav.append((tr(settings, f"Page {page}/{pages}", f"页码 {page}/{pages}"), f"log:j:{token}:{page}"))
    if page < pages:
        nav.append((tr(settings, "Next >", "下一页 >"), f"log:p:{token}:{page + 1}"))
    return body, bot.keyboard([
        nav,
        [(tr(settings, "First", "首页"), f"log:p:{token}:1"), (tr(settings, "Last", "尾页"), f"log:p:{token}:{pages}")],
        [(tr(settings, "Refresh", "刷新结果"), f"log:r:{token}"), (tr(settings, "Edit Filters", "修改条件"), f"log:e:{token}")],
        [(bot.label(settings, "back"), "menu:log")],
    ])


def prompt(settings, field):
    prompts = {
        "ports": ("Send ports separated by commas, e.g. 1935,24678. Send - to clear.", "输入端口，逗号分隔，例如 1935,24678。发送 - 清空。"),
        "countries": ("Send country names or common codes, e.g. CN,US,United Kingdom. Send - to clear.", "输入国家名称或常用代码，逗号分隔，例如 中国,US,英国。发送 - 清空。"),
        "sources": ("Send IPs, CIDRs or ranges separated by commas. Send - to clear.", "输入来源 IP、网段或 IP 范围，逗号分隔。发送 - 清空。"),
        "window": ("Send a duration, e.g. 90m, 2h or 3d. Send - for all time.", "输入时长，例如 90m、2h 或 3d。发送 - 查看全部时间。"),
        "since": ("Start time: YYYY-MM-DD HH:MM (UTC), or ISO time with offset, e.g. 2026-10-01T17:00:00+08:00. Send - to clear.", "开始时间：YYYY-MM-DD HH:MM（UTC）；也可输入带时区的时间，例如 2026-10-01T17:00:00+08:00。发送 - 清空。"),
        "until": ("End time: YYYY-MM-DD HH:MM (UTC) or ISO time with offset. A date alone includes that entire UTC day. Send - to clear.", "结束时间：YYYY-MM-DD HH:MM（UTC）或带时区的时间。只输入日期时包含该 UTC 日期的全天。发送 - 清空。"),
    }
    if field not in prompts:
        raise ValueError("unknown search field")
    return tr(settings, *prompts[field])


def clear_field(query, field):
    if field == "all":
        query.clear()
    elif field == "time":
        for key in ("window", "since", "until"):
            query.pop(key, None)
    else:
        query.pop(field, None)


def handle_callback(settings, chat, data):
    bot.PENDING_ACTIONS.pop(chat, None)
    try:
        if data in {"log:browse", "status:blocked"}:
            return render_results(settings, chat)
        if data == "log:search":
            return render_form(settings, chat, new_draft(chat))
        parts = data.split(":")
        action, token = parts[1:3]
        if action == "p":
            return render_results(settings, chat, token=token, page=int(parts[3]))
        if action == "j":
            bot.PENDING_ACTIONS[chat] = {"action": "log_page", "token": token, "page": parts[3]}
            return tr(settings, "Send the page number.", "请输入页码。"), bot.back_keyboard(f"log:p:{token}:{parts[3]}", settings)
        if action in {"r", "e"}:
            query = result_query(settings, chat, token)
            return render_results(settings, chat, query=query) if action == "r" else render_form(settings, chat, new_draft(chat, query))
        value = draft(chat, token)
        query = value["filters"]
        if action == "f":
            return render_form(settings, chat, token)
        if action == "run":
            return render_results(settings, chat, query=query)
        if action == "select":
            return render_selector(settings, chat, token, parts[3], int(parts[4]))
        if action == "toggle":
            field, index, page = parts[3], int(parts[4]), int(parts[5])
            if field not in {"ports", "countries"} or index < 0:
                raise ValueError("invalid selection")
            item = value["facets"][field][index]
            selected = list(query.get(field, []))
            selected.remove(item) if item in selected else selected.append(item)
            updated = {**query, field: selected}
            normalize_query(updated)
            value["filters"] = updated
            return render_selector(settings, chat, token, field, page)
        if action == "op":
            normalize_query({**query, "operator": parts[3]})
            query["operator"] = parts[3]
        elif action == "proto":
            updated = dict(query)
            clear_field(updated, "protocol")
            if parts[3] != "all":
                updated["protocol"] = parts[3]
            normalize_query(updated)
            value["filters"] = updated
        elif action == "time":
            return render_time(settings, chat, token)
        elif action == "window":
            updated = dict(query)
            clear_field(updated, "time")
            updated["window"] = int(parts[3])
            normalize_query(updated)
            value["filters"] = updated
        elif action == "clear":
            clear_field(query, parts[3])
        elif action == "input":
            message = prompt(settings, parts[3])
            bot.PENDING_ACTIONS[chat] = {"action": "log_filter", "draft": token, "field": parts[3]}
            return message, bot.back_keyboard(f"log:f:{token}", settings)
        else:
            raise ValueError("unknown search action")
        return render_form(settings, chat, token)
    except (ValueError, IndexError, KeyError, TypeError) as exc:
        keys = log_keyboard(settings)
        if "token" in locals() and token in DRAFTS and DRAFTS[token]["chat"] == chat:
            keys["inline_keyboard"].insert(0, [{"text": tr(settings, "Edit Filters", "修改条件"), "callback_data": f"log:f:{token}"}])
        return tr(settings, f"Blocked history: {exc}", f"拦截记录：{exc}"), keys


def handle_input(settings, chat, message):
    pending = bot.PENDING_ACTIONS.pop(chat)
    try:
        if pending["action"] == "log_page":
            if not re.fullmatch(r"[0-9]{1,6}", message.strip()) or int(message) < 1:
                raise ValueError("page number must be a positive integer")
            return render_results(settings, chat, token=pending["token"], page=int(message))
        token, field = pending["draft"], pending["field"]
        value = draft(chat, token)
        query = dict(value["filters"])
        message = message.strip()
        if message == "-":
            clear_field(query, "time" if field == "window" or (field in {"since", "until"} and "window" in query) else field)
        elif field in {"ports", "countries", "sources"}:
            values = [part.strip() for part in message.replace("，", ",").split(",") if part.strip()]
            if not values:
                raise ValueError("send at least one value or - to clear")
            query[field] = [int(part) for part in values] if field == "ports" else [country_key(part) for part in values] if field == "countries" else values
        elif field == "window":
            match = re.fullmatch(r"([1-9][0-9]{0,6})([mhd])", message.lower())
            if not match:
                raise ValueError("use a duration such as 90m, 2h or 3d")
            clear_field(query, "time")
            query["window"] = int(match[1]) * {"m": 60, "h": 3600, "d": 86400}[match[2]]
        elif field in {"since", "until"}:
            if "window" in query:
                clear_field(query, "time")
            query[field] = parse_time(message, end=field == "until")
        else:
            raise ValueError("unknown search field")
        normalize_query(query)
        value["filters"] = query
        return render_form(settings, chat, token)
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        bot.PENDING_ACTIONS[chat] = pending
        back = f"log:p:{pending['token']}:{pending['page']}" if pending["action"] == "log_page" else f"log:f:{pending['draft']}"
        return tr(settings, f"Invalid search value: {exc}\nPlease try again.", f"搜索值无效：{exc}\n请重新输入。"), bot.back_keyboard(back, settings)
