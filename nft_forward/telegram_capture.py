"""Button-driven recording settings and metadata-only packet history."""
from __future__ import annotations

import json

from . import telegram_bot as bot
from .blocked_search import COUNTRIES, country_key, country_label


def tr(settings, en, zh):
    return bot.text(settings, en, zh)


def request(settings, args):
    ok, data, error = bot.relay_json(settings, ["capture", *args], {})
    if not ok:
        raise ValueError(error)
    return data


def update(settings, patch):
    return request(settings, ["set", "--json", json.dumps(patch, ensure_ascii=False)])


def settings_menu(settings):
    return tr(settings, "Settings", "设置"), bot.keyboard([
        [(tr(settings, "Packet Recording", "数据包记录"), "cap:home")],
        [(bot.label(settings, "back"), "menu:manage")]])


def home(settings, data=None):
    data = data or request(settings, ["status"])
    config, runtime = data["config"], data["runtime"]
    ports = ", ".join(map(str, config["ports"])) or "-"
    countries = ", ".join(country_label(c, settings.language) for c in config["countries"]) or tr(settings, "All countries", "全部国家")
    scope = tr(settings, "Blocked only", "仅拦截流量") if config["scope"] == "blocked" else tr(settings, "All incoming", "全部入站流量")
    enabled = tr(settings, "ON", "开") if config["enabled"] else tr(settings, "OFF", "关")
    body = tr(settings, f"Packet Recording: {enabled}\nScope: {scope}\nPorts: {ports[:400]}\nCountries: {countries[:400]}",
              f"数据包记录：{enabled}\n范围：{scope}\n端口：{ports[:400]}\n国家：{countries[:400]}")
    body += f"\n{config['max_disk_mb']} MiB / {config['retention_days']}d / {config['rate_pps']} packets/s"
    body += tr(settings, f"\nCollector: {runtime.get('state')}\nSaved: {runtime.get('saved', 0)} | Country skipped: {runtime.get('country_skipped', 0)} | Storage skipped: {runtime.get('storage_skipped', 0)}",
               f"\n采集器：{runtime.get('state')}\n已保存：{runtime.get('saved', 0)} | 国家筛除：{runtime.get('country_skipped', 0)} | 存储跳过：{runtime.get('storage_skipped', 0)}")
    if runtime.get("error"):
        body += "\n" + bot.one_line(runtime["error"])[:300]
    if "rate_limited" in runtime:
        body += tr(settings, f"\nCopy rate limit skips (since last nft apply): {runtime['rate_limited']}", f"\n复制限速跳过（上次 nft 应用以来）：{runtime['rate_limited']}")
    body += tr(settings, "\nPCAP payloads stay on the relay. Recording never permits blocked traffic. Rate-limited copies may be incomplete.",
               "\nPCAP 载荷仅存于中继。记录不会放行拦截流量，限速可能导致记录不完整。")
    return body, bot.keyboard([
        [(tr(settings, "Turn OFF", "关闭记录") if config["enabled"] else tr(settings, "Turn ON", "开启记录"), f"cap:enable:{0 if config['enabled'] else 1}")],
        [(tr(settings, "Select Ports", "选择端口"), "cap:ports:0"), (tr(settings, "Countries", "选择国家"), "cap:countries:0")],
        [(tr(settings, "Scope", "记录范围"), "cap:scope"), (tr(settings, "Limits / Retention", "限额 / 保留时间"), "cap:limits")],
        [(tr(settings, "Recorded Packets", "数据包记录列表"), "cap:files:1"), (tr(settings, "Refresh", "刷新"), "cap:home")],
        [(bot.label(settings, "back"), "manage:settings")]])


def selector(settings, kind, page, data=None):
    data = data or request(settings, ["status"])
    config = data["config"]
    choices = [row["port"] for row in data["forwarding_ports"]] if kind == "ports" else list(dict.fromkeys(["CN", "GB", "AU", *COUNTRIES, *config["countries"]]))
    page = min(max(0, page), max(0, (len(choices) - 1) // 8))
    rows = []
    for index, value in enumerate(choices[page * 8:(page + 1) * 8], page * 8):
        label = str(value) if kind == "ports" else country_label(value, settings.language)
        # Use the canonical value for ports and an index for country names (which
        # can exceed Telegram's callback byte limit).
        action = str(value) if kind == "ports" else str(index)
        rows.append([(f"{'[x]' if value in config[kind] else '[ ]'} {label[:40]}", f"cap:toggle:{kind}:{action}:{page}")])
    nav = []
    if page:
        nav.append((tr(settings, "< Previous", "< 上一页"), f"cap:{kind}:{page - 1}"))
    if (page + 1) * 8 < len(choices):
        nav.append((tr(settings, "Next >", "下一页 >"), f"cap:{kind}:{page + 1}"))
    if nav:
        rows.append(nav)
    if kind == "countries":
        rows.append([(tr(settings, "Other Countries", "输入其他国家"), "cap:input:countries"),
                     (tr(settings, "All countries", "全部国家"), "cap:clear:countries")])
    else:
        rows.append([(tr(settings, "Clear Ports", "清空端口"), "cap:clear:ports")])
    rows.append([(bot.label(settings, "back"), "cap:home")])
    body = tr(settings, "Recording Ports\nNo selected ports = no recording.", "记录端口\n未选择端口时不记录。") if kind == "ports" else tr(settings, "Countries (OR)\nEmpty = all. Unknown locations are excluded unless selected.", "国家（或）\n留空代表全部；未选择未知时，不记录未知归属地。")
    return body, bot.keyboard(rows)


def file_list(settings, page):
    data = request(settings, ["files", "--page", str(page)])
    rows, lines = [], []
    for item in data["rows"]:
        title = f"{bot.short_time(item['last'])} | {item['count']} | {item['scope']}"
        lines.append(title)
        rows.append([(title, f"cap:r:{item['id']}:1")])
    nav = []
    if data["page"] > 1:
        nav.append((tr(settings, "< Previous", "< 上一页"), f"cap:files:{data['page'] - 1}"))
    if data["page"] < data["pages"]:
        nav.append((tr(settings, "Next >", "下一页 >"), f"cap:files:{data['page'] + 1}"))
    if nav:
        rows.append(nav)
    rows += [[(tr(settings, "Refresh", "刷新"), f"cap:files:{data['page']}")], [(bot.label(settings, "back"), "menu:log")]]
    return tr(settings, f"Recorded Packets\nFiles: page {data['page']}/{data['pages']}", f"数据包记录\n文件：第 {data['page']}/{data['pages']} 页") + ("" if lines else tr(settings, "\nNo recordings.", "\n暂无记录。")), bot.keyboard(rows)


def record_list(settings, file_id, page, anchor=None):
    args = ["records", file_id, "--page", str(page)]
    if anchor is not None:
        args += ["--anchor", str(anchor)]
    data = request(settings, args)
    if data.get("expired"):
        return tr(settings, "Recording expired or was removed by retention.", "记录已过期或被保留策略清理。"), bot.back_keyboard("cap:files:1", settings)
    lines = [tr(settings, f"Packet Records: {data['total']}\nPage {data['page']}/{data['pages']}", f"数据包记录：{data['total']}\n第 {data['page']}/{data['pages']} 页"), data["path"]]
    for row in data["rows"]:
        lines.append(f"#{row['id']} {bot.short_time(row['timestamp'])}\n{row['source_ip']}:{row['source_port']} -> {row['destination_ip']}:{row['destination_port']}\n{row['protocol']} {row['flags']} | {row['scope']} | {row['captured_bytes']}/{row['packet_bytes']} B | TTL {row['ttl']}\n{bot.one_line(row['geo'])[:70]} | {bot.one_line(row['isp'])[:60]}\noffset={row['offset']} truncated={row['truncated']}")
    nav = []
    if data["page"] > 1:
        nav.append((tr(settings, "< Previous", "< 上一页"), f"cap:r:{file_id}:{data['page'] - 1}:{data['anchor']}"))
    if data["page"] < data["pages"]:
        nav.append((tr(settings, "Next >", "下一页 >"), f"cap:r:{file_id}:{data['page'] + 1}:{data['anchor']}"))
    rows = [nav] if nav else []
    rows += [[(tr(settings, "Refresh", "刷新"), f"cap:r:{file_id}:1")], [(bot.label(settings, "back"), "cap:files:1")]]
    return "\n\n".join(lines), bot.keyboard(rows)


def handle_callback(settings, chat, data):
    bot.PENDING_ACTIONS.pop(chat, None)
    try:
        parts = data.split(":")
        action = parts[1]
        if data == "manage:settings":
            return settings_menu(settings)
        if action == "home":
            return home(settings)
        if action == "files":
            return file_list(settings, int(parts[2]))
        if action == "r":
            return record_list(settings, parts[2], int(parts[3]), int(parts[4]) if len(parts) > 4 else None)
        if action == "enable":
            if parts[2] not in {"0", "1"}:
                raise ValueError("invalid switch")
            update(settings, {"enabled": parts[2] == "1"})
            return home(settings)
        if action in {"ports", "countries"}:
            return selector(settings, action, int(parts[2]))
        if action == "toggle":
            kind, index, page = parts[2], int(parts[3]), int(parts[4])
            if kind not in {"ports", "countries"} or index < 0:
                raise ValueError("invalid selection")
            current = request(settings, ["status"])
            config = current["config"]
            choices = list(dict.fromkeys(["CN", "GB", "AU", *COUNTRIES, *config["countries"]]))
            value = index if kind == "ports" else choices[index]
            values = list(config[kind])
            values.remove(value) if value in values else values.append(value)
            update(settings, {kind: values})
            return selector(settings, kind, page)
        if action == "clear" and parts[2] in {"ports", "countries"}:
            update(settings, {parts[2]: []})
            return selector(settings, parts[2], 0)
        if action == "scope":
            if len(parts) == 3:
                update(settings, {"scope": parts[2]})
                return home(settings)
            return tr(settings, "Recording Scope", "记录范围"), bot.keyboard([
                [(tr(settings, "Blocked only (default)", "仅拦截流量（默认）"), "cap:scope:blocked")],
                [(tr(settings, "All incoming on selected ports", "所选端口的全部入站流量"), "cap:scope:all")],
                [(bot.label(settings, "back"), "cap:home")]])
        if action == "limits":
            return tr(settings, "Recording Limits", "记录限额"), bot.keyboard([
                [("128 MiB / 3d / 100 pps", "cap:preset:small")], [("256 MiB / 7d / 500 pps", "cap:preset:default")],
                [(tr(settings, "Custom limits", "自定义限额"), "cap:input:limits")], [(bot.label(settings, "back"), "cap:home")]])
        if action == "preset":
            mb, days, pps = {"small": (128, 3, 100), "default": (256, 7, 500)}[parts[2]]
            update(settings, {"max_disk_mb": mb, "retention_days": days, "rate_pps": pps})
            return home(settings)
        if action == "input" and parts[2] in {"countries", "limits"}:
            bot.PENDING_ACTIONS[chat] = {"action": "capture_input", "field": parts[2]}
            message = tr(settings, "Country names/codes, comma separated (replaces selection); - for all.", "国家名称或代码，用逗号分隔（替换当前选择）；- 代表全部。") if parts[2] == "countries" else tr(settings, "Send: disk_MiB days packets_per_second\nRanges: 32..16384 1..90 10..10000", "输入：磁盘_MiB 天数 每秒包数\n范围：32..16384 1..90 10..10000")
            return message, bot.back_keyboard("cap:home", settings)
        raise ValueError("unknown recording action")
    except (ValueError, IndexError, KeyError, TypeError) as exc:
        return tr(settings, f"Packet recording: {exc}", f"数据包记录：{exc}"), bot.back_keyboard("cap:home", settings)


def handle_input(settings, chat, message):
    pending = bot.PENDING_ACTIONS.pop(chat)
    try:
        if pending["field"] == "countries":
            countries = [] if message.strip() == "-" else [country_key(x.strip()) for x in message.replace("，", ",").split(",") if x.strip()]
            update(settings, {"countries": countries})
        else:
            mb, days, pps = map(int, message.split())
            update(settings, {"max_disk_mb": mb, "retention_days": days, "rate_pps": pps})
        return home(settings)
    except (ValueError, TypeError) as exc:
        bot.PENDING_ACTIONS[chat] = pending
        return tr(settings, f"Invalid setting: {exc}", f"设置无效：{exc}"), bot.back_keyboard("cap:home", settings)
