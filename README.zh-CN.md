<p align="center">
  <img src="assets/niftgate-icon.svg" width="96" alt="NiftGate 图标">
</p>

# NiftGate

**NiftGate** 是一个便携式 nftables 中继/出口白名单工具包，适合需要端口转发、
但不希望中继端口向公网完全开放的使用场景。

它把转发规则保存在中继服务器上，由出口节点提供 Secret URL、Telegram 机器人、
Nginx/TLS 和失败重试队列。旧命令名 `nft.sh` 会继续保留，便于从旧版本升级。

## 功能

- nftables TCP/UDP 端口转发，并可限制来源 IP。
- 中继端保存转发规则、规则集、DDNS 记录和 Secret URL。
- 出口节点可替换：新出口节点可以从中继端同步状态。
- 可选 Telegram 机器人，支持点击按钮操作。
- Secret URL 可通过 Telegram 或终端管理。
- 攻击模式可冻结 SSH/DDNS/Secret URL 自动添加，手动操作仍然可用。
- 支持导入/导出，便于迁移和备份。
- 出口节点与中继节点之间支持密码或 SSH 密钥认证。
- 支持本地 metowolf/iplist 缓存，用于 IP 地理位置和 ISP 信息。
- 一键安装、升级和卸载。
- 可选的按端口数据包记录、国家筛选，以及 Telegram 元数据分页查看。

中继服务器会拒绝这些转发/监听端口：`80`、`443`、`8080`、`8443`。

## 架构

```text
用户/设备
  -> 中继服务器：nftables DNAT/SNAT、转发规则、白名单、规则集
  -> 出口节点：Telegram 机器人、Secret URL、Nginx/TLS、重试队列
```

中继服务器是持久化的唯一事实来源。如果要更换出口节点，只需要在新出口节点安装
NiftGate，填写中继连接信息，然后从中继同步即可。

## 环境要求

- 中继服务器和出口节点均为 Debian/Ubuntu 系统。
- root 权限。
- `python3`、`nftables`、`ssh`；安装脚本会尝试安装缺失包。
- 出口节点需要 `nginx` 来暴露 Secret URL。
- 可选：使用密码 SSH 时需要 `sshpass`。
- 可选：Telegram Bot Token 和 ChatID。

## 安装

推荐在**出口节点**运行安装脚本。它会先安装出口节点服务，然后通过 SSH 使用
中继服务器的内网地址安装中继端。

```bash
bash <(curl -Ls https://raw.githubusercontent.com/alexchen7/niftgate/main/install.sh)
```

如果你已经下载或克隆了仓库：

```bash
sudo bash install.sh
```

安装时会先询问界面语言，可选择英文或中文。之后会继续询问：

- Secret URL 使用的域名或公网主机名。
- Secret URL 的公网 TLS 端口和本地后端端口。
- 中继服务器内网 IP/主机名、SSH 端口、用户名和认证方式。
- SSH 密码或私钥路径。
- 可选 DDNS 白名单域名。
- 可选 Telegram Bot Token 和 ChatID。
- Nginx 证书方式：复用已有证书、自签名证书或跳过。

Telegram 是可选项。如果 Bot Token 或 ChatID 留空，核心服务仍会安装，
Telegram 服务会保持禁用。

## 升级

已配置过的出口节点可以直接升级，不需要重新输入全部配置：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/alexchen7/niftgate/main/install.sh) --upgrade
```

升级会保留出口节点配置，刷新本地服务文件并重启相关服务，然后使用已保存的中继
SSH 配对信息刷新中继端。

## 终端菜单

安装后可以运行：

```bash
nft.sh menu
```

菜单会根据安装时选择的语言显示，并提供：

- 状态
- 转发规则
- Secret URL
- 攻击模式
- 导出

也可以直接使用 CLI 命令进行自动化操作。

## 转发规则

添加受限转发规则：

```bash
nft.sh add-rule 58495 203.0.113.20 58495 --note "main exit"
```

添加手动白名单：

```bash
nft.sh allow 198.51.100.23 --ruleset public --channel manual --prefix 32
```

同步 DDNS：

```bash
nft.sh sync-ddns
```

DDNS 记录可通过 Telegram 的 `Manage -> DDNS` 管理，也可使用 CLI：

```bash
nft.sh ddns list
nft.sh ddns add mobile.example.com --ruleset public
nft.sh ddns delete 1 --keep-allowlist
```

删除 DDNS 时默认会移除该记录创建的白名单条目。如果希望只删除 DDNS 记录，
保留白名单，请加 `--keep-allowlist`。

## 规则集

公共规则集 `public` 默认应用到所有转发规则。也可以创建自定义规则集：

```bash
nft.sh ruleset set ddns --channels ddns,manual --ddns-prefix 24 --manual-prefix 32
```

把转发规则绑定到自定义规则集：

```bash
nft.sh add-rule 58495 203.0.113.20 58495 --ruleset ddns
```

## 编辑目标地址

Telegram：**管理 > 编辑转发规则 > 选择规则**。点击 **本机端口**、
**目标 IP / 域名 / URL** 或 **目标端口** 后发送新值。修改本机端口会保留备注和
访问策略；已占用的转发端口、保留端口会被拒绝。DNS 或 nftables 验证失败时保留原规则。

```bash
nft.sh edit-rule 58495 --new-lport 58496
nft.sh edit-rule 58496 --dest-ip exit.example.com --dest-port 58495
nft.sh add-rule 58500 https://exit.example.com/path 58500
```

URL 仅提取域名。URL 的路径、协议和内嵌端口不会改变单独设置的目标端口；
本功能是 TCP/UDP 转发，不是 HTTP 反向代理。兼容已有 IPv4 规则和旧数据库。

中继端的 `nft-forward-destinations.timer` 每 10 秒检查目标域名，攻击模式下也继续工作。
只有实际使用的 IPv4 地址变化时才原子更新 nftables。DNS 暂时失败时保留上一次成功
解析的地址，下次继续重试。存在多个 A 记录时，只要当前地址仍在结果中就继续使用，
避免因返回顺序变化反复更新。新域名必须成功解析后才能保存。导入导出包含域名和
缓存地址，导入时不需要 DNS 可用。

```bash
nft.sh sync-destinations
systemctl status nft-forward-destinations.timer
```

## Secret URL

Secret URL 由中继端保存，出口节点会同步缓存。即使中继暂时不可达，已缓存且启用
的 URL 仍可访问，失败的白名单推送会进入本地队列并重试。

CLI 示例：

```bash
nft.sh secret-url list
nft.sh secret-url create --ruleset public --label phone
nft.sh secret-url delete 3
```

Telegram 菜单路径：

```text
Manage -> Secret URL
```

可以查看启用 URL、生成多个 Secret URL，或删除一个/多个 URL。

## Telegram

Telegram 机器人运行在出口节点，不要求中继服务器能访问 Telegram。

主菜单包含：

- Status：显示白名单、转发规则、规则集、拦截 IP 数量，并显示到中继的 SSH 延迟。
- Manage：管理转发规则、Secret URL、DDNS 和规则集绑定。
- Log：查看最近白名单和拦截记录。
- Attack Mode：一键开启或关闭攻击模式。

如果经常收到 `unauthorized`，请确认 `config.json` 里的 Telegram ChatID 与当前
私聊或群聊 ID 完全一致。

## 攻击模式

```bash
nft.sh mode attack
nft.sh mode regular
```

`attack` 会冻结 SSH 登录、DDNS、Secret URL 等自动来源添加；已有白名单继续生效，
手动 CLI/TG 操作仍可使用。

## 导出和导入

默认导出不会包含敏感 Secret URL 路径：

```bash
nft.sh export > niftgate-export.json
```

如果需要一起导出 Secret URL 路径：

```bash
nft.sh export --include-secrets > niftgate-export-with-secrets.json
```

导入：

```bash
nft.sh import niftgate-export.json --merge
```

替换式导入：

```bash
nft.sh import niftgate-export.json --replace
```

请不要公开包含密码、私钥、Telegram Token、ChatID 或 Secret URL 路径的导出文件。

## 更换出口节点

在新出口节点运行安装脚本，填写原中继服务器信息即可。安装完成后同步中继状态：

```bash
nft.sh sync-from-relay
```

如果只需要更新出口节点保存的中继连接信息：

```bash
nft.sh pair-exit
```

转发规则保存在中继服务器上，不需要重建。

## 拦截记录分页与高级搜索

Telegram：**日志 > 拦截记录（分页）**。每页 5 条，支持上一页、下一页、首页、
尾页，以及点击页码后输入指定页数。**状态 > 拦截 IP** 也进入分页视图，数量不再
限制显示为 1000 条。

**日志 > 高级搜索** 支持多端口、来源国家、来源 IP/网段/范围、TCP/UDP，以及
最近拦截时间。可用按钮多选，也可输入逗号分隔的值。**AND** 表示所有已设置的
条件都要满足，**OR** 表示满足其中任一条件即可；同一字段内的多个值使用 OR。
例如端口 `1935,24678`、国家 `CN,US`、最近 24 小时并选择 **AND**，表示：
`(端口 1935 或 24678) 且 (中国或美国) 且 最近 24 小时`。

时间预设包括最近 1/6/24 小时、7/30 天；自定义时长支持 `90m`、`2h`、`3d`。
自定义日期时间默认使用 UTC，也可明确输入时区偏移，例如
`2026-10-01T17:00:00+08:00`。结束时间只输入日期时包含该 UTC 日期的全天。
国家按记录中的归属地匹配，常见国家支持中英文名称和代码；国家选择器列出历史
记录中实际出现的国家。

每条记录汇总一个来源 IP + 协议 + 本机端口。时间条件筛选的是 **最近拦截时间**，
次数是该记录的 **历史累计值**，不是所选时间范围内的包数，也不是逐个包的历史。
已隐藏或删除的历史记录不会进入新查询。

分页使用固定查询快照，新的拦截不会使正在浏览的页发生跳动。点击 **刷新结果**
重新查询，相对时间范围也会随之更新。快照 30 分钟过期，缓存最多保留 8 份；
每次搜索上限为 32 MiB / 100,000 条，超过时会要求缩小条件，不会静默截断。
已有快照保留查询时的数据。搜索不修改转发规则、白名单、累计次数或隐藏标记。

中继端 CLI 示例：

```bash
nft.sh blocked-search --query '{"ports":[1935,24678],"countries":["CN"],"window":86400,"operator":"AND"}'
nft.sh blocked-search --token 上次返回的token --page 2
nft.sh blocked-filters
```

原有 `nft.sh blocked --limit 20` 仍然返回 JSON 数组，兼容旧接口。

## IP 缓存

Telegram：**管理 > IP 归属地库 > 更新数据库**。出口节点下载 GitHub 上的
[ip2region 社区数据库](https://github.com/lionsoul2014/ip2region)，构建 SQLite 索引，
再通过已保存的 SSH 配对同步到中继。中继不需要访问 GitHub。更新在后台运行，
点击 **立即刷新** 可查看进度、上游版本/日期及中继上次同步版本。
下载或 SSH 失败会显示错误，可再次点击更新按钮重试。

免费社区数据不定期更新。IP 城市定位是估计值，尤其移动网络和 VPN 的出口位置
不一定等于用户所在地；数据更新日期不代表实时定位精度。优先使用 ip2region 的
国家、省、市和运营商信息，原 metowolf/iplist 缓存及出口在线查询继续作为补充。

不使用 Telegram 时，在出口节点运行：

```bash
nft.sh geo-update
nft.sh geo-status
```

如需先构建项目内缓存，再打包到离线机器：

```bash
python3 scripts/update_ip_cache.py
```

缓存目录：

```text
cache/iplist/geoip.db
cache/iplist/geoip.previous.db
```

通过地址段、完整性及校验和验证后才原子替换数据库，并保留上一份可用数据。
源版本、内容哈希及上游许可证保存在数据库内。更新时同步刷新已有白名单和拦截
记录的归属地/运营商标签，不改变时间、过期设置、次数或访问策略；历史 JSONL
日志保留原样。更新数据库不需要重载防火墙或重启服务。

更新服务为 `nft-forward-geo-update.service`，按需启动，不会持续循环下载。
只使用 Python 标准库和 SQLite，不需要额外 Python 依赖或注册账号。
缓存文件不会提交到 Git，升级时保留。

## 数据包记录

记录功能**默认关闭，且不选择任何端口**。Telegram 中进入
**管理 > 设置 > 数据包记录**，选择转发端口后开启。
默认范围为**仅拦截流量**：在 NiftGate 实际丢弃路径复制数据包。
也可切换为**全部入站流量**，包含所选中继端口上被允许的 TCP/UDP 流量和已建立连接。
记录不会开放端口、放宽白名单或中断连接。修改规则端口时记录选项随规则迁移，
删除规则会移除该规则的记录选项。

国家可多选，按“或”匹配，例如中国、英国、澳大利亚；留空表示全部国家。
归属地筛选只查询中继本地 IP 数据库，不逐包进行在线查询。启用国家筛选后，
除非选择“未知”，否则未知归属地不会被记录。归属地信息是近似值，可能存在误差或过期。

**日志 > 数据包记录**显示分段文件列表。选择文件后可分页查看 UTC 时间、来源/目标
地址和端口、协议/标志、大小、归属地/运营商、PCAP 偏移及截断状态。
**不会向 Telegram 发送载荷**。原始 IPv4 PCAP 和元数据索引仅保存在中继
`/var/lib/nft-forward/captures/`；自定义数据库路径时位于其旁的 `captures/`。
目录权限为 `0700`，文件权限为 `0600`。

终端菜单 `nft.sh menu` 的选项 7 和 CLI 提供相同设置。
在出口端运行以下命令，会通过配对 SSH 转发至中继：

```bash
nft.sh capture status
nft.sh capture set --json '{"ports":[1935],"scope":"blocked","countries":["CN","GB","AU"]}'
nft.sh capture set --json '{"enabled":true}'
nft.sh capture files
nft.sh capture records <file-id> --page 1
nft.sh capture set --json '{"enabled":false}'
```

中继安装脚本会安装 `tcpdump` 和 `nft-forward-capture.service`。
未开启或未选择端口时采集器保持空闲。默认限额为 **PCAP/索引合计 256 MiB、
保留 7 天、每秒最多复制 500 包**。旧分段自动清理，磁盘空间不足时跳过记录，
不会影响转发。Telegram 和终端可调整限额。服务的 CPU 配额为 25%，内存上限为
256 MiB。NiftGate 使用 NFLOG 组 `61440`，请勿让其他采集器占用此组。

记录尽力而为，复制限速、内核队列溢出、资源限制或采集器故障均可能导致缺失。
不会为了获取载荷而放行拦截连接，因此被拦截的 TCP SYN 往往没有应用载荷。
只索引可解析头部的 IPv4 TCP/UDP 包。PCAP 可能含敏感信息，请勿公开。
升级保留设置和记录文件；导出/导入不包含抓包文件，也不会让新导入的规则自动开启记录。
卸载会停止记录；选择删除状态数据时，也会删除已保存的抓包文件。

### 排除白名单来源

在**日志 > 高级搜索**开启**排除白名单**，即可排除当前任一公共或自定义规则集中
有效白名单覆盖的 IP，包括网段和 IP 范围；已过期条目不参与排除。
即使其他条件使用 OR，白名单排除仍然生效。已生成的分页保持查询时快照，点击刷新
会重新按当前白名单筛选。此操作不会改变防火墙或删除拦截记录。

## 卸载

在服务器上运行：

```bash
sudo bash install.sh --uninstall
```

卸载流程会停止并禁用 NiftGate 服务。中继端默认只删除 NiftGate 管理的
`nft_forward` 表和配置，不会删除旧版 `port_forward` 转发规则。

脚本会询问是否同时删除配置、状态和日志。

## 常用路径

中继服务器：

```text
/etc/nft-forward/config.json
/var/lib/nft-forward/state.db
/var/log/nft-forward/
/etc/nftables.d/nft-forward-managed.conf
```

出口节点：

```text
/etc/nft-forward-exit/config.json
/var/lib/nft-forward-exit/state.db
/etc/nft-forward-exit/ssh/
/etc/nginx/sites-available/nft-forward-secret-url.conf
```

## 安全提示

- 不要公开真实密码、私钥、Telegram Token、ChatID 或包含 Secret URL 的导出文件。
- 密码 SSH 可用于持续运行，密码文件会以 root-only 权限保存，并通过 `sshpass` 使用。
- SSH 密钥认证可配合 restricted forced command。
- Secret URL 是 Bearer Secret，请像密码一样保存。
- 中继服务器不要使用被 ISP 屏蔽或保留的端口：`80`、`443`、`8080`、`8443`。

## 开发检查

```bash
python3 -m unittest discover -s tests -v
python3 tests/smoke_cli.py
bash -n install.sh scripts/*.sh
```

## 许可证

MIT
