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

## IP 缓存

部署到无法访问 GitHub 的中继服务器前，可先在有网络的机器上更新缓存：

```bash
python3 scripts/update_ip_cache.py
```

缓存目录：

```text
cache/iplist/
```

如果本地缓存没有命中，中继端会尝试通过 SSH 让出口节点进行在线查询。查询失败时
会记录为 `unknown`，不会中断白名单或拦截日志流程。

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
