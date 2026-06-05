# NiftGate

![NiftGate icon](assets/niftgate-icon.svg)

**NiftGate** is a portable nftables relay/exit whitelist toolkit for people who
need controlled port forwarding without leaving relay ports open to the world.

It keeps forwarding rules on the relay server, serves Secret URLs from the exit
node, supports DDNS and SSH-login whitelist updates, and can be managed from a
terminal menu or an optional Telegram bot.

> Internally, the legacy command name `nft.sh` is preserved for compatibility.

## Features

- nftables TCP/UDP forwarding with source-IP restrictions.
- Relay-owned forwarding rules, rulesets, DDNS entries, and Secret URLs.
- Replaceable exit node: sync URL/ruleset state from the relay.
- Optional Telegram bot with clickable menus.
- Secret URL management from Telegram or terminal.
- Attack mode to freeze automatic SSH/DDNS/web additions.
- Import/export for migration and backup.
- Password or SSH-key operation between exit and relay.
- Local metowolf/iplist cache for geo/ISP metadata.
- One-key installer with uninstall support.

Reserved relay ports are refused: `80`, `443`, `8080`, and `8443`.

## Architecture

```text
User/device
  -> Relay server: nftables DNAT/SNAT, forwarding rules, allowlist, rulesets
  -> Exit node: Telegram bot, Secret URL endpoint, Nginx/TLS, retry queue
```

The relay is the source of truth. If you move to a new exit node, install
NiftGate on the new exit node, point it at the relay, and sync from relay.

## Requirements

- Debian or Ubuntu-based relay and exit servers.
- Root access.
- `python3`, `nftables`, `ssh`; installer can install missing packages.
- `nginx` on the exit node for public Secret URLs.
- Optional: `sshpass` for ongoing password-based SSH operation.
- Optional: Telegram bot token and ChatID.

## Install

Run the installer on the **exit node**. It installs exit services first, then
uploads and installs the relay side over SSH using the relay intranet address.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/alexchen7/niftgate/main/install.sh)
```

If you downloaded or cloned the repository:

```bash
sudo bash install.sh
```

The installer asks for:

- Secret URL domain or public hostname.
- Secret URL public TLS port and backend port.
- Relay intranet IP/host, SSH port, username, and auth method.
- SSH password or private key path.
- Optional DDNS whitelist hostname.
- Optional Telegram bot token and ChatID.
- Nginx certificate mode: reuse certificate, self-signed, or skip.

Telegram is optional. If token/ChatID are left blank, the core services still
install and Telegram stays disabled.

## Terminal Menu

After installation:

```bash
nft.sh menu
```

The menu guides you through:

- Status
- Forwarding rules
- Secret URLs
- Attack mode
- Export

Direct CLI commands are also available for automation.

## Forwarding Rules

Add a restricted forwarding rule:

```bash
nft.sh add-rule 58495 203.0.113.20 58495 --note "main exit"
```

Add a manual whitelist entry:

```bash
nft.sh allow 198.51.100.23 --ruleset public --channel manual --prefix 32
```

Sync DDNS entries:

```bash
nft.sh sync-ddns
```

Switch modes:

```bash
nft.sh mode regular
nft.sh mode attack
```

Attack mode freezes automatic `ssh_login`, `ddns`, and `web` additions. Manual
CLI and Telegram edits still work.

## Rulesets

The built-in `public` ruleset applies to forwarding rules by default.

Create or update a custom ruleset:

```bash
nft.sh ruleset set ddns \
  --channels manual,ddns,web \
  --manual-prefix 32 \
  --ddns-prefix 24 \
  --web-prefix 24 \
  --note "DDNS managed users"
```

Attach rulesets to a forwarding rule:

```bash
nft.sh add-rule 58495 203.0.113.20 58495 --ruleset ddns
```

## Secret URLs

Secret URLs let a user visit a long, private URL and add their current source IP
to a ruleset through the `web` channel.

List active URLs:

```bash
nft.sh secret-url list
```

Create a URL for a ruleset:

```bash
nft.sh secret-url create --ruleset public --label phone
```

Delete one or more URLs:

```bash
nft.sh secret-url delete 1 2
```

The exit node syncs Secret URLs from the relay. If the relay is temporarily
unreachable, the exit node keeps serving the last synced active URL cache and
queues whitelist updates for retry.

## Telegram Bot

Telegram is optional and runs on the exit node. The bot provides clickable
buttons:

- `Status`: counts plus relay SSH latency/timeout.
- `Manage`: forwarding rules, rulesets, and Secret URLs.
- `Log`: recent whitelist and blocked-source entries.
- `Attack Mode`: regular/attack toggle.

Enable Telegram after adding a token and ChatID:

```bash
sudo systemctl enable --now nft-forward-exit-telegram.service
```

Disable Telegram:

```bash
sudo systemctl disable --now nft-forward-exit-telegram.service
```

## Import And Export

Export relay-owned state:

```bash
nft.sh export -o niftgate-export.json
```

Default export excludes private keys, passwords, Telegram token, and Secret URL
paths.

For a full migration backup that includes Secret URL paths:

```bash
nft.sh export --include-secrets -o niftgate-full-export.json
chmod 600 niftgate-full-export.json
```

Import into a relay:

```bash
nft.sh import niftgate-export.json --merge
```

Replace current managed relay state with an export:

```bash
nft.sh import niftgate-full-export.json --replace
```

After import, run:

```bash
nft.sh apply
```

## Exit Node Migration

1. Install NiftGate on the new exit node.
2. Enter the relay intranet IP/host and SSH credentials during setup.
3. Pair the relay with the new exit node if needed:

   ```bash
   nft.sh pair-exit --host <exit-host-or-ip> --user root --auth-method password
   ```

4. On the exit node, verify or change the relay connection without re-entering
   the full setup:

   ```bash
   nft.sh pair-relay
   nft.sh pair-relay --host <relay-intranet-ip> --user root --port 22 --auth-method password --ask-password --test
   ```

   To switch to key auth later:

   ```bash
   nft.sh pair-relay --auth-method key --key /etc/nft-forward-exit/ssh/relay_ed25519 --clear-password --test
   ```

   `pair-relay` updates only the relay SSH block in the exit-node config and
   try-restarts active exit services. Add `--no-restart` if you want to restart
   services manually.

5. On the exit node, sync relay-owned state:

   ```bash
   nft.sh sync-from-relay
   ```

6. Restart exit services if you used `--no-restart`:

   ```bash
   sudo systemctl restart nft-forward-exit-phone.service nft-forward-exit-queue.service
   ```

Forwarding rules remain on the relay and do not need to be recreated.

## IP Cache

Populate the bundled metowolf/iplist cache before deploying to a relay without
GitHub access:

```bash
python3 scripts/update_ip_cache.py
```

The cache is stored under:

```text
cache/iplist/
```

If local cache lookup misses, the relay can use the exit node for online lookup
when relay-to-exit SSH is reachable. Lookup failures resolve to `unknown`
without interrupting whitelist or block handling.

## Uninstall

On the server:

```bash
sudo bash install.sh --uninstall
```

The uninstall flow stops and disables NiftGate services. On relay systems it
removes only the managed `nft_forward` table/config and preserves legacy
`port_forward` rules by default.

You will be asked whether to remove config, state, and logs.

## Useful Paths

Relay:

```text
/etc/nft-forward/config.json
/var/lib/nft-forward/state.db
/var/log/nft-forward/
/etc/nftables.d/nft-forward-managed.conf
```

Exit:

```text
/etc/nft-forward-exit/config.json
/var/lib/nft-forward-exit/state.db
/etc/nft-forward-exit/ssh/
/etc/nginx/sites-available/nft-forward-secret-url.conf
```

## Security Notes

- Do not publish real passwords, private keys, Telegram tokens, ChatIDs, or
  Secret URL exports.
- Password SSH is supported for ongoing operation. Password files are stored
  root-only and read through `sshpass`.
- Key auth can use restricted forced commands.
- Secret URLs are bearer secrets. Treat them like passwords.
- Keep relay forwarding rules off blocked ISP ports: `80`, `443`, `8080`,
  `8443`.

## Development Checks

```bash
python3 -m unittest discover -s tests -v
python3 tests/smoke_cli.py
bash -n install.sh scripts/*.sh
```

## License

MIT
