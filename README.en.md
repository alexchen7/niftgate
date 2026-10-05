# NiftGate

<p align="center">
  <img src="assets/niftgate-icon.svg" width="96" alt="NiftGate icon">
</p>

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
- Community ip2region city/ISP database with a one-click Telegram updater and legacy cache fallback.
- Optional per-port packet recording with country filters and metadata-only Telegram browsing.
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

- Interface language: English or Chinese.
- Secret URL domain or public hostname.
- Secret URL public TLS port and backend port.
- Relay intranet IP/host, SSH port, username, and auth method.
- SSH password or private key path.
- Optional DDNS whitelist hostname.
- Optional Telegram bot token and ChatID.
- Nginx certificate mode: reuse certificate, self-signed, or skip.

Telegram is optional. If token/ChatID are left blank, the core services still
install and Telegram stays disabled.

## Upgrade

On an already configured exit node, upgrade without re-entering the setup:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/alexchen7/niftgate/main/install.sh) --upgrade
```

Upgrade preserves the exit-node config, then refreshes the relay side using the
saved relay SSH pairing.

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

Manage DDNS records on the relay:

```bash
nft.sh ddns list
nft.sh ddns add mobile.wl.example.com --ruleset public
nft.sh ddns delete 1
nft.sh ddns delete 1 --keep-allowlist
```

The relay DDNS timer refreshes records every 10 seconds. When deleting a DDNS
record, you can remove the whitelist entries created by that record or keep them
with `--keep-allowlist`. The Telegram DDNS delete menu provides both choices as
buttons.

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

## Editing Destinations

Telegram: **Manage > Edit Forwarding Rule > choose a rule**. Use **Listening
Port**, **Destination IP / Host / URL**, or **Destination Port**, then send the
new value. Port moves preserve notes and access policies and reject occupied or
reserved relay ports. Failed DNS or nftables validation leaves the old rule intact.

```bash
nft.sh edit-rule 58495 --new-lport 58496
nft.sh edit-rule 58496 --dest-ip exit.example.com --dest-port 58495
nft.sh add-rule 58500 https://exit.example.com/path 58500
```

For URLs, only the hostname is used. URL paths, schemes and embedded ports do not
change the separately configured destination port; this is TCP/UDP forwarding,
not an HTTP reverse proxy. IPv4 destinations and older databases remain compatible.

The relay's `nft-forward-destinations.timer` checks hostname destinations every
10 seconds, including in attack mode. It applies one atomic nftables update only
when the chosen IPv4 address changes. DNS failures retain the last successful
address and retry on the next cycle. With multiple A records, the current address
is retained while it remains in the answer, avoiding DNS-order churn. New hostnames
must resolve successfully before being saved. Export/import includes both the
hostname and cached address; it does not require DNS during import.

```bash
nft.sh sync-destinations
systemctl status nft-forward-destinations.timer
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
- `Manage`: forwarding rules, rulesets, Secret URLs, and DDNS records.
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

## Blocked History And Search

Telegram: **Log > Blocked History**. Records are shown five per page with
Previous/Next, First/Last, and a clickable page number for jumping to a page.
**Status > Blocked IPs** opens the same paginated view and shows the full count.

**Log > Advanced Search** supports multiple ports, source countries, source
IPs/CIDRs/ranges, TCP/UDP, and a last-blocked time range. Select values with buttons
or enter comma-separated values. **AND** requires every selected filter field;
**OR** accepts any selected field. Multiple values inside a field are OR'd.
For example, ports `1935,24678`, countries `CN,US`, a 24-hour window, and **AND**
match `(port 1935 OR 24678) AND (China OR United States) AND last 24 hours`.

Time presets cover 1/6/24 hours and 7/30 days. Custom durations accept `90m`, `2h`,
or `3d`. Custom dates/times are UTC unless an explicit offset is supplied, such as
`2026-10-01T17:00:00+08:00`. A date-only end bound includes the entire UTC day.
Country matching uses the stored geolocation country, including name/code aliases
for common countries; the picker lists the countries actually present in history.

Records aggregate one source IP + protocol + listening port. The time filter
uses **last_seen**, and each record's count is its **lifetime total**, not the
number of packets within the selected window. This does not reconstruct individual
historical packets. Hidden/deleted history is excluded from new searches.

Each result set is a fixed snapshot, so incoming traffic cannot shuffle pages.
**Refresh** takes a new snapshot (and updates relative time windows). Snapshots
expire after 30 minutes; the cache keeps at most eight, with a 32 MiB/100,000-record
limit per search. Larger searches ask for narrower filters instead of silently
truncating results. Existing snapshots retain the data as it was when queried.
Searching never changes forwarding rules, allowlists, counters, or hidden flags.

CLI examples on the relay:

```bash
nft.sh blocked-search --query '{"ports":[1935,24678],"countries":["CN"],"window":86400,"operator":"AND"}'
nft.sh blocked-search --token TOKEN_FROM_PREVIOUS_RESULT --page 2
nft.sh blocked-filters
```

The existing `nft.sh blocked --limit 20` command retains its JSON-array output.

## IP Cache

Telegram: **Manage > IP Database > Update Database**. The exit node downloads
the public [ip2region dataset](https://github.com/lionsoul2014/ip2region), builds
an indexed SQLite database, and sends it to the relay over the saved SSH pairing.
The relay does not need GitHub access. The job runs in the background; **Refresh
Now** shows progress, the upstream revision/date, and the last synchronized relay
revision. Download or SSH errors appear there and can be retried with the same button.

The free community dataset updates irregularly. IP-based city information is an
estimate, especially for mobile networks and VPNs; the update date is not a claim
of live location accuracy. ip2region is the primary country/province/city/ISP
source; metowolf/iplist and the existing exit-side online lookup remain fallbacks.

On an exit node, without Telegram:

```bash
nft.sh geo-update
nft.sh geo-status
```

To build only the project cache before packaging for offline installation:

```bash
python3 scripts/update_ip_cache.py
```

The cache is stored under:

```text
cache/iplist/geoip.db
cache/iplist/geoip.previous.db
```

The active database is replaced atomically only after range, integrity and
checksum validation. Its source revision, content hash and upstream license are
stored inside it. The previous database is retained. Updating also refreshes
the geo/ISP labels on existing whitelist and blocked records, preserving their
timestamps, expiry, counts and access policies. Historical JSONL logs are retained.
No firewall apply or service restart is needed for database updates.

The updater is `nft-forward-geo-update.service`; it is started on demand, not a
permanently running download loop. Core lookups use Python's standard library and
SQLite; no additional Python package or account is needed. Cache files are ignored
by Git and are preserved across upgrades.

## Packet Recording

Recording is **off by default**, with no ports selected. In Telegram, open
**Manage > Settings > Packet Recording**, select forwarding ports, and turn it on.
The default scope is **Blocked only** (copies from NiftGate's actual drop path).
You can switch to **All incoming** to record TCP/UDP traffic arriving at selected
relay ports, including permitted traffic and established connections. Selecting a
port does not open it or change its whitelist. Port edits carry the selection with
the rule; deleting the rule removes its capture selection.

Choose multiple countries with OR matching, such as CN, GB and AU. An empty list
means all countries. Filtering uses the relay's local IP database, never an online
lookup per packet. Unknown locations are excluded by a country filter unless
Unknown is selected. Geolocation is approximate and may be out of date.

**Log > Recorded Packets** lists rotating capture files. Select a file and browse
packet timestamps (UTC), addresses, ports, protocol/flags, sizes, location/ISP,
PCAP offsets and truncation status. Payloads are never sent to Telegram. Raw IPv4
PCAP files and their metadata indexes stay in the relay's
`/var/lib/nft-forward/captures/` (or `captures/` beside a custom state database),
with directory permissions `0700` and file permissions `0600`.

The terminal menu (`nft.sh menu`, option 7) and CLI provide the same settings;
on an exit node, capture commands proxy to the paired relay:

```bash
nft.sh capture status
nft.sh capture set --json '{"ports":[1935],"scope":"blocked","countries":["CN","GB","AU"]}'
nft.sh capture set --json '{"enabled":true}'
nft.sh capture files
nft.sh capture records <file-id> --page 1
nft.sh capture set --json '{"enabled":false}'
```

The relay installer adds `tcpdump` and `nft-forward-capture.service`. The collector
is idle until enabled with selected ports. Default limits are **256 MiB total
PCAP/index storage, 7 days, and 500 packet copies/second**. Older segments are
deleted automatically; low disk space skips recording instead of disrupting
forwarding. Limits are configurable in Telegram/terminal. The service has a 25%
CPU quota and a 256 MiB memory limit. NFLOG group `61440` is reserved for NiftGate.
Do not run another NFLOG collector on that group.

Recording is best effort: rate limiting, kernel queue overflow, resource limits,
or collector outages can lose copies. It does not accept blocked connections to
solicit payloads: a blocked TCP SYN often has no application payload. Only IPv4
TCP/UDP with decodable headers is indexed. Capture files may contain sensitive
traffic; keep them private. Upgrades preserve settings/files; export/import does
not include captures or enable recording on newly imported rules. Uninstallation
stops recording; removing state also deletes stored captures.

### Exclude Whitelisted Sources

In **Log > Advanced Search**, turn on **Exclude Whitelisted**. This excludes IPs
covered by any currently active public or custom whitelist entry, including
CIDRs/ranges. Expired entries do not exclude an IP. The exclusion applies even
when other filters use OR. Existing search pages retain their snapshot; Refresh
re-evaluates the current whitelist. No firewall rules or blocked records change.

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
