#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
INSTALL_DIR="/opt/nft-forward"
CONFIG_DIR="/etc/nft-forward"
STATE_DIR="/var/lib/nft-forward"
LOG_DIR="/var/log/nft-forward"

if [[ ${EUID} -ne 0 ]]; then
    echo "Please run as root." >&2
    exit 1
fi

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
else
    ID=unknown
fi

if [[ "${ID}" != "debian" && "${ID}" != "ubuntu" ]]; then
    echo "Warning: this installer is tested on Debian/Ubuntu; continuing anyway." >&2
fi

need_pkg=()
for cmd in python3 nft ssh systemctl; do
    command -v "${cmd}" >/dev/null 2>&1 || need_pkg+=("${cmd}")
done
if ((${#need_pkg[@]})); then
    apt-get update -y
    apt-get install -y python3 nftables openssh-client systemd
fi

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" /etc/nftables.d
cp -a "${PROJECT_DIR}/." "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/bin/nft.sh" "${INSTALL_DIR}/scripts/"*.sh "${INSTALL_DIR}/scripts/update_ip_cache.py" 2>/dev/null || true

install -m 0755 "${INSTALL_DIR}/bin/nft.sh" /usr/local/bin/nft.sh
install -m 0755 "${INSTALL_DIR}/scripts/relay_restricted_command.sh" /usr/local/bin/nft-forward-relay-command

if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
    install -m 0600 "${INSTALL_DIR}/config/config.example.json" "${CONFIG_DIR}/config.json"
    echo "Created ${CONFIG_DIR}/config.json; edit SSH/DDNS settings before enabling remote integrations."
fi

if [[ ! -f /etc/nftables.conf ]]; then
    cat >/etc/nftables.conf <<'NFTCONF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.conf"
NFTCONF
elif ! grep -qF 'include "/etc/nftables.d/*.conf"' /etc/nftables.conf; then
    printf '\ninclude "/etc/nftables.d/*.conf"\n' >> /etc/nftables.conf
fi

NFT_FORWARD_CONFIG="${CONFIG_DIR}/config.json" /usr/local/bin/nft.sh init-db
if [[ -f /etc/nftables.d/port-forward.conf ]]; then
    NFT_FORWARD_CONFIG="${CONFIG_DIR}/config.json" /usr/local/bin/nft.sh import-legacy /etc/nftables.d/port-forward.conf || true
fi
NFT_FORWARD_CONFIG="${CONFIG_DIR}/config.json" /usr/local/bin/nft.sh apply --no-apply || true

install -m 0644 "${INSTALL_DIR}/services/nft-forward-blocklog.service" /etc/systemd/system/
install -m 0644 "${INSTALL_DIR}/services/nft-forward-sshlog.service" /etc/systemd/system/
install -m 0644 "${INSTALL_DIR}/services/nft-forward-ddns.service" /etc/systemd/system/
install -m 0644 "${INSTALL_DIR}/services/nft-forward-ddns.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nft-forward-blocklog.service || true
systemctl enable --now nft-forward-sshlog.service || true
systemctl enable --now nft-forward-ddns.timer || true
systemctl enable --now nftables || true

cat <<EOF

Relay installation complete.

Next steps:
1. Edit ${CONFIG_DIR}/config.json
2. Add the exit node public key to /root/.ssh/authorized_keys like:
   command="/usr/local/bin/nft-forward-relay-command",no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA...
3. Run: nft.sh status

EOF
