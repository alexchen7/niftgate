#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
INSTALL_DIR="/opt/nft-forward"
CONFIG_DIR="/etc/nft-forward-exit"
STATE_DIR="/var/lib/nft-forward-exit"
CERT_DIR="${CONFIG_DIR}/certs"
NGINX_SITE="/etc/nginx/sites-available/nft-forward-phone.conf"
NGINX_LINK="/etc/nginx/sites-enabled/nft-forward-phone.conf"

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

if ! command -v nginx >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y nginx
fi
for cmd in python3 ssh systemctl openssl; do
    command -v "${cmd}" >/dev/null 2>&1 || apt-get install -y python3 openssh-client systemd openssl
done
systemctl enable --now nginx

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${CERT_DIR}" "${CONFIG_DIR}/ssh"
cp -a "${PROJECT_DIR}/." "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/bin/nft.sh" "${INSTALL_DIR}/scripts/"*.sh "${INSTALL_DIR}/scripts/update_ip_cache.py" 2>/dev/null || true

install -m 0755 "${INSTALL_DIR}/bin/nft.sh" /usr/local/bin/nft.sh
install -m 0755 "${INSTALL_DIR}/scripts/exit_geo_command.sh" /usr/local/bin/nft-forward-exit-geo-command

if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
    install -m 0600 "${INSTALL_DIR}/config/config.example.json" "${CONFIG_DIR}/config.json"
    python3 - "${CONFIG_DIR}/config.json" <<'PY'
import json, secrets, sys
path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
data["role"] = "exit"
data["paths"]["state_db"] = "/var/lib/nft-forward-exit/state.db"
data["phone"]["secret_path"] = secrets.token_urlsafe(48)
json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print()
PY
    echo "Created ${CONFIG_DIR}/config.json; edit Telegram token, admin IDs, and relay SSH settings."
fi

NFT_FORWARD_CONFIG="${CONFIG_DIR}/config.json" /usr/local/bin/nft.sh init-db
install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-telegram.service" /etc/systemd/system/
install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-phone.service" /etc/systemd/system/
install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-queue.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nft-forward-exit-phone.service || true
systemctl enable --now nft-forward-exit-queue.service || true

detected_cert=""
detected_key=""
for pair in \
    "/root/cert/fullchain.pem:/root/cert/privkey.pem" \
    "/root/cert/cert.pem:/root/cert/key.pem"; do
    cert="${pair%%:*}"
    key="${pair##*:}"
    if [[ -f "${cert}" && -f "${key}" ]]; then
        detected_cert="${cert}"
        detected_key="${key}"
        break
    fi
done
if [[ -z "${detected_cert}" && -d /root/.acme.sh ]]; then
    cert="$(find /root/.acme.sh -name fullchain.cer -type f | head -n 1 || true)"
    if [[ -n "${cert}" ]]; then
        key="$(dirname "${cert}")/$(basename "$(dirname "${cert}")").key"
        [[ -f "${key}" ]] && detected_cert="${cert}" && detected_key="${key}"
    fi
fi

configure_nginx() {
    local cert="$1" key="$2" server_name="$3"
    local port secret
    backend_port="$(python3 -c 'import json;print(json.load(open("'"${CONFIG_DIR}/config.json"'"))["phone"]["port"])')"
    public_port="$(python3 -c 'import json;print(json.load(open("'"${CONFIG_DIR}/config.json"'"))["phone"].get("public_port", 18443))')"
    secret="$(python3 -c 'import json;print(json.load(open("'"${CONFIG_DIR}/config.json"'"))["phone"]["secret_path"])')"
    cat >"${NGINX_SITE}" <<EOF_NGINX
server {
    listen ${public_port} ssl;
    server_name ${server_name};

    ssl_certificate ${cert};
    ssl_certificate_key ${key};

    location /${secret} {
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:${backend_port}/${secret};
    }

    location / {
        return 404;
    }
}
EOF_NGINX
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
    nginx -t && systemctl reload nginx
}

self_signed() {
    local name="${1:-nft-forward.local}"
    local dir="${CERT_DIR}/self-signed"
    mkdir -p "${dir}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -subj "/CN=${name}" \
        -keyout "${dir}/privkey.pem" \
        -out "${dir}/fullchain.pem"
    echo "${dir}/fullchain.pem:${dir}/privkey.pem"
}

echo ""
echo "Certificate setup for exit-node phone URL:"
echo "1) Reuse detected/3x-ui certificate"
echo "2) Issue Cloudflare DNS certificate with acme.sh"
echo "3) Try Let's Encrypt IP certificate"
echo "4) Skip TLS/Nginx config for now"
read -rp "Choose [1-4]: " cert_choice

case "${cert_choice}" in
    1)
        echo "Detected cert: ${detected_cert:-none}"
        echo "Detected key : ${detected_key:-none}"
        read -rp "Certificate path [${detected_cert}]: " cert
        read -rp "Key path [${detected_key}]: " key
        cert="${cert:-${detected_cert}}"
        key="${key:-${detected_key}}"
        read -rp "Nginx server_name [_]: " server_name
        server_name="${server_name:-_}"
        if [[ -f "${cert}" && -f "${key}" ]]; then
            configure_nginx "${cert}" "${key}" "${server_name}"
        else
            echo "Certificate/key not found; skipping Nginx TLS config." >&2
        fi
        ;;
    2)
        command -v curl >/dev/null 2>&1 || apt-get install -y curl
        if [[ ! -x /root/.acme.sh/acme.sh ]]; then
            curl https://get.acme.sh | sh
        fi
        read -rp "Cloudflare domain name: " domain
        read -rp "Cloudflare API token (DNS edit): " cf_token
        export CF_Token="${cf_token}"
        /root/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" || true
        mkdir -p "${CERT_DIR}/${domain}"
        /root/.acme.sh/acme.sh --install-cert -d "${domain}" \
            --key-file "${CERT_DIR}/${domain}/privkey.pem" \
            --fullchain-file "${CERT_DIR}/${domain}/fullchain.pem" || true
        if [[ -f "${CERT_DIR}/${domain}/fullchain.pem" && -f "${CERT_DIR}/${domain}/privkey.pem" ]]; then
            configure_nginx "${CERT_DIR}/${domain}/fullchain.pem" "${CERT_DIR}/${domain}/privkey.pem" "${domain}"
        else
            echo "Cloudflare certificate failed; keeping services running without Nginx TLS config." >&2
        fi
        ;;
    3)
        command -v curl >/dev/null 2>&1 || apt-get install -y curl
        if [[ ! -x /root/.acme.sh/acme.sh ]]; then
            curl https://get.acme.sh | sh
        fi
        read -rp "IP address for certificate: " ip_addr
        mkdir -p "${CERT_DIR}/${ip_addr}"
        set +e
        /root/.acme.sh/acme.sh --issue --server letsencrypt --standalone --preferred-chain "ISRG Root X1" --valid-to 168 -d "${ip_addr}" \
            --key-file "${CERT_DIR}/${ip_addr}/privkey.pem" \
            --fullchain-file "${CERT_DIR}/${ip_addr}/fullchain.pem"
        rc=$?
        set -e
        if [[ ${rc} -ne 0 || ! -f "${CERT_DIR}/${ip_addr}/fullchain.pem" ]]; then
            echo "IP certificate failed; falling back to self-signed certificate." >&2
            pair="$(self_signed "${ip_addr}")"
            configure_nginx "${pair%%:*}" "${pair##*:}" "_"
        else
            configure_nginx "${CERT_DIR}/${ip_addr}/fullchain.pem" "${CERT_DIR}/${ip_addr}/privkey.pem" "_"
        fi
        ;;
    *)
        echo "Skipping certificate/Nginx TLS config."
        ;;
esac

cat <<EOF

Exit-node installation complete.

Next steps:
1. Edit ${CONFIG_DIR}/config.json with Telegram token/admin IDs and relay SSH settings.
2. Add the relay public key to this exit node like:
   command="/usr/local/bin/nft-forward-exit-geo-command",no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA...
3. Enable Telegram after config is ready:
   systemctl enable --now nft-forward-exit-telegram.service

EOF
