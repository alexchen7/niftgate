#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
INSTALL_DIR="/opt/nft-forward"
EXIT_CONFIG_DIR="/etc/nft-forward-exit"
RELAY_CONFIG_DIR="/etc/nft-forward"
NIFTGATE_REF="${NIFTGATE_REF:-main}"
NIFTGATE_ARCHIVE_URL="${NIFTGATE_ARCHIVE_URL:-https://github.com/alexchen7/niftgate/archive/refs/heads/${NIFTGATE_REF}.tar.gz}"
BOOTSTRAP_TMP=""
DRY_RUN=0
MODE="full"
INSTALL_LANG="${INSTALL_LANG:-en}"

usage() {
    cat <<'EOF'
Usage: bash install.sh [--dry-run] [--exit-only|--relay-only|--upgrade|--uninstall]

Default: run on the exit node, install exit services, then install the relay
over SSH using the relay intranet address.

Use --upgrade on an already configured exit node to refresh NiftGate without
re-entering domain, relay, DDNS, Telegram, or certificate settings.
EOF
}

while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --exit-only) MODE="exit-only" ;;
        --relay-only) MODE="relay-only" ;;
        --upgrade) MODE="upgrade" ;;
        --uninstall) MODE="uninstall" ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

run() {
    if ((DRY_RUN)); then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

apt_install() {
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        "$@"
}

ask() {
    local prompt="$1" default="${2:-}" value
    if [[ -n "$default" ]]; then
        read -rp "${prompt} [${default}]: " value
        printf '%s' "${value:-$default}"
    else
        read -rp "${prompt}: " value
        printf '%s' "$value"
    fi
}

normalize_lang() {
    case "${1,,}" in
        zh|cn|zh-cn|chinese) printf '%s' "zh" ;;
        *) printf '%s' "en" ;;
    esac
}

msg() {
    if [[ "${INSTALL_LANG}" == "zh" ]]; then
        printf '%s' "$2"
    else
        printf '%s' "$1"
    fi
}

load_existing_language() {
    local cfg="${EXIT_CONFIG_DIR}/config.json" current
    if [[ -f "$cfg" ]] && command -v python3 >/dev/null 2>&1; then
        current="$(python3 - "$cfg" <<'PY' 2>/dev/null || true
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    print(data.get("ui", {}).get("language", data.get("language", "")))
except Exception:
    pass
PY
)"
        if [[ -n "$current" ]]; then
            INSTALL_LANG="$(normalize_lang "$current")"
        fi
    else
        INSTALL_LANG="$(normalize_lang "$INSTALL_LANG")"
    fi
}

choose_language() {
    local value
    load_existing_language
    while true; do
        value="$(ask "Language / 语言: English or 中文 (en/zh)" "$INSTALL_LANG")"
        case "${value,,}" in
            en|english)
                INSTALL_LANG="en"
                return 0
                ;;
            zh|cn|zh-cn|chinese)
                INSTALL_LANG="zh"
                return 0
                ;;
            *)
                echo "Please enter en or zh. / 请输入 en 或 zh。" >&2
                ;;
        esac
    done
}

ask_auth_method() {
    local value
    while true; do
        value="$(ask "$(msg "Relay SSH auth method: type 'password' or 'key' (do not enter the secret here)" "中继 SSH 认证方式：输入 'password' 或 'key'（这里不要输入密码/密钥内容）")" "password")"
        case "${value,,}" in
            password|pass)
                printf '%s' "password"
                return 0
                ;;
            key|passkey|ssh-key|sshkey)
                printf '%s' "key"
                return 0
                ;;
            *)
                echo "$(msg "Please enter only 'password' or 'key'. The actual secret is requested on the next prompt." "请输入 'password' 或 'key'。真正的密码/密钥会在下一步询问。")" >&2
                ;;
        esac
    done
}

secret_ask() {
    local prompt="$1" value
    read -rsp "${prompt}: " value
    printf '\n' >&2
    printf '%s' "$value"
}

cleanup_bootstrap() {
    if [[ -n "${BOOTSTRAP_TMP}" && -d "${BOOTSTRAP_TMP}" ]]; then
        rm -rf "${BOOTSTRAP_TMP}"
    fi
}
trap cleanup_bootstrap EXIT

resolve_project_dir() {
    if [[ -f "${PROJECT_DIR}/bin/nft.sh" && -d "${PROJECT_DIR}/nft_forward" ]]; then
        return 0
    fi

    local archive extracted
    BOOTSTRAP_TMP="$(mktemp -d /tmp/niftgate-install.XXXXXX)"
    archive="${BOOTSTRAP_TMP}/niftgate.tgz"
    echo "Full project files were not found next to install.sh; downloading NiftGate ${NIFTGATE_REF}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${NIFTGATE_ARCHIVE_URL}" -o "${archive}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${archive}" "${NIFTGATE_ARCHIVE_URL}"
    else
        echo "curl or wget is required to install from the one-line script." >&2
        exit 1
    fi
    tar -xzf "${archive}" -C "${BOOTSTRAP_TMP}"
    extracted="$(find "${BOOTSTRAP_TMP}" -mindepth 1 -maxdepth 1 -type d -name 'niftgate-*' | head -n 1)"
    if [[ -z "${extracted}" || ! -f "${extracted}/bin/nft.sh" ]]; then
        echo "Downloaded archive does not look like a NiftGate release." >&2
        exit 1
    fi
    PROJECT_DIR="${extracted}"
}

install_common() {
    resolve_project_dir
    if [[ ${EUID} -ne 0 && ${DRY_RUN} -eq 0 ]]; then
        echo "Please run as root." >&2
        exit 1
    fi
    if command -v apt-get >/dev/null 2>&1; then
        run apt-get update -y
        apt_install python3 openssh-client openssh-server systemd tar
    fi
    run mkdir -p "${INSTALL_DIR}"
    run cp -a "${PROJECT_DIR}/." "${INSTALL_DIR}/"
    run install -m 0755 "${INSTALL_DIR}/bin/nft.sh" /usr/local/bin/nft.sh
}

write_json_with_python() {
    local path="$1" code="$2"
    if ((DRY_RUN)); then
        printf '[dry-run] update json %s\n%s\n' "$path" "$code"
    else
        python3 - "$path" <<PY
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
$code
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")
path.chmod(0o600)
PY
    fi
}

setup_exit_config() {
    local domain public_port backend_port tg_token tg_chat relay_host relay_user relay_port relay_auth relay_key relay_pass ddns_host
    choose_language
    domain="$(ask "$(msg "Secret URL domain/public host" "Secret URL 域名/公网主机名")")"
    public_port="$(ask "$(msg "Secret URL public TLS port" "Secret URL 公网 TLS 端口")" "18443")"
    backend_port="$(ask "$(msg "Secret URL backend port" "Secret URL 后端端口")" "18088")"
    relay_host="$(ask "$(msg "Relay intranet IP/host" "中继服务器内网 IP/主机名")")"
    relay_user="$(ask "$(msg "Relay SSH user" "中继服务器 SSH 用户")" "root")"
    relay_port="$(ask "$(msg "Relay SSH port" "中继服务器 SSH 端口")" "22")"
    relay_auth="$(ask_auth_method)"
    relay_key=""
    relay_pass=""
    if [[ "$relay_auth" == "key" ]]; then
        relay_key="$(ask "$(msg "Relay SSH key path" "中继服务器 SSH 密钥路径")" "${EXIT_CONFIG_DIR}/ssh/relay_ed25519")"
    else
        relay_pass="$(secret_ask "$(msg "Relay SSH password" "中继服务器 SSH 密码")")"
        if command -v apt-get >/dev/null 2>&1 && ! command -v sshpass >/dev/null 2>&1; then
            apt_install sshpass
        fi
    fi
    ddns_host="$(ask "$(msg "Optional DDNS whitelist hostname" "可选 DDNS 白名单主机名")" "")"
    tg_token="$(ask "$(msg "Optional Telegram bot token" "可选 Telegram 机器人 Token")" "")"
    tg_chat="$(ask "$(msg "Optional Telegram ChatID" "可选 Telegram ChatID")" "")"

    run mkdir -p "${EXIT_CONFIG_DIR}/ssh"
    if [[ "$relay_auth" == "password" ]]; then
        if ((DRY_RUN)); then
            echo "[dry-run] write relay password to ${EXIT_CONFIG_DIR}/ssh/relay_password"
        else
            umask 077
            printf '%s\n' "$relay_pass" >"${EXIT_CONFIG_DIR}/ssh/relay_password"
        fi
    fi
    if [[ ! -f "${EXIT_CONFIG_DIR}/config.json" ]]; then
        run install -m 0600 "${INSTALL_DIR}/config/config.example.json" "${EXIT_CONFIG_DIR}/config.json"
    fi
    write_json_with_python "${EXIT_CONFIG_DIR}/config.json" "
data['role'] = 'exit'
ui = data.setdefault('ui', {})
ui['language'] = '$INSTALL_LANG'
data.setdefault('paths', {})['state_db'] = '/var/lib/nft-forward-exit/state.db'
ssh = data.setdefault('ssh', {})
ssh['relay_host'] = '$relay_host'
ssh['relay_user'] = '$relay_user'
ssh['relay_port'] = int('$relay_port')
ssh['relay_auth_method'] = '$relay_auth'
ssh['relay_key'] = '$relay_key'
ssh['relay_password_file'] = '${EXIT_CONFIG_DIR}/ssh/relay_password' if '$relay_auth' == 'password' else ''
phone = data.setdefault('phone', {})
phone['public_host'] = '$domain'
phone['public_port'] = int('$public_port')
phone['public_scheme'] = 'https'
phone['port'] = int('$backend_port')
phone['bind'] = '127.0.0.1'
import secrets
if not phone.get('secret_path') or phone.get('secret_path', '').startswith('replace-with'):
    phone['secret_path'] = 'wl-' + secrets.token_urlsafe(48)
data['ddns'] = ([{'host': '$ddns_host', 'ruleset': 'public'}] if '$ddns_host' else data.get('ddns', []))
telegram = data.setdefault('telegram', {})
telegram['token'] = '$tg_token'
telegram['admin_ids'] = ([int('$tg_chat')] if '$tg_chat' else [])
"
}

configure_exit_nginx() {
    local cfg="${EXIT_CONFIG_DIR}/config.json" domain public_port backend_port cert_choice cert key cert_dir site
    load_existing_language
    if ((DRY_RUN)); then
        cert_choice="$(ask "$(msg "Nginx TLS certificate (reuse/self-signed/skip)" "Nginx TLS 证书（reuse/self-signed/skip）")" "reuse")"
        echo "[dry-run] configure Nginx TLS mode: ${cert_choice}"
        return 0
    fi
    domain="$(python3 -c "import json;d=json.load(open('$cfg'));print(d.get('phone',{}).get('public_host') or '_')")"
    public_port="$(python3 -c "import json;d=json.load(open('$cfg'));print(d.get('phone',{}).get('public_port',18443))")"
    backend_port="$(python3 -c "import json;d=json.load(open('$cfg'));print(d.get('phone',{}).get('port',18088))")"
    cert_choice="$(ask "$(msg "Nginx TLS certificate (reuse/self-signed/skip)" "Nginx TLS 证书（reuse/self-signed/skip）")" "reuse")"
    cert=""
    key=""
    if [[ "$cert_choice" == "reuse" ]]; then
        cert="$(ask "$(msg "Certificate fullchain path" "证书 fullchain 路径")" "/root/cert/fullchain.pem")"
        key="$(ask "$(msg "Certificate private key path" "证书私钥路径")" "/root/cert/privkey.pem")"
    elif [[ "$cert_choice" == "self-signed" ]]; then
        cert_dir="${EXIT_CONFIG_DIR}/certs/self-signed"
        run mkdir -p "$cert_dir"
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj "/CN=${domain}" \
            -keyout "${cert_dir}/privkey.pem" \
            -out "${cert_dir}/fullchain.pem"
        cert="${cert_dir}/fullchain.pem"
        key="${cert_dir}/privkey.pem"
    else
        echo "$(msg "Skipping Nginx TLS config." "跳过 Nginx TLS 配置。")"
        return 0
    fi
    site="/etc/nginx/sites-available/nft-forward-secret-url.conf"
    cat >"${site}" <<EOF_NGINX
server {
    listen ${public_port} ssl;
    server_name ${domain};

    ssl_certificate ${cert};
    ssl_certificate_key ${key};

    location / {
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:${backend_port};
    }
}
EOF_NGINX
    ln -sf "${site}" /etc/nginx/sites-enabled/nft-forward-secret-url.conf
    nginx -t
    systemctl reload nginx
}

install_exit() {
    install_common
    if command -v apt-get >/dev/null 2>&1; then
        apt_install nginx openssl
    fi
    run systemctl enable --now nginx
    setup_exit_config
    configure_exit_nginx
    run env NFT_FORWARD_CONFIG="${EXIT_CONFIG_DIR}/config.json" /usr/local/bin/nft.sh init-db
    run install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-phone.service" /etc/systemd/system/
    run install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-queue.service" /etc/systemd/system/
    run install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-telegram.service" /etc/systemd/system/
    run systemctl daemon-reload
    run systemctl enable --now nft-forward-exit-phone.service
    run systemctl enable --now nft-forward-exit-queue.service
    run systemctl restart nft-forward-exit-phone.service
    run systemctl restart nft-forward-exit-queue.service
    if ((DRY_RUN)); then
        echo "[dry-run] enable Telegram only if token is configured"
    elif python3 - <<PY
import json
data=json.load(open('${EXIT_CONFIG_DIR}/config.json'))
raise SystemExit(0 if data.get('telegram',{}).get('token') else 1)
PY
    then
        run systemctl enable --now nft-forward-exit-telegram.service
        run systemctl restart nft-forward-exit-telegram.service
    else
        run systemctl disable --now nft-forward-exit-telegram.service || true
    fi
}

upgrade_existing() {
    install_common
    if [[ ! -f "${EXIT_CONFIG_DIR}/config.json" ]]; then
        echo "No existing ${EXIT_CONFIG_DIR}/config.json found. Run the normal installer first." >&2
        exit 1
    fi
    run env NFT_FORWARD_CONFIG="${EXIT_CONFIG_DIR}/config.json" /usr/local/bin/nft.sh init-db
    run install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-phone.service" /etc/systemd/system/
    run install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-queue.service" /etc/systemd/system/
    run install -m 0644 "${INSTALL_DIR}/services/nft-forward-exit-telegram.service" /etc/systemd/system/
    run systemctl daemon-reload
    run systemctl enable --now nft-forward-exit-phone.service
    run systemctl enable --now nft-forward-exit-queue.service
    run systemctl restart nft-forward-exit-phone.service
    run systemctl restart nft-forward-exit-queue.service
    if ((DRY_RUN)); then
        echo "[dry-run] enable Telegram only if token is configured"
    elif python3 - <<PY
import json
data=json.load(open('${EXIT_CONFIG_DIR}/config.json'))
raise SystemExit(0 if data.get('telegram',{}).get('token') else 1)
PY
    then
        run systemctl enable --now nft-forward-exit-telegram.service
        run systemctl restart nft-forward-exit-telegram.service
    else
        run systemctl disable --now nft-forward-exit-telegram.service || true
    fi
    install_relay_remote
}

ssh_prefix() {
    local host="$1" user="$2" port="$3" auth="$4" key="$5" passfile="$6"
    if [[ "$auth" == "password" ]]; then
        printf 'sshpass -f %q ssh -o BatchMode=no -o ConnectTimeout=8 -p %q %q@%q' "$passfile" "$port" "$user" "$host"
    else
        printf 'ssh -o BatchMode=yes -o ConnectTimeout=8 -i %q -p %q %q@%q' "$key" "$port" "$user" "$host"
    fi
}

install_relay_remote() {
    local cfg="${EXIT_CONFIG_DIR}/config.json" host user port auth key passfile tmp local_pkg remote_dir verify_out
    if ((DRY_RUN)); then
        echo "[dry-run] package project and install relay over SSH using the configured relay intranet address"
        return 0
    fi
    host="$(python3 -c "import json;d=json.load(open('$cfg'));print(d['ssh']['relay_host'])")"
    user="$(python3 -c "import json;d=json.load(open('$cfg'));print(d['ssh'].get('relay_user','root'))")"
    port="$(python3 -c "import json;d=json.load(open('$cfg'));print(d['ssh'].get('relay_port',22))")"
    auth="$(python3 -c "import json;d=json.load(open('$cfg'));print(d['ssh'].get('relay_auth_method','key'))")"
    key="$(python3 -c "import json;d=json.load(open('$cfg'));print(d['ssh'].get('relay_key',''))")"
    passfile="$(python3 -c "import json;d=json.load(open('$cfg'));print(d['ssh'].get('relay_password_file',''))")"

    if [[ -z "$host" || -z "$user" || -z "$port" ]]; then
        echo "Relay SSH settings are incomplete; cannot install relay side." >&2
        exit 1
    fi
    if [[ "$auth" == "password" ]]; then
        if [[ -z "$passfile" || ! -f "$passfile" ]]; then
            echo "Relay password auth is selected, but the relay password file is missing: ${passfile}" >&2
            exit 1
        fi
        if ! command -v sshpass >/dev/null 2>&1; then
            if command -v apt-get >/dev/null 2>&1; then
                apt_install sshpass
            else
                echo "sshpass is required for relay password auth but is not installed." >&2
                exit 1
            fi
        fi
    elif [[ "$auth" == "key" ]]; then
        if [[ -z "$key" || ! -f "$key" ]]; then
            echo "Relay key auth is selected, but the relay key file is missing: ${key}" >&2
            exit 1
        fi
    else
        echo "Unknown relay SSH auth method: ${auth}" >&2
        exit 1
    fi

    echo "Installing relay side on ${user}@${host}:${port}..."
    local_pkg="$(mktemp /tmp/niftgate-relay.XXXXXX.tgz)"
    tmp="/tmp/niftgate-relay-install.tgz"
    remote_dir="/tmp/niftgate-relay-install"
    tar -czf "$local_pkg" -C "${PROJECT_DIR}" .

    if [[ "$auth" == "password" ]]; then
        sshpass -f "$passfile" scp -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -P "$port" "$local_pkg" "${user}@${host}:${tmp}"
        sshpass -f "$passfile" ssh -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -p "$port" "${user}@${host}" \
            "rm -rf ${remote_dir} && mkdir -p ${remote_dir} && tar -xzf ${tmp} -C ${remote_dir} && bash ${remote_dir}/scripts/init_relay.sh"
    else
        scp -i "$key" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -P "$port" "$local_pkg" "${user}@${host}:${tmp}"
        ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -p "$port" "${user}@${host}" \
            "rm -rf ${remote_dir} && mkdir -p ${remote_dir} && tar -xzf ${tmp} -C ${remote_dir} && bash ${remote_dir}/scripts/init_relay.sh"
    fi
    rm -f "$local_pkg"

    if [[ "$auth" == "password" ]]; then
        if ! verify_out="$(sshpass -f "$passfile" ssh -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -p "$port" "${user}@${host}" "/usr/local/bin/nft.sh bot-status" 2>&1)"; then
            echo "Relay installation verification failed. The relay did not return bot-status:" >&2
            echo "$verify_out" >&2
            exit 1
        fi
    else
        if ! verify_out="$(ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -p "$port" "${user}@${host}" "/usr/local/bin/nft.sh bot-status" 2>&1)"; then
            echo "Relay installation verification failed. The relay did not return bot-status:" >&2
            echo "$verify_out" >&2
            exit 1
        fi
    fi
    echo "Relay installation verified: ${verify_out}"

    local secret_path secret_b64 remote_secret_cmd
    secret_path="$(python3 -c "import json;d=json.load(open('$cfg'));print(d.get('phone',{}).get('secret_path',''))")"
    if [[ -n "${secret_path}" ]]; then
        secret_b64="$(printf '%s' "${secret_path}" | base64 | tr -d '\n')"
        remote_secret_cmd="secret=\$(printf '%s' '${secret_b64}' | base64 -d); NFT_FORWARD_CONFIG=/etc/nft-forward/config.json /usr/local/bin/nft.sh secret-url create --ruleset public --label default --path \"\$secret\" 2>/dev/null || true"
        if [[ "$auth" == "password" ]]; then
            sshpass -f "$passfile" ssh -o BatchMode=no -o ConnectTimeout=8 -p "$port" "${user}@${host}" "${remote_secret_cmd}"
        else
            ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=8 -p "$port" "${user}@${host}" "${remote_secret_cmd}"
        fi
        NFT_FORWARD_CONFIG="${EXIT_CONFIG_DIR}/config.json" /usr/local/bin/nft.sh sync-from-relay || true
    fi
}

uninstall_local() {
    load_existing_language
    run systemctl disable --now nft-forward-exit-phone.service nft-forward-exit-queue.service nft-forward-exit-telegram.service || true
    run systemctl disable --now nft-forward-blocklog.service nft-forward-sshlog.service nft-forward-ddns.timer || true
    run rm -f /etc/nftables.d/nft-forward-managed.conf
    if command -v nft >/dev/null 2>&1; then
        run nft delete table ip nft_forward || true
    fi
    run rm -f /etc/systemd/system/nft-forward-*.service /etc/systemd/system/nft-forward-*.timer
    run systemctl daemon-reload
    read -rp "$(msg "Remove config/state/logs too? [y/N]: " "同时删除配置/状态/日志吗？[y/N]: ")" remove_data
    if [[ "${remove_data,,}" == "y" ]]; then
        run rm -rf /etc/nft-forward /etc/nft-forward-exit /var/lib/nft-forward /var/lib/nft-forward-exit /var/log/nft-forward /var/log/nft-forward-exit
    fi
    run rm -rf "${INSTALL_DIR}"
}

case "$MODE" in
    full)
        install_exit
        install_relay_remote
        ;;
    exit-only)
        install_exit
        ;;
    relay-only)
        install_common
        run bash "${INSTALL_DIR}/scripts/init_relay.sh"
        ;;
    upgrade)
        upgrade_existing
        ;;
    uninstall)
        uninstall_local
        ;;
esac
