#!/bin/bash

# ====================================================
# VPS Unified Init Script
# Merges:
# - ssh-rescue.sh
# - vps-modular-init.sh
# Adds:
# - OpenClaw + SearXNG + Caddy deployment
# - Optional Cloudflare origin lockdown for 80/443
# ====================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误：请使用 root 身份运行${NC}"
    exit 1
fi

if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}错误：仅支持 Debian 或 Ubuntu 系统${NC}"
    exit 1
fi

OS_NAME="$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')"
DEFAULT_HOSTNAME="${OS_NAME}-vps"
DEFAULT_NEW_SSH_PORT="22222"

USERNAME=""
USER_PASSWORD=""
SSH_PORT=""
NEW_HOSTNAME="$DEFAULT_HOSTNAME"
SWAP_SIZE="1G"
SSH_KEY=""

OPENCLAW_USER=""
OPENCLAW_DOMAIN=""
OPENCLAW_ACME_EMAIL=""
OPENCLAW_GATEWAY_PORT="18789"
OPENCLAW_CONTROL_PATH="/openclaw"
OPENCLAW_GATEWAY_TOKEN=""
SEARXNG_BIND_PORT="8888"
SEARXNG_LANGUAGE="zh"
USE_CLOUDFLARE_LOCKDOWN="n"
OPENCLAW_CONFIG_PATH=""
OPENCLAW_EXISTING_SERVICE=""
OPENCLAW_BACKUP_DIR=""
OPENCLAW_REUSE_EXISTING_SEARXNG="y"
OPENCLAW_TAKEOVER_EXISTING_SERVICE="n"
OPENCLAW_CLEANUP_EXISTING_SEARXNG="n"
OPENCLAW_EXISTING_SEARXNG_PORT=""

CADDY_IMAGE="caddy:2.10.2-alpine"
SEARXNG_IMAGE="searxng/searxng:latest"
SEARXNG_CONTAINER_NAME="searxng"
OPENCLAW_SEARCH_PLUGIN_REPO="https://github.com/akr-n/openclaw-search.git"

SEARXNG_STACK_DIR="/srv/infra/apps/searxng-openclaw"
CADDY_STACK_DIR="/srv/infra/edge/caddy-openclaw"
SEARXNG_SECRET_DIR="/srv/secrets/searxng-openclaw"
OPENCLAW_SECRET_DIR="/srv/secrets/openclaw"
CADDY_DATA_DIR="/srv/data/caddy-openclaw"
SEARXNG_DATA_DIR="/srv/data/searxng-openclaw"
OPENCLAW_LOCKDOWN_NFT="${CADDY_STACK_DIR}/cloudflare-origin-lockdown.nft"
OPENCLAW_LOCKDOWN_SCRIPT="/usr/local/sbin/apply-openclaw-origin-lockdown.sh"
OPENCLAW_LOCKDOWN_SERVICE="/etc/systemd/system/openclaw-origin-lockdown.service"
OPENCLAW_GATEWAY_SERVICE="/etc/systemd/system/openclaw-gateway.service"

line() {
    echo -e "${BLUE}$(printf '=%.0s' {1..72})${NC}"
}

title() {
    line
    echo -e "${GREEN}$1${NC}"
    line
}

log_info() {
    echo -e "${GREEN}[信息]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}>>> $1${NC}\n"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

normalize_answer() {
    printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]'
}

answer_is_yes() {
    case "$(normalize_answer "${1:-}")" in
        y|yes|shi|true|1|是)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

answer_is_no() {
    case "$(normalize_answer "${1:-}")" in
        n|no|fou|false|0|否)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

confirm_default_no() {
    local answer="${1:-}"
    [ -n "$answer" ] || return 1
    answer_is_yes "$answer"
}

confirm_default_yes() {
    local answer="${1:-}"
    [ -n "$answer" ] || return 0
    answer_is_no "$answer" && return 1
    answer_is_yes "$answer"
}

yn_to_label() {
    if [ "${1:-n}" = "y" ]; then
        echo "Y"
    else
        echo "N"
    fi
}

ensure_package() {
    if ! dpkg -s "$1" >/dev/null 2>&1; then
        apt-get install -y "$1"
    fi
}

is_valid_username() {
    local name="$1"
    [[ "$name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || return 1
    [ "$name" != "root" ]
}

is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

is_valid_hostname() {
    local host="$1"
    [[ "$host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

is_valid_swap_size() {
    local size="$1"
    [[ "$size" =~ ^[1-9][0-9]*[KMG]$ ]]
}

detect_admin_user() {
    local user

    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER:-}" != "root" ] && id "${SUDO_USER:-}" >/dev/null 2>&1; then
        echo "${SUDO_USER}"
        return 0
    fi

    if [ -n "${USER:-}" ] && [ "${USER:-}" != "root" ] && id "${USER:-}" >/dev/null 2>&1; then
        if id -nG "${USER}" 2>/dev/null | tr ' ' '\n' | grep -qx "sudo"; then
            echo "${USER}"
            return 0
        fi
    fi

    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$uid" -ge 1000 ] || continue
        [ "$user" = "nobody" ] && continue
        [ "$shell" = "/usr/sbin/nologin" ] && continue
        [ "$shell" = "/bin/false" ] && continue
        if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx "sudo"; then
            echo "$user"
            return 0
        fi
    done < <(getent passwd)

    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$uid" -ge 1000 ] || continue
        [ "$user" = "nobody" ] && continue
        [ "$shell" = "/usr/sbin/nologin" ] && continue
        [ "$shell" = "/bin/false" ] && continue
        echo "$user"
        return 0
    done < <(getent passwd)

    return 1
}

detect_ssh_service_name() {
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "ssh.service"; then
        echo "ssh"
        return
    fi
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "sshd.service"; then
        echo "sshd"
        return
    fi
    if systemctl status ssh >/dev/null 2>&1; then
        echo "ssh"
        return
    fi
    if systemctl status sshd >/dev/null 2>&1; then
        echo "sshd"
        return
    fi

    echo "ssh"
}

restart_ssh_service() {
    local svc
    svc="$(detect_ssh_service_name)"
    if systemctl restart "$svc" >/dev/null 2>&1; then
        return 0
    fi
    if [ "$svc" != "ssh" ] && systemctl restart ssh >/dev/null 2>&1; then
        return 0
    fi
    if [ "$svc" != "sshd" ] && systemctl restart sshd >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

reload_ssh_service() {
    local svc
    svc="$(detect_ssh_service_name)"
    if systemctl reload "$svc" >/dev/null 2>&1; then
        return 0
    fi
    restart_ssh_service
}

detect_sshd_port_runtime() {
    local detected_port
    local parsed_port

    detected_port="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"
    if is_valid_port "$detected_port"; then
        echo "$detected_port"
        return
    fi

    parsed_port="$(
        {
            cat /etc/ssh/sshd_config 2>/dev/null
            cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
        } | awk '
            /^[[:space:]]*#/ { next }
            tolower($1) == "port" && $2 ~ /^[0-9]+$/ { port = $2 }
            END { if (port != "") print port }
        '
    )"

    if is_valid_port "$parsed_port"; then
        echo "$parsed_port"
    else
        echo "22"
    fi
}

effective_ssh_port() {
    if is_valid_port "${SSH_PORT:-}"; then
        echo "$SSH_PORT"
        return
    fi
    detect_sshd_port_runtime
}

hydrate_runtime_defaults() {
    local detected_user
    local detected_port
    local detected_host

    if [ -z "${USERNAME:-}" ] || ! id "${USERNAME:-}" >/dev/null 2>&1; then
        detected_user="$(detect_admin_user || true)"
        if [ -n "$detected_user" ] && is_valid_username "$detected_user"; then
            USERNAME="$detected_user"
        fi
    fi

    detected_port="$(detect_sshd_port_runtime)"
    if is_valid_port "$detected_port"; then
        SSH_PORT="$detected_port"
    fi

    detected_host="$(hostnamectl --static 2>/dev/null || hostname)"
    if [ -n "$detected_host" ] && { [ -z "${NEW_HOSTNAME:-}" ] || [ "$NEW_HOSTNAME" = "$DEFAULT_HOSTNAME" ] || [ "$NEW_HOSTNAME" = "0" ]; }; then
        NEW_HOSTNAME="$detected_host"
    fi
}

set_sshd_option() {
    local key="$1"
    local value="$2"
    local conf="$3"

    if grep -qE "^[#[:space:]]*${key}[[:space:]]+" "$conf"; then
        sed -i -E "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$conf"
    else
        echo "${key} ${value}" >> "$conf"
    fi
}

get_user_home() {
    getent passwd "$1" | cut -d: -f6
}

json_get_file() {
    local file="$1"
    local filter="$2"
    if [ -f "$file" ]; then
        jq -r "$filter // empty" "$file" 2>/dev/null || true
    fi
}

extract_port_from_url() {
    local url="$1"
    if [ -z "$url" ]; then
        return
    fi
    printf '%s\n' "$url" | sed -nE 's#^[a-zA-Z]+://[^:/]+:([0-9]+).*$#\1#p' | head -n1
}

probe_searxng_json_api() {
    local port="$1"
    if ! is_valid_port "$port"; then
        return 1
    fi
    curl -fsS --max-time 10 "http://127.0.0.1:${port}/search?q=test&format=json" >/dev/null
}

detect_openclaw_user() {
    local candidate
    local user
    local home_dir

    for candidate in "${OPENCLAW_USER:-}" "${USERNAME:-}" "$(detect_admin_user || true)" root; do
        [ -n "$candidate" ] || continue
        if ! id "$candidate" >/dev/null 2>&1; then
            continue
        fi
        home_dir="$(get_user_home "$candidate")"
        if [ -x "${home_dir}/.openclaw/bin/openclaw" ] || [ -f "${home_dir}/.openclaw/openclaw.json" ]; then
            echo "$candidate"
            return 0
        fi
    done

    while IFS=: read -r user _ uid _ _ home_dir shell; do
        [ "$uid" -ge 0 ] || continue
        [ "$shell" = "/usr/sbin/nologin" ] && continue
        [ "$shell" = "/bin/false" ] && continue
        if [ -x "${home_dir}/.openclaw/bin/openclaw" ] || [ -f "${home_dir}/.openclaw/openclaw.json" ]; then
            echo "$user"
            return 0
        fi
    done < <(getent passwd)

    return 1
}

detect_openclaw_config_path() {
    local user="$1"
    local home_dir
    home_dir="$(get_user_home "$user")"
    printf '%s\n' "${home_dir}/.openclaw/openclaw.json"
}

detect_caddy_domain_from_caddyfile() {
    local caddyfile="${CADDY_STACK_DIR}/Caddyfile"
    if [ ! -f "$caddyfile" ]; then
        return
    fi

    awk '
        /^[[:space:]]*\{/ { in_global = 1; next }
        in_global && /^[[:space:]]*\}/ { in_global = 0; next }
        in_global { next }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^[^[:space:]\{][^\{]*\{$/ {
            line = $0
            sub(/[[:space:]]*\{[[:space:]]*$/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            split(line, parts, /[[:space:]]*,?[[:space:]]*/)
            print parts[1]
            exit
        }
    ' "$caddyfile" 2>/dev/null || true
}

hydrate_openclaw_runtime_context() {
    local detected_user
    local detected_config
    local detected_gateway_port
    local detected_searxng_url
    local detected_searxng_port
    local detected_domain

    detected_user="$(detect_openclaw_user || true)"
    if [ -n "$detected_user" ] && id "$detected_user" >/dev/null 2>&1; then
        OPENCLAW_USER="$detected_user"
        detected_config="$(detect_openclaw_config_path "$detected_user")"
        if [ -f "$detected_config" ]; then
            OPENCLAW_CONFIG_PATH="$detected_config"
            detected_gateway_port="$(json_get_file "$detected_config" '.gateway.port')"
            if is_valid_port "$detected_gateway_port"; then
                OPENCLAW_GATEWAY_PORT="$detected_gateway_port"
            fi

            detected_searxng_url="$(json_get_file "$detected_config" '.plugins.entries["openclaw-search"].config.baseUrl')"
            detected_searxng_port="$(extract_port_from_url "$detected_searxng_url")"
            if is_valid_port "$detected_searxng_port"; then
                SEARXNG_BIND_PORT="$detected_searxng_port"
            fi
        fi
    fi

    if ! is_valid_port "${SEARXNG_BIND_PORT:-}"; then
        detected_searxng_port="$(detect_searxng_port_from_docker || true)"
        if is_valid_port "$detected_searxng_port"; then
            SEARXNG_BIND_PORT="$detected_searxng_port"
        fi
    fi

    detected_domain="$(detect_caddy_domain_from_caddyfile || true)"
    if [ -n "$detected_domain" ]; then
        OPENCLAW_DOMAIN="$detected_domain"
    fi
}

detect_openclaw_service_name() {
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "openclaw-gateway.service"; then
        echo "openclaw-gateway.service"
        return 0
    fi

    systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -i '^openclaw.*\.service$' | head -n1 || true
}

detect_searxng_port_from_docker() {
    local port
    if ! command_exists docker; then
        return
    fi

    port="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -i 'searx' | sed -nE 's/.*127\.0\.0\.1:([0-9]+)->8080\/tcp.*/\1/p' | head -n1)"
    if is_valid_port "$port"; then
        echo "$port"
        return
    fi

    port="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -i 'searx' | sed -nE 's/.*0\.0\.0\.0:([0-9]+)->8080\/tcp.*/\1/p' | head -n1)"
    if is_valid_port "$port"; then
        echo "$port"
    fi
}

list_existing_searxng_containers() {
    if ! command_exists docker; then
        return
    fi

    docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null | awk '
        BEGIN { IGNORECASE = 1 }
        $1 ~ /searx/ || $2 ~ /searx/ { print }
    '
}

port_is_in_use() {
    local port="$1"
    if ! is_valid_port "$port"; then
        return 1
    fi
    ss -ltn "( sport = :${port} )" 2>/dev/null | awk 'NR > 1 { found = 1 } END { exit found ? 0 : 1 }'
}

suggest_fresh_searxng_port() {
    local candidate
    for candidate in 8888 8787 8381 8081 18080; do
        if ! port_is_in_use "$candidate"; then
            echo "$candidate"
            return
        fi
    done
    echo "8888"
}

backup_existing_searxng_metadata() {
    local backup_dir="$1"
    local container
    local image
    local ports

    if ! command_exists docker; then
        return 0
    fi

    list_existing_searxng_containers > "${backup_dir}/searxng-containers.txt" 2>/dev/null || true

    while IFS=$'\t' read -r container image ports; do
        [ -n "$container" ] || continue
        docker inspect "$container" > "${backup_dir}/searxng-${container}.inspect.json" 2>/dev/null || true
        docker logs --tail 200 "$container" > "${backup_dir}/searxng-${container}.log" 2>&1 || true
    done < <(list_existing_searxng_containers || true)
}

cleanup_existing_searxng_containers() {
    local container
    local image
    local ports
    local found="n"

    if ! command_exists docker; then
        log_warn "未安装 Docker，无法自动清理旧 SearXNG 容器"
        return 0
    fi

    while IFS=$'\t' read -r container image ports; do
        [ -n "$container" ] || continue
        found="y"
        log_info "正在清理旧 SearXNG 容器：${container}（${image}）"
        docker rm -f "$container" >/dev/null
    done < <(list_existing_searxng_containers || true)

    if [ "$found" = "n" ]; then
        log_info "未检测到需要清理的 SearXNG Docker 容器"
    fi
}

ensure_searxng_target_port_available() {
    if port_is_in_use "$SEARXNG_BIND_PORT"; then
        log_error "目标 SearXNG 端口 ${SEARXNG_BIND_PORT} 已被占用，请更换端口或先清理旧实例"
        return 1
    fi
}

backup_file_with_timestamp() {
    local source="$1"
    local backup_dir="$2"
    if [ -f "$source" ]; then
        cp "$source" "${backup_dir}/$(basename "$source")"
    fi
}

install_openclaw_search_plugin() {
    local tmp_root
    local plugin_dir

    tmp_root="$(mktemp -d /tmp/openclaw-search.XXXXXX)"
    plugin_dir="${tmp_root}/openclaw-search"

    git clone --depth 1 "$OPENCLAW_SEARCH_PLUGIN_REPO" "$plugin_dir" >/dev/null 2>&1

    run_as_user "$OPENCLAW_USER" "openclaw plugins uninstall openclaw-search >/dev/null 2>&1 || true"
    run_as_user "$OPENCLAW_USER" "openclaw plugins install \"$plugin_dir\""
    run_as_user "$OPENCLAW_USER" "openclaw plugins enable openclaw-search" || true

    rm -rf "$tmp_root"
}

run_as_user() {
    local user="$1"
    shift
    local user_home
    user_home="$(get_user_home "$user")"
    if [ -z "$user_home" ]; then
        log_error "无法找到用户 $user 的家目录"
        return 1
    fi
    su - "$user" -c "export PATH=\"$user_home/.openclaw/bin:/usr/local/bin:/usr/bin:/bin:\$PATH\"; $*"
}

random_hex() {
    openssl rand -hex "$1"
}

ensure_dir() {
    install -d -m "$1" "$2"
}

primary_ipv4() {
    hostname -I | awk '{print $1}'
}

collect_username() {
    local detected_user
    local input_user
    local previous_username

    detected_user="$(detect_admin_user || true)"
    if [ -z "${USERNAME:-}" ] && [ -n "$detected_user" ] && is_valid_username "$detected_user"; then
        USERNAME="$detected_user"
    fi

    while true; do
        previous_username="${USERNAME:-}"
        if [ -n "${USERNAME:-}" ]; then
            read -r -p "用户名（默认 ${USERNAME}）: " input_user
            if [ -n "$input_user" ]; then
                USERNAME="$input_user"
            fi
        else
            read -r -p "用户名: " USERNAME
        fi

        if [ "$USERNAME" != "$previous_username" ]; then
            USER_PASSWORD=""
        fi

        if is_valid_username "$USERNAME"; then
            return
        fi
        log_error "用户名无效"
    done
}

collect_password() {
    local pw1
    local pw2
    local reset_confirm

    if [ -n "${USER_PASSWORD:-}" ]; then
        return
    fi

    if [ -n "${USERNAME:-}" ] && id "$USERNAME" >/dev/null 2>&1; then
        read -r -p "用户 $USERNAME 已存在，是否重置密码？(y/N): " reset_confirm
        if ! confirm_default_no "$reset_confirm"; then
            log_info "跳过密码更新"
            return
        fi
    fi

    while true; do
        read -s -p "为 $USERNAME 设置密码: " pw1
        echo ""
        read -s -p "确认密码: " pw2
        echo ""
        if [ "$pw1" = "$pw2" ] && [ -n "$pw1" ]; then
            USER_PASSWORD="$pw1"
            return
        fi
        log_error "两次输入的密码不一致"
    done
}

collect_ssh_port() {
    local input_port
    local detected_port

    detected_port="$(detect_sshd_port_runtime)"
    if ! is_valid_port "${SSH_PORT:-}"; then
        SSH_PORT="$detected_port"
    fi

    while true; do
        read -r -p "SSH 端口（回车保持 ${SSH_PORT}，输入 0 表示 22，推荐 ${DEFAULT_NEW_SSH_PORT}）: " input_port
        if [ -z "$input_port" ]; then
            SSH_PORT="$(effective_ssh_port)"
            return
        fi
        if [ "$input_port" = "0" ]; then
            SSH_PORT="22"
            return
        fi
        if is_valid_port "$input_port"; then
            SSH_PORT="$input_port"
            return
        fi
        log_error "端口必须是 1-65535 之间的整数"
    done
}

collect_hostname() {
    local input_host
    while true; do
        read -r -p "主机名（回车保持 ${NEW_HOSTNAME}，输入 0 跳过）: " input_host
        if [ -z "$input_host" ]; then
            return
        fi
        if [ "$input_host" = "0" ]; then
            NEW_HOSTNAME="0"
            return
        fi
        if is_valid_hostname "$input_host"; then
            NEW_HOSTNAME="$input_host"
            return
        fi
        log_error "主机名无效"
    done
}

collect_swap() {
    local input_swap
    while true; do
        read -r -p "交换分区大小（回车保持 ${SWAP_SIZE}，输入 0 跳过）: " input_swap
        if [ -z "$input_swap" ]; then
            return
        fi
        if [ "$input_swap" = "0" ]; then
            SWAP_SIZE="0"
            return
        fi
        if is_valid_swap_size "$input_swap"; then
            SWAP_SIZE="$input_swap"
            return
        fi
        log_error "交换分区大小格式无效"
    done
}

collect_ssh_key() {
    if [ -n "${SSH_KEY:-}" ]; then
        return
    fi

    echo -e "\n${BLUE}请粘贴 SSH 公钥，或直接回车跳过${NC}"
    read -r -p "> " SSH_KEY

    if [ -n "$SSH_KEY" ] && [[ ! "$SSH_KEY" =~ ^ssh-(ed25519|rsa)[[:space:]]+ ]]; then
        log_error "SSH 公钥格式无效"
        SSH_KEY=""
    fi
}

collect_full_info() {
    local current_user
    local current_port
    local current_host

    USER_PASSWORD=""
    hydrate_runtime_defaults
    current_user="${USERNAME:-未检测到}"
    current_port="$(detect_sshd_port_runtime)"
    current_host="$(hostnamectl --static 2>/dev/null || hostname)"

    title "VPS 基础初始化"
    echo "当前环境："
    echo "  用户: $current_user"
    echo "  SSH 端口: $current_port"
    echo "  主机名: $current_host"
    echo ""

    collect_username
    collect_password
    collect_ssh_port
    collect_hostname
    collect_swap
    collect_ssh_key

    echo ""
    echo "执行计划："
    echo "  用户名: $USERNAME"
    echo "  SSH 端口: $SSH_PORT"
    echo "  主机名: $NEW_HOSTNAME"
    echo "  交换分区: $SWAP_SIZE"
    echo "  SSH 公钥: $([ -n "$SSH_KEY" ] && echo 已配置 || echo 已跳过)"
    echo ""
    read -r -p "确认执行？(y/N): " confirm
    confirm_default_no "$confirm"
}

step_upgrade() {
    log_step "系统更新与基础软件"
    apt-get update
    apt-get upgrade -y
    apt-get install -y sudo curl wget vim htop jq git net-tools ca-certificates gnupg lsb-release apt-transport-https unzip
}

step_hostname() {
    if [ "$NEW_HOSTNAME" = "0" ]; then
        log_warn "跳过主机名设置"
        return
    fi
    if ! is_valid_hostname "$NEW_HOSTNAME"; then
        log_error "主机名无效：$NEW_HOSTNAME"
        return 1
    fi

    log_step "设置主机名为 $NEW_HOSTNAME"
    hostnamectl set-hostname "$NEW_HOSTNAME"

    local tmp_hosts
    tmp_hosts="$(mktemp)"
    grep -v -w -F -- "$NEW_HOSTNAME" /etc/hosts > "$tmp_hosts" || true
    if ! grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+localhost([[:space:]]|$)' "$tmp_hosts"; then
        echo "127.0.0.1 localhost" >> "$tmp_hosts"
    fi
    echo "127.0.0.1 $NEW_HOSTNAME" >> "$tmp_hosts"
    echo "::1 $NEW_HOSTNAME" >> "$tmp_hosts"
    mv "$tmp_hosts" /etc/hosts

    timedatectl set-timezone Asia/Shanghai || true
    log_info "主机名和时区已更新"
}

step_user() {
    log_step "配置用户：$USERNAME"

    if id "$USERNAME" >/dev/null 2>&1; then
        if [ -n "${USER_PASSWORD:-}" ]; then
            echo "$USERNAME:$USER_PASSWORD" | chpasswd
            log_info "已更新 $USERNAME 的密码"
        else
            log_info "用户已存在，跳过密码更新"
        fi
    else
        if [ -z "${USER_PASSWORD:-}" ]; then
            log_error "新建用户必须设置密码"
            return 1
        fi
        useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$USER_PASSWORD" | chpasswd
        log_info "用户 $USERNAME 已创建"
    fi

    usermod -aG sudo "$USERNAME"
    echo "$USERNAME ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/90-$USERNAME"
    chmod 440 "/etc/sudoers.d/90-$USERNAME"
    visudo -cf "/etc/sudoers.d/90-$USERNAME" >/dev/null
    log_info "用户 $USERNAME 已加入 sudo 组"
}

step_ssh() {
    log_step "SSH 安全加固"

    local conf="/etc/ssh/sshd_config"
    local backup="${conf}.bak"
    local ssh_port
    local user_home
    local target_user

    [ ! -f "$backup" ] && cp "$conf" "$backup"
    ssh_port="$(effective_ssh_port)"
    if ! is_valid_port "$ssh_port"; then
        log_error "SSH 端口无效：$ssh_port"
        return 1
    fi
    SSH_PORT="$ssh_port"

    if [ -n "$SSH_KEY" ]; then
        for target_user in "root" "$USERNAME"; do
            if ! id "$target_user" >/dev/null 2>&1; then
                continue
            fi
            user_home="$(get_user_home "$target_user")"
            mkdir -p "$user_home/.ssh"
            touch "$user_home/.ssh/authorized_keys"
            if ! grep -Fxq -- "$SSH_KEY" "$user_home/.ssh/authorized_keys"; then
                printf '%s\n' "$SSH_KEY" >> "$user_home/.ssh/authorized_keys"
            fi
            chmod 700 "$user_home/.ssh"
            chmod 600 "$user_home/.ssh/authorized_keys"
            chown -R "$target_user:$target_user" "$user_home/.ssh"
        done
        log_info "SSH 公钥已部署"
    fi

    set_sshd_option "Port" "$ssh_port" "$conf"
    set_sshd_option "PubkeyAuthentication" "yes" "$conf"
    set_sshd_option "PermitRootLogin" "prohibit-password" "$conf"
    set_sshd_option "PasswordAuthentication" "yes" "$conf"
    set_sshd_option "PermitEmptyPasswords" "no" "$conf"
    set_sshd_option "UsePAM" "yes" "$conf"
    set_sshd_option "ChallengeResponseAuthentication" "no" "$conf"
    set_sshd_option "KbdInteractiveAuthentication" "no" "$conf"

    if sshd -t; then
        restart_ssh_service
        log_info "SSH 服务已重启"
    else
        cp "$backup" "$conf"
        restart_ssh_service || true
        log_error "SSH 配置无效，已恢复备份"
        return 1
    fi

    if [ "$ssh_port" != "22" ]; then
        echo -e "${YELLOW}请记得在云平台安全组或防火墙放行 TCP/${ssh_port}${NC}"
        echo -e "${GREEN}请在新终端测试：ssh -p ${ssh_port} ${USERNAME}@$(primary_ipv4)${NC}"
    fi
}

step_performance() {
    log_step "性能优化"

    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        grep -q '^net.core.default_qdisc=fq$' /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        grep -q '^net.ipv4.tcp_congestion_control=bbr$' /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
        log_info "BBR 已启用"
    else
        log_info "BBR 已处于启用状态"
    fi

    if [ "$SWAP_SIZE" = "0" ]; then
        log_warn "跳过 Swap 配置"
        return
    fi

    if [ ! -f /swapfile ]; then
        if fallocate -l "$SWAP_SIZE" /swapfile 2>/dev/null; then
            :
        elif truncate -s "$SWAP_SIZE" /swapfile 2>/dev/null; then
            :
        else
            dd if=/dev/zero of=/swapfile bs="$SWAP_SIZE" count=1 status=none
        fi
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
        log_info "Swap 已配置完成"
    else
        log_info "Swap 文件已存在"
    fi

    free -h
}

step_docker() {
    log_step "安装 Docker"

    if ! command_exists docker; then
        curl -fsSL https://get.docker.com | bash
    fi

    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

    systemctl daemon-reload
    systemctl restart docker
    systemctl enable docker

    if [ -n "${USERNAME:-}" ] && id "$USERNAME" >/dev/null 2>&1; then
        usermod -aG docker "$USERNAME"
    fi

    log_info "Docker 已就绪"
}

prepare_openclaw_host() {
    log_step "为 OpenClaw 整栈准备宿主机"

    apt-get update
    apt-get install -y curl wget jq git ca-certificates net-tools

    if ! command_exists docker; then
        step_docker
    else
        systemctl enable docker >/dev/null 2>&1 || true
        systemctl restart docker >/dev/null 2>&1 || true
    fi

    if command_exists ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1 || true
        ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1 || true
    fi
}

step_firewall() {
    log_step "配置 UFW 防火墙"

    ensure_package ufw
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    local ssh_port
    ssh_port="$(detect_sshd_port_runtime)"
    if ! is_valid_port "$ssh_port"; then
        log_error "无法识别当前 SSH 端口"
        return 1
    fi

    ufw allow "$ssh_port"/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    echo "y" | ufw enable
    ufw status numbered
}

step_fail2ban() {
    log_step "配置 Fail2Ban"

    local ssh_port
    local jail_file="/etc/fail2ban/jail.local"
    ssh_port="$(detect_sshd_port_runtime)"

    if ! is_valid_port "$ssh_port"; then
        log_error "无法识别当前 SSH 端口"
        return 1
    fi

    apt-get install -y fail2ban python3-systemd >/dev/null 2>&1 || apt-get install -y fail2ban

    cat > "$jail_file" <<EOF
# Managed by vps-unified-init.sh
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
allowipv6 = auto

[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
backend = systemd
logpath = %(systemd_journal)s
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd
maxretry = 3
bantime = 7200
EOF

    fail2ban-client -t >/dev/null
    systemctl restart fail2ban
    systemctl enable fail2ban >/dev/null 2>&1 || true
    fail2ban-client status sshd || true
}

test_config() {
    local report_user
    local report_port

    report_user="$(detect_admin_user || true)"
    report_port="$(detect_sshd_port_runtime)"

    title "当前系统状态"
    echo "主机名："
    hostname
    echo ""
    echo "时区："
    timedatectl | grep "Time zone" || true
    echo ""
    echo "SSH 端口: $report_port"
    grep "^Port" /etc/ssh/sshd_config || true
    grep "^PermitRootLogin" /etc/ssh/sshd_config || true
    grep "^PasswordAuthentication" /etc/ssh/sshd_config || true
    echo ""
    echo "BBR："
    sysctl net.ipv4.tcp_congestion_control || true
    echo ""
    echo "交换分区："
    free -h | grep Swap || true
    echo ""
    echo "Docker："
    docker --version 2>/dev/null || echo "未安装"
    echo ""
    echo "UFW："
    ufw status 2>/dev/null || echo "未安装"
    echo ""
    echo "Fail2Ban："
    systemctl status fail2ban --no-pager -l 2>/dev/null | grep Active || echo "未安装"
    echo ""
    if [ -n "$report_user" ]; then
        echo "检测到的管理用户: $report_user"
    fi
}

view_ssh_config() {
    title "当前 SSH 状态"
    sshd -T | grep -E "^(port|passwordauthentication|permitrootlogin|pubkeyauthentication)" || true
    echo ""
    echo "已授权公钥："
    if [ -f /root/.ssh/authorized_keys ]; then
        grep "^ssh-" /root/.ssh/authorized_keys || true
    else
        echo "未找到 /root/.ssh/authorized_keys"
    fi
    echo ""
    echo "当前会话："
    who || true
}

enable_password_login() {
    title "开启 SSH 密码登录"
    local current_status
    local backup_file

    current_status="$(sshd -T | awk '/^passwordauthentication /{print $2}')"
    if [ "$current_status" = "yes" ]; then
        log_warn "密码认证已经处于开启状态"
        return
    fi

    read -r -p "现在开启密码登录吗？(y/N): " confirm
    answer_is_yes "$confirm" || return

    backup_file="/etc/ssh/sshd_config.backup.$(date +%s)"
    cp /etc/ssh/sshd_config "$backup_file"
    set_sshd_option "PasswordAuthentication" "yes" /etc/ssh/sshd_config

    if sshd -t; then
        reload_ssh_service
        log_info "密码登录已开启"
        echo "备份文件: $backup_file"
    else
        cp "$backup_file" /etc/ssh/sshd_config
        reload_ssh_service || true
        log_error "配置校验失败，已恢复备份"
    fi
}

disable_password_login() {
    title "关闭 SSH 密码登录"
    local current_status
    local backup_file

    current_status="$(sshd -T | awk '/^passwordauthentication /{print $2}')"
    if [ "$current_status" = "no" ]; then
        log_warn "密码认证已经处于关闭状态"
        return
    fi

    if [ ! -s /root/.ssh/authorized_keys ]; then
        log_error "未找到 root 的 authorized_keys，拒绝关闭密码登录"
        return
    fi

    read -r -p "现在关闭密码登录吗？(y/N): " confirm
    answer_is_yes "$confirm" || return

    backup_file="/etc/ssh/sshd_config.backup.$(date +%s)"
    cp /etc/ssh/sshd_config "$backup_file"
    set_sshd_option "PasswordAuthentication" "no" /etc/ssh/sshd_config

    if sshd -t; then
        reload_ssh_service
        log_info "密码登录已关闭"
        echo "备份文件: $backup_file"
    else
        cp "$backup_file" /etc/ssh/sshd_config
        reload_ssh_service || true
        log_error "配置校验失败，已恢复备份"
    fi
}

set_root_password() {
    title "设置 root 密码"
    passwd root
}

generate_new_keypair() {
    title "生成新的 SSH 密钥对"
    local keyname
    local tmpdir

    read -r -p "密钥名称（默认 rescue_$(date +%Y%m%d)）: " keyname
    if [ -z "$keyname" ]; then
        keyname="rescue_$(date +%Y%m%d)"
    fi

    tmpdir="/tmp/ssh_keys_$$"
    mkdir -p "$tmpdir"
    ssh-keygen -t ed25519 -f "$tmpdir/$keyname" -N "" -C "rescue_key_$(date +%Y%m%d)" >/dev/null

    echo ""
    echo "私钥内容："
    cat "$tmpdir/$keyname"
    echo ""

    read -r -p "是否将公钥追加到 /root/.ssh/authorized_keys？(y/N): " add_key
    if answer_is_yes "$add_key"; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        cat "$tmpdir/$keyname.pub" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        log_info "公钥已追加"
    fi

    rm -rf "$tmpdir"
}

ssh_rescue_menu() {
    local choice
    while true; do
        title "SSH 紧急救援工具"
        echo "1) 查看 SSH 配置"
        echo "2) 开启密码登录"
        echo "3) 设置 root 密码"
        echo "4) 生成新的 SSH 密钥对"
        echo "5) 关闭密码登录"
        echo "0) 返回上级菜单"
        echo ""
        read -r -p "请选择 [0-5]: " choice
        case "$choice" in
            1) view_ssh_config ;;
            2) enable_password_login ;;
            3) set_root_password ;;
            4) generate_new_keypair ;;
            5) disable_password_login ;;
            0) return ;;
            *) log_error "无效选项" ;;
        esac
        echo ""
        read -r -p "按回车继续..."
    done
}

collect_openclaw_stack_info() {
    local detected_user
    local input

    detected_user="${OPENCLAW_USER:-}"
    if [ -z "$detected_user" ]; then
        if [ -n "${USERNAME:-}" ] && id "$USERNAME" >/dev/null 2>&1; then
            detected_user="$USERNAME"
        else
            detected_user="$(detect_admin_user || true)"
        fi
    fi

    if [ -z "$detected_user" ]; then
        log_error "未检测到合适的用户，请先创建用户"
        return 1
    fi

    read -r -p "OpenClaw 运行用户（默认 ${detected_user}）: " input
    OPENCLAW_USER="${input:-$detected_user}"
    if ! id "$OPENCLAW_USER" >/dev/null 2>&1; then
        log_error "用户 $OPENCLAW_USER 不存在"
        return 1
    fi

    while true; do
        read -r -p "OpenClaw 公网域名（必填）: " input
        if [ -n "$input" ]; then
            OPENCLAW_DOMAIN="$input"
            break
        fi
        log_error "域名不能为空"
    done

    read -r -p "Caddy ACME 邮箱（可选）: " input
    OPENCLAW_ACME_EMAIL="$input"

    read -r -p "OpenClaw 网关端口（默认 ${OPENCLAW_GATEWAY_PORT}）: " input
    if [ -n "$input" ]; then
        if ! is_valid_port "$input"; then
            log_error "OpenClaw 端口无效"
            return 1
        fi
        OPENCLAW_GATEWAY_PORT="$input"
    fi

    read -r -p "OpenClaw 控制界面基础路径（默认 ${OPENCLAW_CONTROL_PATH}）: " input
    if [ -n "$input" ]; then
        OPENCLAW_CONTROL_PATH="$input"
    fi

    read -r -p "SearXNG 回环端口（默认 ${SEARXNG_BIND_PORT}）: " input
    if [ -n "$input" ]; then
        if ! is_valid_port "$input"; then
            log_error "SearXNG 端口无效"
            return 1
        fi
        SEARXNG_BIND_PORT="$input"
    fi

    read -r -p "SearXNG 语言（默认 ${SEARXNG_LANGUAGE}）: " input
    if [ -n "$input" ]; then
        SEARXNG_LANGUAGE="$input"
    fi

    read -r -p "是否启用仅允许 Cloudflare 回源的 80/443 收口？(y/N): " input
    if confirm_default_no "$input"; then
        USE_CLOUDFLARE_LOCKDOWN="y"
    else
        USE_CLOUDFLARE_LOCKDOWN="n"
    fi

    title "OpenClaw 整栈部署计划"
    echo "运行用户: $OPENCLAW_USER"
    echo "公网域名: $OPENCLAW_DOMAIN"
    echo "网关端口: $OPENCLAW_GATEWAY_PORT"
    echo "控制界面路径: $OPENCLAW_CONTROL_PATH"
    echo "SearXNG 端口: $SEARXNG_BIND_PORT"
    echo "SearXNG 语言: $SEARXNG_LANGUAGE"
    echo "仅允许 Cloudflare 回源: $(yn_to_label "$USE_CLOUDFLARE_LOCKDOWN")"
    echo ""
    read -r -p "确认开始部署？(y/N): " input
    confirm_default_no "$input"
}

collect_openclaw_migration_info() {
    local detected_user
    local input
    local existing_gateway_port
    local existing_base_path
    local existing_searxng_url
    local existing_searxng_port
    local existing_service
    local existing_searxng_containers
    local suggested_new_port

    detected_user="$(detect_openclaw_user || true)"
    if [ -z "$detected_user" ]; then
        log_error "未检测到已安装的 OpenClaw。现有部署请使用全新部署模式，或先确认 OpenClaw 已安装。"
        return 1
    fi

    read -r -p "OpenClaw 运行用户（默认 ${detected_user}）: " input
    OPENCLAW_USER="${input:-$detected_user}"
    if ! id "$OPENCLAW_USER" >/dev/null 2>&1; then
        log_error "用户 $OPENCLAW_USER 不存在"
        return 1
    fi

    OPENCLAW_CONFIG_PATH="$(detect_openclaw_config_path "$OPENCLAW_USER")"
    existing_gateway_port="$(json_get_file "$OPENCLAW_CONFIG_PATH" '.gateway.port')"
    if is_valid_port "$existing_gateway_port"; then
        OPENCLAW_GATEWAY_PORT="$existing_gateway_port"
    fi

    existing_base_path="$(json_get_file "$OPENCLAW_CONFIG_PATH" '.gateway.controlUi.basePath')"
    if [ -n "$existing_base_path" ]; then
        OPENCLAW_CONTROL_PATH="$existing_base_path"
    fi

    existing_searxng_url="$(json_get_file "$OPENCLAW_CONFIG_PATH" '.plugins.entries["openclaw-search"].config.baseUrl')"
    existing_searxng_port="$(extract_port_from_url "$existing_searxng_url")"
    if ! probe_searxng_json_api "$existing_searxng_port"; then
        existing_searxng_port="$(detect_searxng_port_from_docker || true)"
    fi
    if is_valid_port "$existing_searxng_port"; then
        OPENCLAW_EXISTING_SEARXNG_PORT="$existing_searxng_port"
        SEARXNG_BIND_PORT="$existing_searxng_port"
    else
        OPENCLAW_EXISTING_SEARXNG_PORT=""
    fi

    OPENCLAW_CLEANUP_EXISTING_SEARXNG="n"

    existing_service="$(detect_openclaw_service_name || true)"
    OPENCLAW_EXISTING_SERVICE="${existing_service:-}"

    while true; do
        read -r -p "OpenClaw 公网域名（必填）: " input
        if [ -n "$input" ]; then
            OPENCLAW_DOMAIN="$input"
            break
        fi
        log_error "域名不能为空"
    done

    read -r -p "Caddy ACME 邮箱（可选）: " input
    OPENCLAW_ACME_EMAIL="$input"

    read -r -p "OpenClaw 当前网关端口（默认 ${OPENCLAW_GATEWAY_PORT}）: " input
    if [ -n "$input" ]; then
        if ! is_valid_port "$input"; then
            log_error "OpenClaw 端口无效"
            return 1
        fi
        OPENCLAW_GATEWAY_PORT="$input"
    fi

    if is_valid_port "${SEARXNG_BIND_PORT:-}"; then
        read -r -p "检测到现有 SearXNG 端口 ${SEARXNG_BIND_PORT}，是否直接复用？(Y/n): " input
        if answer_is_no "$input"; then
            OPENCLAW_REUSE_EXISTING_SEARXNG="n"
        else
            OPENCLAW_REUSE_EXISTING_SEARXNG="y"
        fi
    else
        read -r -p "未自动检测到现有 SearXNG。是否手动填写一个已有实例的回环端口并复用？(y/N): " input
        if confirm_default_no "$input"; then
            OPENCLAW_REUSE_EXISTING_SEARXNG="y"
        else
            OPENCLAW_REUSE_EXISTING_SEARXNG="n"
        fi
    fi

    if [ "$OPENCLAW_REUSE_EXISTING_SEARXNG" = "y" ]; then
        read -r -p "SearXNG 回环端口（默认 ${SEARXNG_BIND_PORT}）: " input
        if [ -n "$input" ]; then
            if ! is_valid_port "$input"; then
                log_error "SearXNG 端口无效"
                return 1
            fi
            SEARXNG_BIND_PORT="$input"
        fi
    else
        existing_searxng_containers="$(list_existing_searxng_containers || true)"
        if [ -n "$existing_searxng_containers" ]; then
            echo "检测到以下现有 SearXNG 容器："
            while IFS=$'\t' read -r container image ports; do
                [ -n "$container" ] || continue
                echo "  容器: ${container} | 镜像: ${image} | 端口: ${ports:-未映射}"
            done <<< "$existing_searxng_containers"
            read -r -p "部署新 SearXNG 前，是否先备份并清理这些旧容器？(Y/n): " input
            if confirm_default_yes "$input"; then
                OPENCLAW_CLEANUP_EXISTING_SEARXNG="y"
            fi
        fi

        if [ "$OPENCLAW_CLEANUP_EXISTING_SEARXNG" = "y" ] && is_valid_port "${OPENCLAW_EXISTING_SEARXNG_PORT:-}"; then
            SEARXNG_BIND_PORT="$OPENCLAW_EXISTING_SEARXNG_PORT"
        else
            suggested_new_port="$(suggest_fresh_searxng_port)"
            if [ -z "${SEARXNG_BIND_PORT:-}" ] || [ "${SEARXNG_BIND_PORT:-}" = "${OPENCLAW_EXISTING_SEARXNG_PORT:-}" ] || port_is_in_use "$SEARXNG_BIND_PORT"; then
                SEARXNG_BIND_PORT="$suggested_new_port"
            fi
        fi

        read -r -p "新的 SearXNG 回环端口（默认 ${SEARXNG_BIND_PORT}）: " input
        if [ -n "$input" ]; then
            if ! is_valid_port "$input"; then
                log_error "SearXNG 端口无效"
                return 1
            fi
            SEARXNG_BIND_PORT="$input"
        fi
    fi

    if [ -n "$OPENCLAW_EXISTING_SERVICE" ]; then
        read -r -p "检测到现有 OpenClaw 服务 ${OPENCLAW_EXISTING_SERVICE}，是否保持现有服务，不改为脚本接管？(Y/n): " input
        if answer_is_no "$input"; then
            OPENCLAW_TAKEOVER_EXISTING_SERVICE="y"
        else
            OPENCLAW_TAKEOVER_EXISTING_SERVICE="n"
        fi
    else
        read -r -p "未检测到现有 OpenClaw systemd 服务，是否由脚本写入并接管 openclaw-gateway.service？(y/N): " input
        if confirm_default_no "$input"; then
            OPENCLAW_TAKEOVER_EXISTING_SERVICE="y"
        else
            OPENCLAW_TAKEOVER_EXISTING_SERVICE="n"
        fi
    fi

    read -r -p "是否开启仅允许 Cloudflare 回源的 80/443 收口？(y/N): " input
    if confirm_default_no "$input"; then
        USE_CLOUDFLARE_LOCKDOWN="y"
    else
        USE_CLOUDFLARE_LOCKDOWN="n"
    fi

    title "OpenClaw 无缝迁移计划"
    echo "运行用户: $OPENCLAW_USER"
    echo "配置文件: $OPENCLAW_CONFIG_PATH"
    echo "公网域名: $OPENCLAW_DOMAIN"
    echo "当前网关端口: $OPENCLAW_GATEWAY_PORT"
    echo "现有服务: ${OPENCLAW_EXISTING_SERVICE:-未检测到}"
    echo "复用现有 SearXNG: $(yn_to_label "$OPENCLAW_REUSE_EXISTING_SEARXNG")"
    echo "清理现有 SearXNG: $(yn_to_label "$OPENCLAW_CLEANUP_EXISTING_SEARXNG")"
    echo "SearXNG 端口: $SEARXNG_BIND_PORT"
    echo "脚本接管 OpenClaw 服务: $(yn_to_label "$OPENCLAW_TAKEOVER_EXISTING_SERVICE")"
    echo "仅允许 Cloudflare 回源: $(yn_to_label "$USE_CLOUDFLARE_LOCKDOWN")"
    echo ""
    read -r -p "确认开始迁移？(y/N): " input
    confirm_default_no "$input"
}

ensure_openclaw_installed() {
    log_step "检查 OpenClaw 是否已安装"

    local user_home
    user_home="$(get_user_home "$OPENCLAW_USER")"

    if run_as_user "$OPENCLAW_USER" "command -v openclaw >/dev/null 2>&1 || [ -x \"$user_home/.openclaw/bin/openclaw\" ]"; then
        log_info "用户 $OPENCLAW_USER 的 OpenClaw 已安装"
        return
    fi

    apt-get install -y curl git jq ca-certificates
    log_info "准备为 $OPENCLAW_USER 安装 OpenClaw"
    run_as_user "$OPENCLAW_USER" "curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install-cli.sh | bash"
}

write_openclaw_gateway_service() {
    local user_home
    user_home="$(get_user_home "$OPENCLAW_USER")"

    cat > "$OPENCLAW_GATEWAY_SERVICE" <<EOF
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${OPENCLAW_USER}
WorkingDirectory=${user_home}
Environment=HOME=${user_home}
Environment=PATH=${user_home}/.openclaw/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/bin/bash -lc 'openclaw gateway'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openclaw-gateway >/dev/null
}

configure_openclaw_search_plugin() {
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.trustedProxies '[\"127.0.0.1\",\"::1\"]' --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set tools.web.search.enabled false --json" || true
    run_as_user "$OPENCLAW_USER" "openclaw config unset tools.web.search.apiKey" || true
    run_as_user "$OPENCLAW_USER" "openclaw config unset tools.web.search.provider" || true

    install_openclaw_search_plugin
    run_as_user "$OPENCLAW_USER" "openclaw config set plugins.entries.openclaw-search.enabled true --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set plugins.entries.openclaw-search.config.baseUrl \"http://127.0.0.1:${SEARXNG_BIND_PORT}\""
    run_as_user "$OPENCLAW_USER" "openclaw config set plugins.entries.openclaw-search.config.maxResults 10 --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set plugins.entries.openclaw-search.config.language \"${SEARXNG_LANGUAGE}\""
    run_as_user "$OPENCLAW_USER" "openclaw config set plugins.entries.openclaw-search.config.safesearch 0 --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set plugins.entries.openclaw-search.config.timeout 15 --json"
}

configure_openclaw_gateway() {
    log_step "配置 OpenClaw 网关与插件"

    ensure_dir 0700 "$OPENCLAW_SECRET_DIR"
    if [ ! -s "${OPENCLAW_SECRET_DIR}/gateway_token" ]; then
        random_hex 32 > "${OPENCLAW_SECRET_DIR}/gateway_token"
        chmod 0600 "${OPENCLAW_SECRET_DIR}/gateway_token"
    fi
    OPENCLAW_GATEWAY_TOKEN="$(cat "${OPENCLAW_SECRET_DIR}/gateway_token")"

    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.mode local"
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.port ${OPENCLAW_GATEWAY_PORT} --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.bind loopback"
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.controlUi.enabled true --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.controlUi.basePath \"${OPENCLAW_CONTROL_PATH}\""
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.auth.mode token"
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.auth.token \"${OPENCLAW_GATEWAY_TOKEN}\""
    configure_openclaw_search_plugin

    write_openclaw_gateway_service
    systemctl restart openclaw-gateway
    log_info "OpenClaw 网关已配置完成"
}

backup_existing_openclaw_state() {
    local user_home
    local backup_dir
    local service_path

    user_home="$(get_user_home "$OPENCLAW_USER")"
    backup_dir="${user_home}/.openclaw/backups/migration-$(date +%Y%m%d%H%M%S)"
    ensure_dir 0700 "$backup_dir"

    OPENCLAW_BACKUP_DIR="$backup_dir"
    backup_file_with_timestamp "$OPENCLAW_CONFIG_PATH" "$backup_dir"
    backup_existing_searxng_metadata "$backup_dir"

    if [ -n "${OPENCLAW_EXISTING_SERVICE:-}" ]; then
        service_path="/etc/systemd/system/${OPENCLAW_EXISTING_SERVICE}"
        if [ -f "$service_path" ]; then
            backup_file_with_timestamp "$service_path" "$backup_dir"
        fi
        service_path="/lib/systemd/system/${OPENCLAW_EXISTING_SERVICE}"
        if [ -f "$service_path" ]; then
            backup_file_with_timestamp "$service_path" "$backup_dir"
        fi
    fi

    docker ps --format '{{.Names}}\t{{.Ports}}' > "${backup_dir}/docker-ps.txt" 2>/dev/null || true
    ss -ltnp > "${backup_dir}/ss-ltnp.txt" 2>/dev/null || true

    cat > "${backup_dir}/migration-summary.txt" <<EOF
openclaw_user=${OPENCLAW_USER}
openclaw_config=${OPENCLAW_CONFIG_PATH}
openclaw_service=${OPENCLAW_EXISTING_SERVICE}
openclaw_gateway_port=${OPENCLAW_GATEWAY_PORT}
searxng_bind_port=${SEARXNG_BIND_PORT}
openclaw_domain=${OPENCLAW_DOMAIN}
reuse_existing_searxng=${OPENCLAW_REUSE_EXISTING_SEARXNG}
cleanup_existing_searxng=${OPENCLAW_CLEANUP_EXISTING_SEARXNG}
takeover_existing_service=${OPENCLAW_TAKEOVER_EXISTING_SERVICE}
EOF

    log_info "现有 OpenClaw 配置已备份到 ${backup_dir}"
}

restart_openclaw_gateway() {
    local user_home

    if [ "$OPENCLAW_TAKEOVER_EXISTING_SERVICE" = "y" ]; then
        write_openclaw_gateway_service
        systemctl restart openclaw-gateway
        OPENCLAW_EXISTING_SERVICE="openclaw-gateway.service"
        return
    fi

    if [ -n "${OPENCLAW_EXISTING_SERVICE:-}" ] && systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${OPENCLAW_EXISTING_SERVICE}"; then
        systemctl restart "${OPENCLAW_EXISTING_SERVICE}"
        return
    fi

    if ! run_as_user "$OPENCLAW_USER" "openclaw gateway restart" >/dev/null 2>&1; then
        user_home="$(get_user_home "$OPENCLAW_USER")"
        nohup su - "$OPENCLAW_USER" -c "export PATH=\"${user_home}/.openclaw/bin:/usr/local/bin:/usr/bin:/bin:\$PATH\"; openclaw gateway" >/dev/null 2>&1 &
    fi
    sleep 3
}

verify_existing_searxng() {
    if curl -fsS --max-time 10 "http://127.0.0.1:${SEARXNG_BIND_PORT}/search?q=test&format=json" >/dev/null; then
        log_info "已复用现有 SearXNG: 127.0.0.1:${SEARXNG_BIND_PORT}"
        return 0
    fi

    log_error "无法访问现有 SearXNG: 127.0.0.1:${SEARXNG_BIND_PORT}"
    return 1
}

ensure_caddy_ports_available_for_migration() {
    local occupier
    occupier="$(ss -ltnp '( sport = :80 or sport = :443 )' 2>/dev/null | awk 'NR>1{print $NF}' | tr '\n' ' ')"

    if [ -z "$occupier" ]; then
        return 0
    fi

    if printf '%s\n' "$occupier" | grep -q 'openclaw-caddy'; then
        return 0
    fi

    log_error "检测到 80/443 已被占用，迁移模式不会强行接管这些端口。当前监听: ${occupier}"
    return 1
}

migrate_existing_openclaw_stack() {
    log_step "无缝迁移现有 OpenClaw / SearXNG"

    prepare_openclaw_host
    ensure_openclaw_installed
    backup_existing_openclaw_state

    if [ "$OPENCLAW_REUSE_EXISTING_SEARXNG" = "y" ]; then
        verify_existing_searxng
    else
        if [ "$OPENCLAW_CLEANUP_EXISTING_SEARXNG" = "y" ]; then
            cleanup_existing_searxng_containers
        fi
        ensure_searxng_target_port_available
        deploy_searxng
    fi

    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.port ${OPENCLAW_GATEWAY_PORT} --json"
    run_as_user "$OPENCLAW_USER" "openclaw config set gateway.bind loopback"
    configure_openclaw_search_plugin
    restart_openclaw_gateway

    ensure_caddy_ports_available_for_migration
    deploy_caddy
    verify_openclaw_stack

    echo ""
    echo "迁移备份目录: ${OPENCLAW_BACKUP_DIR}"
}

do_cleanup_existing_searxng() {
    local detected_containers
    local backup_root
    local backup_dir
    local input
    local container
    local image
    local ports

    detected_containers="$(list_existing_searxng_containers || true)"
    if [ -z "$detected_containers" ]; then
        log_warn "未检测到现有 SearXNG Docker 容器"
        return
    fi

    title "检测到现有 SearXNG 容器"
    while IFS=$'\t' read -r container image ports; do
        [ -n "$container" ] || continue
        echo "容器: ${container}"
        echo "镜像: ${image}"
        echo "端口: ${ports:-未映射}"
        echo ""
    done <<< "$detected_containers"

    read -r -p "是否先备份元数据并清理这些旧 SearXNG 容器？(y/N): " input
    confirm_default_no "$input" || {
        log_warn "已取消"
        return
    }

    backup_root="/root/.vps-unified-init/backups"
    backup_dir="${backup_root}/searxng-cleanup-$(date +%Y%m%d%H%M%S)"
    ensure_dir 0700 "$backup_root"
    ensure_dir 0700 "$backup_dir"

    backup_existing_searxng_metadata "$backup_dir"
    cleanup_existing_searxng_containers

    echo ""
    echo "清理前备份目录: ${backup_dir}"
}

write_searxng_settings() {
    local secret_key
    ensure_dir 0755 "$SEARXNG_STACK_DIR"
    ensure_dir 0750 "$SEARXNG_DATA_DIR"
    ensure_dir 0700 "$SEARXNG_SECRET_DIR"

    if [ ! -s "${SEARXNG_SECRET_DIR}/secret_key" ]; then
        random_hex 32 > "${SEARXNG_SECRET_DIR}/secret_key"
        chmod 0600 "${SEARXNG_SECRET_DIR}/secret_key"
    fi
    secret_key="$(cat "${SEARXNG_SECRET_DIR}/secret_key")"

    cat > "${SEARXNG_SECRET_DIR}/settings.yml" <<EOF
use_default_settings: true
general:
  debug: false
  instance_name: "Private SearXNG for OpenClaw"
search:
  safe_search: 0
  formats:
    - html
    - json
server:
  secret_key: "${secret_key}"
  limiter: true
  image_proxy: true
  bind_address: "0.0.0.0"
EOF
    chmod 0600 "${SEARXNG_SECRET_DIR}/settings.yml"
}

deploy_searxng() {
    log_step "部署 SearXNG"

    write_searxng_settings
    cat > "${SEARXNG_STACK_DIR}/compose.yaml" <<EOF
services:
  searxng:
    image: ${SEARXNG_IMAGE}
    container_name: ${SEARXNG_CONTAINER_NAME}
    restart: unless-stopped
    ports:
      - "127.0.0.1:${SEARXNG_BIND_PORT}:8080"
    volumes:
      - ${SEARXNG_SECRET_DIR}/settings.yml:/etc/searxng/settings.yml:ro
EOF

    docker compose -f "${SEARXNG_STACK_DIR}/compose.yaml" up -d
    sleep 10
    if curl -fsS --max-time 10 "http://127.0.0.1:${SEARXNG_BIND_PORT}/search?q=test&format=json" >/dev/null; then
        log_info "SearXNG JSON API 已可访问"
    else
        log_warn "SearXNG 暂未就绪，稍后可用 curl http://127.0.0.1:${SEARXNG_BIND_PORT}/search?q=test\\&format=json 检查"
    fi
}

write_caddy_files() {
    local email_line=""

    ensure_dir 0755 "$CADDY_STACK_DIR"
    ensure_dir 0750 "${CADDY_DATA_DIR}/data"
    ensure_dir 0750 "${CADDY_DATA_DIR}/config"

    if [ -n "$OPENCLAW_ACME_EMAIL" ]; then
        email_line="	email ${OPENCLAW_ACME_EMAIL}"
    fi

    cat > "${CADDY_STACK_DIR}/Caddyfile" <<EOF
{
	admin off
${email_line}
}

${OPENCLAW_DOMAIN} {
	encode zstd gzip

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
		Referrer-Policy "strict-origin-when-cross-origin"
	}

	reverse_proxy 127.0.0.1:${OPENCLAW_GATEWAY_PORT} {
		header_up X-Forwarded-Host {host}
		header_up X-Forwarded-Proto {scheme}
		header_up X-Forwarded-For {remote_host}
	}
}
EOF

    cat > "${CADDY_STACK_DIR}/compose.yaml" <<EOF
services:
  caddy:
    image: ${CADDY_IMAGE}
    container_name: openclaw-caddy
    restart: unless-stopped
    network_mode: host
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - ${CADDY_STACK_DIR}/Caddyfile:/etc/caddy/Caddyfile:ro
      - ${CADDY_DATA_DIR}/data:/data
      - ${CADDY_DATA_DIR}/config:/config
EOF
}

write_cloudflare_origin_lockdown() {
    cat > "$OPENCLAW_LOCKDOWN_NFT" <<'EOF'
table inet openclaw_origin_lockdown {
	set cloudflare_ipv4 {
		type ipv4_addr
		flags interval
		elements = {
			173.245.48.0/20,
			103.21.244.0/22,
			103.22.200.0/22,
			103.31.4.0/22,
			141.101.64.0/18,
			108.162.192.0/18,
			190.93.240.0/20,
			188.114.96.0/20,
			197.234.240.0/22,
			198.41.128.0/17,
			162.158.0.0/15,
			104.16.0.0/13,
			104.24.0.0/14,
			172.64.0.0/13,
			131.0.72.0/22
		}
	}

	set cloudflare_ipv6 {
		type ipv6_addr
		flags interval
		elements = {
			2400:cb00::/32,
			2606:4700::/32,
			2803:f800::/32,
			2405:b500::/32,
			2405:8100::/32,
			2a06:98c0::/29,
			2c0f:f248::/32
		}
	}

	chain input {
		type filter hook input priority -1; policy accept;
		tcp dport { 80, 443 } ip saddr @cloudflare_ipv4 accept
		tcp dport { 80, 443 } ip6 saddr @cloudflare_ipv6 accept
		tcp dport { 80, 443 } drop
	}
}
EOF

    cat > "$OPENCLAW_LOCKDOWN_SCRIPT" <<EOF
#!/bin/bash
set -euo pipefail

nft -c -f "${OPENCLAW_LOCKDOWN_NFT}"
if nft list table inet openclaw_origin_lockdown >/dev/null 2>&1; then
    nft delete table inet openclaw_origin_lockdown
fi
nft -f "${OPENCLAW_LOCKDOWN_NFT}"
EOF
    chmod 0755 "$OPENCLAW_LOCKDOWN_SCRIPT"

    cat > "$OPENCLAW_LOCKDOWN_SERVICE" <<EOF
[Unit]
Description=Apply Cloudflare-only origin firewall for OpenClaw
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${OPENCLAW_LOCKDOWN_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openclaw-origin-lockdown >/dev/null
    systemctl restart openclaw-origin-lockdown
}

disable_cloudflare_origin_lockdown() {
    systemctl disable --now openclaw-origin-lockdown >/dev/null 2>&1 || true
    rm -f "$OPENCLAW_LOCKDOWN_SERVICE" "$OPENCLAW_LOCKDOWN_SCRIPT"
    if command_exists nft && nft list table inet openclaw_origin_lockdown >/dev/null 2>&1; then
        nft delete table inet openclaw_origin_lockdown
    fi
    systemctl daemon-reload
}

deploy_caddy() {
    log_step "部署 Caddy 反向代理"

    if ss -ltn sport = :80 | awk 'NR>1{print $4}' | grep -q ':'; then
        log_warn "检测到 TCP/80 已有监听，请确认这台 VPS 可以由 Caddy 接管"
    fi
    if ss -ltn sport = :443 | awk 'NR>1{print $4}' | grep -q ':'; then
        log_warn "检测到 TCP/443 已有监听，请确认这台 VPS 可以由 Caddy 接管"
    fi

    write_caddy_files
    docker compose -f "${CADDY_STACK_DIR}/compose.yaml" up -d

    if [ "$USE_CLOUDFLARE_LOCKDOWN" = "y" ]; then
        write_cloudflare_origin_lockdown
    else
        disable_cloudflare_origin_lockdown
    fi
}

deploy_openclaw_stack() {
    prepare_openclaw_host
    ensure_openclaw_installed
    deploy_searxng
    configure_openclaw_gateway
    deploy_caddy
    verify_openclaw_stack
}

verify_openclaw_stack() {
    log_step "验证 OpenClaw 整栈状态"

    hydrate_openclaw_runtime_context

    systemctl status --no-pager openclaw-gateway || true
    docker compose -f "${SEARXNG_STACK_DIR}/compose.yaml" ps || true
    docker compose -f "${CADDY_STACK_DIR}/compose.yaml" ps || true

    echo ""
    echo "检测结果："
    echo "OpenClaw 用户：${OPENCLAW_USER:-未检测到}"
    echo "OpenClaw 配置：${OPENCLAW_CONFIG_PATH:-未检测到}"
    echo "OpenClaw 网关端口：${OPENCLAW_GATEWAY_PORT:-未检测到}"
    echo "SearXNG 端口：${SEARXNG_BIND_PORT:-未检测到}"
    echo "公网域名：${OPENCLAW_DOMAIN:-未检测到}"
    echo ""
    echo "本地检查："
    if is_valid_port "${OPENCLAW_GATEWAY_PORT:-}"; then
        curl -fsSI "http://127.0.0.1:${OPENCLAW_GATEWAY_PORT}" || true
    else
        echo "OpenClaw 网关端口：未检测到"
    fi

    if is_valid_port "${SEARXNG_BIND_PORT:-}"; then
        curl -fsS --max-time 10 "http://127.0.0.1:${SEARXNG_BIND_PORT}/search?q=test&format=json" >/dev/null && echo "SearXNG JSON API：正常" || echo "SearXNG JSON API：待确认"
    else
        echo "SearXNG 端口：未检测到"
    fi

    echo ""
    echo "公网检查："
    if [ -n "${OPENCLAW_DOMAIN:-}" ]; then
        curl -fsSI "https://${OPENCLAW_DOMAIN}" || echo "公网 HTTPS 检查失败，请确认 DNS 已指向这台 VPS"
    else
        echo "公网域名：未检测到，跳过 HTTPS 检查"
    fi

    echo ""
    echo "OpenClaw 网关令牌已保存到：${OPENCLAW_SECRET_DIR}/gateway_token"
}

do_full_init() {
    local final_ssh_port
    local final_user

    if ! collect_full_info; then
        log_warn "已取消"
        return
    fi

    step_upgrade
    step_hostname
    step_user
    USER_PASSWORD=""
    step_ssh
    step_performance
    step_docker
    step_firewall
    step_fail2ban

    final_ssh_port="$(detect_sshd_port_runtime)"
    final_user="${USERNAME:-}"
    if [ -z "$final_user" ] || ! id "$final_user" >/dev/null 2>&1; then
        final_user="$(detect_admin_user || true)"
    fi
    [ -z "$final_user" ] && final_user="root"

    title "基础初始化已完成"
    echo "云平台安全组请放行：TCP/${final_ssh_port}"
    echo "请在新终端测试登录："
    echo "  ssh -p ${final_ssh_port} ${final_user}@$(primary_ipv4)"
    echo ""
    test_config
}

do_full_openclaw_vps() {
    if ! collect_full_info; then
        log_warn "已取消"
        return
    fi
    step_upgrade
    step_hostname
    step_user
    USER_PASSWORD=""
    step_ssh
    step_performance
    step_docker
    step_firewall
    step_fail2ban

    OPENCLAW_USER="$USERNAME"
    if ! collect_openclaw_stack_info; then
        log_warn "已取消"
        return
    fi
    ensure_openclaw_installed
    deploy_searxng
    configure_openclaw_gateway
    deploy_caddy
    verify_openclaw_stack
}

do_openclaw_seamless_migration() {
    if ! collect_openclaw_migration_info; then
        log_warn "已取消"
        return
    fi
    migrate_existing_openclaw_stack
}

show_menu() {
    local choice
    local cont
    local runtime_port
    local runtime_user

    while true; do
        hydrate_runtime_defaults
        runtime_port="$(detect_sshd_port_runtime)"
        runtime_user="${USERNAME:-未检测到}"

        title "VPS 统一初始化菜单"
        echo "当前检测: 用户 ${runtime_user} | SSH 端口 ${runtime_port}"
        echo ""
        echo "1) 一键基础初始化"
        echo "2) 一键基础初始化 + OpenClaw 整栈部署"
        echo "3) 系统更新与基础软件"
        echo "4) 创建或修改用户"
        echo "5) SSH 安全加固"
        echo "6) 性能优化"
        echo "7) 安装 Docker"
        echo "8) 配置 UFW 防火墙"
        echo "9) 配置 Fail2Ban"
        echo "10) 部署 OpenClaw + SearXNG + Caddy"
        echo "11) 无缝迁移现有 OpenClaw / SearXNG"
        echo "12) 验证 OpenClaw 整栈状态"
        echo "13) SSH 紧急救援工具"
        echo "14) 清理现有 SearXNG 容器"
        echo "t) 查看当前系统状态"
        echo "q) 退出"
        echo ""
        read -r -p "请选择: " choice

        case "$choice" in
            1)
                do_full_init
                ;;
            2)
                do_full_openclaw_vps
                ;;
            3)
                step_upgrade
                ;;
            4)
                USER_PASSWORD=""
                collect_username
                collect_password
                step_user
                USER_PASSWORD=""
                ;;
            5)
                if [ -z "${USERNAME:-}" ] || ! id "$USERNAME" >/dev/null 2>&1; then
                    USERNAME="$(detect_admin_user || true)"
                fi
                if [ -z "${USERNAME:-}" ]; then
                    log_warn "未检测到可用用户，请手动输入"
                    collect_username
                fi
                collect_ssh_port
                collect_ssh_key
                step_ssh
                ;;
            6)
                collect_swap
                step_performance
                ;;
            7)
                step_docker
                ;;
            8)
                runtime_port="$(detect_sshd_port_runtime)"
                read -r -p "检测到当前 SSH 端口为 ${runtime_port}，现在重建 UFW 规则吗？(y/N): " cont
                confirm_default_no "$cont" || continue
                step_firewall
                ;;
            9)
                runtime_port="$(detect_sshd_port_runtime)"
                read -r -p "检测到当前 SSH 端口为 ${runtime_port}，现在配置 Fail2Ban 吗？(y/N): " cont
                confirm_default_no "$cont" || continue
                step_fail2ban
                ;;
            10)
                if ! collect_openclaw_stack_info; then
                    log_warn "已取消"
                    continue
                fi
                deploy_openclaw_stack
                ;;
            11)
                do_openclaw_seamless_migration
                ;;
            12)
                verify_openclaw_stack
                ;;
            13)
                ssh_rescue_menu
                ;;
            14)
                do_cleanup_existing_searxng
                ;;
            t|T)
                test_config
                ;;
            q|Q)
                echo -e "${GREEN}已退出${NC}"
                exit 0
                ;;
            *)
                log_error "无效选项"
                ;;
        esac

        echo ""
        read -r -p "按回车返回菜单..."
    done
}

clear
echo -e "${BLUE}"
cat <<'EOF'
╔══════════════════════════════════════════════════════════════╗
║ VPS 统一初始化脚本                                           ║
║ 支持 Debian 10+ / Ubuntu 20.04+                             ║
║ 基础初始化 + SSH 救援 + OpenClaw/SearXNG/Caddy 部署         ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

hydrate_runtime_defaults
show_menu
