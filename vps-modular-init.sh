#!/bin/bash

# ====================================================
# VPS 模块化初始化脚本 v2.0 (Debian/Ubuntu)
# ====================================================

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 权限与环境检查 ---
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 请使用 root 用户或 sudo 运行此脚本！${NC}"
    exit 1
fi

if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}错误: 此脚本仅支持 Debian 或 Ubuntu 系统。${NC}"
    exit 1
fi

# 获取系统信息
OS_NAME=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')
DEFAULT_HOSTNAME="${OS_NAME}-vps"

# --- 全局变量 ---
USERNAME=""
USER_PASSWORD=""
SSH_PORT="22222"
NEW_HOSTNAME="$DEFAULT_HOSTNAME"
SWAP_SIZE="1G"
SSH_KEY=""

# --- 日志函数 ---
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}>>> $1${NC}\n"
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

effective_ssh_port() {
    if [ -z "${SSH_PORT:-}" ] || [ "${SSH_PORT:-}" = "0" ]; then
        echo "22"
    else
        echo "$SSH_PORT"
    fi
}

detect_sshd_port() {
    local detected_port
    detected_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
    if is_valid_port "$detected_port"; then
        echo "$detected_port"
    else
        effective_ssh_port
    fi
}

is_valid_hostname() {
    local host="$1"
    [[ "$host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

is_valid_swap_size() {
    local size="$1"
    [[ "$size" =~ ^[1-9][0-9]*[KMG]$ ]]
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

# --- 信息收集函数（模块化） ---
collect_username() {
    while true; do
        if [ -n "$USERNAME" ] && is_valid_username "$USERNAME"; then
            return
        fi
        read -r -p "输入新用户名: " USERNAME
        if is_valid_username "$USERNAME"; then
            return
        fi
        log_error "用户名无效。仅支持小写字母/数字/_/-，且不能是 root。"
    done
}

collect_password() {
    if [ -z "$USER_PASSWORD" ]; then
        while true; do
            read -s -p "设置 $USERNAME 的密码: " pw1
            echo ""
            read -s -p "确认密码: " pw2
            echo ""
            if [ "$pw1" = "$pw2" ] && [ -n "$pw1" ]; then
                USER_PASSWORD="$pw1"
                break
            fi
            log_error "密码不匹配或为空，请重新输入！"
        done
    fi
}

collect_ssh_port() {
    while true; do
        read -r -p "SSH 端口 (回车默认 $SSH_PORT, 输入 0 保持 22): " input_port
        if [ -z "$input_port" ]; then
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
        log_error "端口必须是 1-65535 的整数。"
    done
}

collect_hostname() {
    while true; do
        read -r -p "主机名 (回车默认 $NEW_HOSTNAME, 输入 0 跳过): " input_host
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
        log_error "主机名无效。仅支持字母、数字和中划线，且不能以中划线开头或结尾。"
    done
}

collect_swap() {
    while true; do
        read -r -p "Swap 大小 (回车默认 $SWAP_SIZE, 输入 0 跳过): " input_swap
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
        log_error "Swap 大小格式无效，请使用如 512M、1G、2G。"
    done
}

collect_ssh_key() {
    if [ -z "$SSH_KEY" ]; then
        echo -e "\n${BLUE}=== 配置 SSH 密钥登录 ===${NC}"
        echo -e "请在${RED}本地电脑${NC}运行以下命令获取公钥："
        echo -e "${GREEN}Windows PowerShell:${NC}  Get-Content \$HOME\\.ssh\\id_ed25519.pub"
        echo -e "${GREEN}Windows CMD:${NC}        type %USERPROFILE%\\.ssh\\id_ed25519.pub"
        echo -e "${GREEN}Mac/Linux:${NC}          cat ~/.ssh/id_ed25519.pub"
        echo -e "\n如果提示文件不存在，请先运行: ${YELLOW}ssh-keygen -t ed25519${NC}\n"
        
        read -r -p "粘贴公钥 (以 ssh-ed25519 或 ssh-rsa 开头，回车跳过): " SSH_KEY
        if [ -z "$SSH_KEY" ]; then
            log_warn "未配置 SSH 密钥，将使用密码登录"
        elif [[ ! "$SSH_KEY" =~ ^ssh-(ed25519|rsa)[[:space:]]+ ]]; then
            log_error "SSH 公钥格式无效，已跳过密钥配置"
            SSH_KEY=""
        fi
    fi
}

# 一键初始化的完整信息收集
collect_full_info() {
    echo -e "\n${CYAN}=== VPS 一键初始化配置向导 ===${NC}\n"
    
    collect_username
    collect_password
    collect_ssh_port
    collect_hostname
    collect_swap
    collect_ssh_key
    
    echo -e "\n${BLUE}=== 配置确认 ===${NC}"
    echo "用户名: $USERNAME"
    echo "SSH 端口: $SSH_PORT"
    echo "主机名: $NEW_HOSTNAME"
    echo "Swap: $SWAP_SIZE"
    echo "SSH 密钥: $([ -n "$SSH_KEY" ] && echo '已配置' || echo '未配置')"
    echo ""
    read -p "确认以上信息无误？(y/n): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_warn "已取消操作"
        return 1
    fi
    return 0
}

# --- 功能模块 ---

step_upgrade() {
    log_step "系统更新与基础软件安装"
    apt update && apt upgrade -y
    apt install -y sudo curl wget vim htop jq git net-tools
    log_info "基础环境配置完成"
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
    
    log_step "配置主机名: $NEW_HOSTNAME"
    hostnamectl set-hostname "$NEW_HOSTNAME"
    
    # 修复 /etc/hosts（使用固定字符串匹配，避免用户输入影响 sed 正则）
    local tmp_hosts
    tmp_hosts=$(mktemp)
    grep -v -w -F -- "$NEW_HOSTNAME" /etc/hosts > "$tmp_hosts" || true
    if ! grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+localhost([[:space:]]|$)' "$tmp_hosts"; then
        echo "127.0.0.1 localhost" >> "$tmp_hosts"
    fi
    echo "127.0.0.1 $NEW_HOSTNAME" >> "$tmp_hosts"
    echo "::1       $NEW_HOSTNAME" >> "$tmp_hosts"
    mv "$tmp_hosts" /etc/hosts
    
    # 设置时区
    timedatectl set-timezone Asia/Shanghai
    log_info "主机名已设为 $NEW_HOSTNAME，时区已设为 Asia/Shanghai"
}

step_user() {
    log_step "配置用户: $USERNAME"
    
    if id "$USERNAME" &>/dev/null; then
        log_warn "用户 $USERNAME 已存在，更新密码"
        echo "$USERNAME:$USER_PASSWORD" | chpasswd
    else
        useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$USER_PASSWORD" | chpasswd
        log_info "用户 $USERNAME 创建成功"
    fi
    
    # 配置 sudo 权限
    usermod -aG sudo "$USERNAME"
    local sudoers_file="/etc/sudoers.d/90-$USERNAME"
    echo "$USERNAME ALL=(ALL:ALL) ALL" > "$sudoers_file"
    chmod 440 "$sudoers_file"
    if ! visudo -cf "$sudoers_file" >/dev/null; then
        log_error "sudoers 配置校验失败，已删除 $sudoers_file"
        rm -f "$sudoers_file"
        return 1
    fi
    
    log_info "用户 $USERNAME 已加入 sudo 组（sudo 需输入密码）"
}

step_ssh() {
    log_step "SSH 安全加固配置"
    
    CONF="/etc/ssh/sshd_config"
    [ ! -f "${CONF}.bak" ] && cp "$CONF" "${CONF}.bak"
    local ssh_port
    ssh_port=$(effective_ssh_port)
    if ! is_valid_port "$ssh_port"; then
        log_error "SSH 端口无效：$ssh_port"
        return 1
    fi
    
    # 部署 SSH 密钥（如果提供）
    if [ -n "$SSH_KEY" ]; then
        for TARGET_USER in "root" "$USERNAME"; do
            USER_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
            if [ -z "$USER_HOME" ]; then
                log_warn "未找到用户目录，跳过 $TARGET_USER 的密钥部署"
                continue
            fi
            mkdir -p "$USER_HOME/.ssh"
            touch "$USER_HOME/.ssh/authorized_keys"
            if ! grep -Fxq -- "$SSH_KEY" "$USER_HOME/.ssh/authorized_keys"; then
                printf '%s\n' "$SSH_KEY" >> "$USER_HOME/.ssh/authorized_keys"
            fi
            chmod 700 "$USER_HOME/.ssh"
            chmod 600 "$USER_HOME/.ssh/authorized_keys"
            chown -R "$TARGET_USER:$TARGET_USER" "$USER_HOME/.ssh"
        done
        log_info "SSH 密钥已部署到 root 和 $USERNAME"
    fi
    
    # 修改 SSH 配置
    if [ "$ssh_port" != "22" ]; then
        set_sshd_option "Port" "$ssh_port" "$CONF"
        log_info "SSH 端口已改为 $ssh_port"
    else
        set_sshd_option "Port" "22" "$CONF"
        log_info "SSH 端口保持默认 22"
    fi
    
    # 启用密钥认证
    set_sshd_option "PubkeyAuthentication" "yes" "$CONF"
    
    # 关键配置：root 禁止密码登录，但允许密钥
    set_sshd_option "PermitRootLogin" "prohibit-password" "$CONF"
    
    # 确保新用户可以使用密码登录
    set_sshd_option "PasswordAuthentication" "yes" "$CONF"
    
    # 禁用空密码
    set_sshd_option "PermitEmptyPasswords" "no" "$CONF"
    
    # 启用 PAM（确保密码认证工作）
    set_sshd_option "UsePAM" "yes" "$CONF"
    
    # 禁用 ChallengeResponse（避免干扰密码登录）
    set_sshd_option "ChallengeResponseAuthentication" "no" "$CONF"
    set_sshd_option "KbdInteractiveAuthentication" "no" "$CONF"
    
    # 测试配置
    if sshd -t; then
        systemctl restart ssh
        log_info "SSH 配置已更新并重启"
        if [ "$ssh_port" != "22" ]; then
            echo -e "${YELLOW}============================================${NC}"
            echo -e "${YELLOW}重要提醒：${NC}"
            echo -e "1. 请立即在云平台安全组/防火墙放行端口: ${RED}$ssh_port (TCP)${NC}"
            echo -e "2. 在新终端测试登录: ${GREEN}ssh -p $ssh_port $USERNAME@你的IP${NC}"
            echo -e "3. 确认可以登录后再关闭当前窗口！"
            echo -e "${YELLOW}============================================${NC}"
        fi
    else
        log_error "SSH 配置有误，已恢复备份"
        cp "${CONF}.bak" "$CONF"
        systemctl restart ssh
    fi
}

step_performance() {
    log_step "系统性能优化 (BBR + Swap)"
    
    # BBR
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p > /dev/null 2>&1
        log_info "BBR 已启用"
    else
        log_info "BBR 已处于启用状态"
    fi
    
    # Swap
    if [ "$SWAP_SIZE" = "0" ]; then
        log_warn "跳过 Swap 配置"
        return
    fi
    
    if [ -f /swapfile ]; then
        log_info "Swap 文件已存在"
    else
        log_info "创建 $SWAP_SIZE Swap 文件..."
        if fallocate -l "$SWAP_SIZE" /swapfile 2>/dev/null; then
            :
        elif truncate -s "$SWAP_SIZE" /swapfile 2>/dev/null; then
            :
        elif dd if=/dev/zero of=/swapfile bs="$SWAP_SIZE" count=1 status=none; then
            :
        else
            log_error "创建 Swap 文件失败，请检查 SWAP_SIZE=$SWAP_SIZE"
            return 1
        fi
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        if ! grep -q '/swapfile' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        log_info "Swap 配置完成"
    fi
    
    free -h
}

step_docker() {
    log_step "Docker 安装与配置"
    
    if command -v docker &>/dev/null; then
        log_info "Docker 已安装: $(docker --version)"
    else
        log_info "正在安装 Docker..."
        curl -fsSL https://get.docker.com | bash
    fi
    
    # 配置 Docker
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
    
    # 添加用户到 docker 组
    if [ -n "$USERNAME" ] && id "$USERNAME" &>/dev/null; then
        usermod -aG docker "$USERNAME"
        log_info "用户 $USERNAME  已加入 docker 组"
    fi
    
    systemctl daemon-reload
    systemctl restart docker
    systemctl enable docker
    
    log_info "Docker 配置完成"
}

step_firewall() {
    log_step "配置 UFW 防火墙"
    
    # 安装 UFW
    if ! command -v ufw &>/dev/null; then
        apt install ufw -y
    fi
    
    # 重置 UFW（避免之前的规则干扰）
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 放行 SSH 端口
    local ssh_port
    ssh_port=$(detect_sshd_port)
    if ! is_valid_port "$ssh_port"; then
        log_error "无法识别有效 SSH 端口，取消防火墙配置"
        return 1
    fi
    ufw allow "$ssh_port"/tcp comment 'SSH'
    log_info "已放行 SSH 端口: $ssh_port"
    
    # 放行 Web 端口
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    log_info "已放行 HTTP/HTTPS 端口"
    
    # 启用防火墙
    echo "y" | ufw enable
    
    log_info "UFW 防火墙配置完成"
    ufw status numbered
}

step_fail2ban() {
    log_step "配置 Fail2Ban 防暴力破解"
    local ssh_port
    local banaction=""
    local banaction_allports=""
    ssh_port=$(detect_sshd_port)
    if ! is_valid_port "$ssh_port"; then
        log_error "无法识别有效 SSH 端口，取消 Fail2Ban 配置"
        return 1
    fi
    
    # 安装 Fail2Ban
    apt install fail2ban -y
    
    # 优先使用 nftables，其次 iptables
    if command -v nft >/dev/null 2>&1; then
        banaction="nftables-multiport"
        banaction_allports="nftables-allports"
    elif command -v iptables >/dev/null 2>&1; then
        banaction="iptables-multiport"
        banaction_allports="iptables-allports"
    else
        apt install -y nftables >/dev/null 2>&1 || true
        if command -v nft >/dev/null 2>&1; then
            banaction="nftables-multiport"
            banaction_allports="nftables-allports"
        else
            log_warn "未检测到 nft/iptables，Fail2Ban 可能无法正确封禁攻击源 IP"
        fi
    fi

    # 创建本地配置
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# 封禁时间（秒）
bantime = 3600
# 检测时间窗口（秒）
findtime = 600
# 最大尝试次数
maxretry = 5
# 忽略的 IP（本机）
ignoreip = 127.0.0.1/8 ::1
allowipv6 = auto
EOF

    if [ -n "$banaction" ]; then
        cat >> /etc/fail2ban/jail.local <<EOF
banaction = ${banaction}
banaction_allports = ${banaction_allports}
EOF
    fi

    cat >> /etc/fail2ban/jail.local <<EOF

[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
maxretry = 3
bantime = 7200
EOF

    # Debian 12+/极简系统可能没有 /var/log/auth.log，改用 systemd backend
    if [ ! -f /var/log/auth.log ]; then
        cat >> /etc/fail2ban/jail.local <<EOF
backend = systemd
journalmatch = _COMM=sshd
EOF
        log_info "检测到 /var/log/auth.log 不存在，Fail2Ban 使用 systemd 日志后端"
    else
        echo "logpath = /var/log/auth.log" >> /etc/fail2ban/jail.local
        log_info "Fail2Ban 使用 /var/log/auth.log"
    fi

    if ! fail2ban-client -t >/dev/null 2>&1; then
        log_error "Fail2Ban 配置校验失败，请检查 /etc/fail2ban/jail.local"
        return 1
    fi

    install -d -m 755 /var/run/fail2ban
    rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid || true
    
    # 重启服务
    systemctl restart fail2ban
    systemctl enable fail2ban >/dev/null 2>&1 || true
    sleep 1

    if systemctl is-active --quiet fail2ban; then
        log_info "Fail2Ban 已配置并启动"
        if ! fail2ban-client status sshd; then
            log_warn "sshd jail 状态读取失败，输出 Fail2Ban 总状态供排查"
            fail2ban-client status || true
        fi
    else
        log_error "Fail2Ban 启动失败，输出最近日志："
        systemctl status fail2ban --no-pager -l || true
        journalctl -u fail2ban --no-pager -n 50 || true
        if [ -f /var/log/fail2ban.log ]; then
            echo -e "\n${YELLOW}=== /var/log/fail2ban.log (tail 80) ===${NC}"
            tail -n 80 /var/log/fail2ban.log || true
        fi
        return 1
    fi
}

# --- 测试函数 ---
test_config() {
    echo -e "\n${BLUE}=== 系统配置检查 ===${NC}\n"
    
    echo -e "${CYAN}主机名:${NC}"
    hostname
    
    echo -e "\n${CYAN}系统时区:${NC}"
    timedatectl | grep "Time zone" || echo "无法获取时区信息"
    
    if [ -n "$USERNAME" ]; then
        echo -e "\n${CYAN}用户信息:${NC}"
        id "$USERNAME"
        
        echo -e "\n${CYAN}sudo 权限测试:${NC}"
        if sudo -l -U "$USERNAME" >/dev/null 2>&1; then
            echo "✓ sudo 权限正常（需密码）"
        else
            echo "✗ sudo 权限异常"
        fi
        
        echo -e "\n${CYAN}Docker 组成员:${NC}"
        groups "$USERNAME" | grep docker && echo "✓ 已加入 docker 组" || echo "✗ 未加入 docker 组"
    fi
    
    echo -e "\n${CYAN}SSH 配置:${NC}"
    echo "当前生效端口: $(detect_sshd_port)"
    grep "^Port" /etc/ssh/sshd_config || echo "Port 22 (默认)"
    grep "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin (未显式配置)"
    grep "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication (未显式配置)"
    
    echo -e "\n${CYAN}BBR 状态:${NC}"
    sysctl net.ipv4.tcp_congestion_control
    
    echo -e "\n${CYAN}Swap 状态:${NC}"
    free -h | grep Swap
    
    echo -e "\n${CYAN}Docker 版本:${NC}"
    docker --version 2>/dev/null || echo "未安装"
    
    echo -e "\n${CYAN}UFW 状态:${NC}"
    ufw status 2>/dev/null || echo "未安装"
    
    echo -e "\n${CYAN}Fail2Ban 状态:${NC}"
    systemctl status fail2ban --no-pager -l 2>/dev/null | grep "Active" || echo "未安装"
    
    echo ""
}

# --- 一键初始化主流程 ---
do_full_init() {
    if ! collect_full_info; then
        return
    fi
    
    step_upgrade
    step_hostname
    step_user
    step_ssh
    step_performance
    step_docker
    step_firewall
    step_fail2ban
    
    local final_ssh_port
    final_ssh_port=$(detect_sshd_port)
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}    🎉 VPS 初始化完成！${NC}"
    echo -e "${GREEN}========================================${NC}\n"
    
    echo -e "${YELLOW}重要提醒：${NC}"
    echo -e "1. 云平台安全组放行端口: ${RED}$final_ssh_port (TCP)${NC}"
    echo -e "2. 新终端测试登录: ${GREEN}ssh -p $final_ssh_port $USERNAME@$(hostname -I | awk '{print $1}')${NC}"
    echo -e "3. 测试密码登录和 sudo 权限"
    echo -e "4. 确认无误后再关闭当前终端\n"
    
    test_config
}

# --- 主菜单 ---
show_menu() {
    while true; do
        echo -e "\n${CYAN}============================================${NC}"
        echo -e "${CYAN}       VPS 初始化管理菜单 v2.0              ${NC}"
        echo -e "${CYAN}============================================${NC}"
        echo -e "  ${GREEN}1)${NC} 一键全量初始化 ${YELLOW}(推荐新系统)${NC}"
        echo -e "  ${GREEN}2)${NC} 系统更新与基础软件"
        echo -e "  ${GREEN}3)${NC} 修改主机名"
        echo -e "  ${GREEN}4)${NC} 创建/修改用户"
        echo -e "  ${GREEN}5)${NC} SSH 安全配置"
        echo -e "  ${GREEN}6)${NC} 性能优化 (BBR + Swap)"
        echo -e "  ${GREEN}7)${NC} 安装 Docker"
        echo -e "  ${GREEN}8)${NC} 配置 UFW 防火墙"
        echo -e "  ${GREEN}9)${NC} 配置 Fail2Ban"
        echo -e "  ${GREEN}t)${NC} 测试当前配置"
        echo -e "  ${RED}q)${NC} 退出"
        echo -e "${CYAN}--------------------------------------------${NC}"
        read -p "请选择 (1-9/t/q): " choice

        case $choice in
            1)
                do_full_init
                ;;
            2)
                step_upgrade
                ;;
            3)
                collect_hostname
                step_hostname
                ;;
            4)
                collect_username
                collect_password
                step_user
                ;;
            5)
                if [ -z "$USERNAME" ]; then
                    log_error "请先创建用户（选项 4）"
                else
                    collect_ssh_port
                    collect_ssh_key
                    step_ssh
                fi
                ;;
            6)
                collect_swap
                step_performance
                ;;
            7)
                if [ -z "$USERNAME" ]; then
                    log_warn "建议先创建用户，继续？(y/n)"
                    read -p "> " cont
                    [ "$cont" != "y" ] && continue
                fi
                step_docker
                ;;
            8)
                if [ -z "$SSH_PORT" ] || [ "$SSH_PORT" = "22222" ]; then
                    log_warn "当前 SSH_PORT=$SSH_PORT，确认？(y/n)"
                    read -p "> " cont
                    [ "$cont" != "y" ] && continue
                fi
                step_firewall
                ;;
            9)
                if [ -z "$SSH_PORT" ] || [ "$SSH_PORT" = "22222" ]; then
                    log_warn "当前 SSH_PORT=$SSH_PORT，确认？(y/n)"
                    read -p "> " cont
                    [ "$cont" != "y" ] && continue
                fi
                step_fail2ban
                ;;
            t|T)
                test_config
                ;;
            q|Q)
                echo -e "${GREEN}感谢使用，再见！${NC}"
                exit 0
                ;;
            *)
                log_error "无效选项，请重新选择"
                ;;
        esac
        
        echo -e "\n${YELLOW}按回车键返回菜单...${NC}"
        read
    done
}

# --- 脚本入口 ---
clear
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════╗
║   VPS 自动化初始化脚本 v2.0              ║
║   支持: Debian 10+ / Ubuntu 20.04+       ║
╚══════════════════════════════════════════╝
EOF
echo -e "${NC}"

show_menu
