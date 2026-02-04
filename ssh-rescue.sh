#!/bin/bash
# SSH Emergency Rescue Script
# 用途：查看SSH配置 + 紧急开启密码登录
# 作者：VPS技术专家
# 日期：2026-02-04

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 分隔线
line() {
    echo -e "${BLUE}$(printf '=%.0s' {1..60})${NC}"
}

# 标题
title() {
    line
    echo -e "${GREEN}$1${NC}"
    line
}

# 检查root权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误：此脚本需要root权限运行${NC}"
   echo "请使用: sudo bash $0"
   exit 1
fi

# ===========================================
# 功能1：查看当前SSH配置
# ===========================================
view_ssh_config() {
    title "📋 当前SSH配置状态"
    
    echo -e "${YELLOW}【1】生效的配置（sshd -T）${NC}"
    sshd -T | grep -E "^(port|passwordauthentication|permitrootlogin|pubkeyauthentication)" | while read line; do
        key=$(echo $line | cut -d' ' -f1)
        value=$(echo $line | cut -d' ' -f2)
        
        if [[ "$key" == "port" ]]; then
            echo -e "  ${GREEN}SSH端口:${NC} $value"
        elif [[ "$key" == "passwordauthentication" ]]; then
            if [[ "$value" == "yes" ]]; then
                echo -e "  ${RED}密码认证:${NC} $value (已启用)"
            else
                echo -e "  ${GREEN}密码认证:${NC} $value (已禁用)"
            fi
        elif [[ "$key" == "permitrootlogin" ]]; then
            echo -e "  ${YELLOW}Root登录:${NC} $value"
        elif [[ "$key" == "pubkeyauthentication" ]]; then
            echo -e "  ${GREEN}密钥认证:${NC} $value"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}【2】配置文件位置${NC}"
    echo -e "  主配置: ${GREEN}/etc/ssh/sshd_config${NC}"
    
    echo ""
    echo -e "${YELLOW}【3】已授权的公钥${NC}"
    if [ -f ~/.ssh/authorized_keys ]; then
        key_count=$(grep -c "^ssh-" ~/.ssh/authorized_keys 2>/dev/null || echo 0)
        echo -e "  ${GREEN}公钥数量:${NC} $key_count"
        echo -e "  ${GREEN}文件路径:${NC} ~/.ssh/authorized_keys"
        echo ""
        echo "  公钥列表："
        grep "^ssh-" ~/.ssh/authorized_keys | while read line; do
            keytype=$(echo $line | awk '{print $1}')
            comment=$(echo $line | awk '{print $3}')
            echo -e "    - ${BLUE}$keytype${NC} ${GREEN}$comment${NC}"
        done
    else
        echo -e "  ${RED}未找到授权公钥文件${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}【4】当前连接会话${NC}"
    who
    
    echo ""
}

# ===========================================
# 功能2：紧急开启密码登录
# ===========================================
enable_password_login() {
    title "🚨 紧急开启密码登录"
    
    # 检查当前状态
    current_status=$(sshd -T | grep "^passwordauthentication" | awk '{print $2}')
    
    if [[ "$current_status" == "yes" ]]; then
        echo -e "${YELLOW}密码认证已经是开启状态，无需修改${NC}"
        return
    fi
    
    echo -e "${RED}⚠️  警告：开启密码登录会降低安全性！${NC}"
    echo -e "${YELLOW}建议仅在紧急情况下使用（如丢失私钥）${NC}"
    echo ""
    
    read -p "确认要开启密码登录吗？(yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${GREEN}✅ 取消操作${NC}"
        return
    fi
    
    # 创建备份
    backup_file="/etc/ssh/sshd_config.backup.$(date +%s)"
    cp /etc/ssh/sshd_config "$backup_file"
    echo -e "${GREEN}✅ 已创建备份: $backup_file${NC}"
    
    # 修改配置
    echo -e "${YELLOW}正在修改配置...${NC}"
    
    # 方法1：直接替换现有行
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # 方法2：如果没有这行，添加它
    if ! grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
        echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    fi
    
    # 测试配置
    echo -e "${YELLOW}测试新配置...${NC}"
    if sshd -t 2>&1; then
        echo -e "${GREEN}✅ 配置语法正确${NC}"
        
        # 重载SSH服务
        echo -e "${YELLOW}重载SSH服务...${NC}"
        systemctl reload sshd
        
        echo -e "${GREEN}✅ SSH服务已重载${NC}"
        echo ""
        
        # 显示新配置
        echo -e "${YELLOW}【新配置状态】${NC}"
        sshd -T | grep -E "^(port|passwordauthentication|permitrootlogin)"
        
        echo ""
        echo -e "${GREEN}✅ 密码登录已成功开启！${NC}"
        echo ""
        echo -e "${YELLOW}【重要提醒】${NC}"
        echo "1. 请立即设置强密码: passwd root"
        echo "2. 修复密钥后，请再次关闭密码登录"
        echo "3. 恢复命令: cp $backup_file /etc/ssh/sshd_config && systemctl reload sshd"
        
    else
        echo -e "${RED}❌ 配置测试失败，恢复备份...${NC}"
        cp "$backup_file" /etc/ssh/sshd_config
        echo -e "${GREEN}✅ 已恢复原配置${NC}"
        exit 1
    fi
}

# ===========================================
# 功能3：设置Root密码
# ===========================================
set_root_password() {
    title "🔑 设置Root密码"
    
    echo -e "${YELLOW}即将设置新的Root密码${NC}"
    echo -e "${RED}密码要求：至少12位，包含大小写字母+数字+特殊符号${NC}"
    echo ""
    
    passwd root
    
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✅ 密码设置成功！${NC}"
    else
        echo -e "${RED}❌ 密码设置失败${NC}"
    fi
}

# ===========================================
# 功能4：关闭密码登录（恢复安全配置）
# ===========================================
disable_password_login() {
    title "🔒 关闭密码登录（恢复安全配置）"
    
    # 检查当前状态
    current_status=$(sshd -T | grep "^passwordauthentication" | awk '{print $2}')
    
    if [[ "$current_status" == "no" ]]; then
        echo -e "${GREEN}密码认证已经是关闭状态${NC}"
        return
    fi
    
    echo -e "${YELLOW}准备关闭密码登录，恢复密钥认证...${NC}"
    echo ""
    
    # 检查是否有授权公钥
    if [ ! -f ~/.ssh/authorized_keys ] || [ ! -s ~/.ssh/authorized_keys ]; then
        echo -e "${RED}❌ 警告：未找到授权公钥！${NC}"
        echo -e "${YELLOW}请先添加公钥，否则关闭密码登录后将无法连接！${NC}"
        return
    fi
    
    key_count=$(grep -c "^ssh-" ~/.ssh/authorized_keys 2>/dev/null || echo 0)
    echo -e "${GREEN}检测到 $key_count 个授权公钥${NC}"
    echo ""
    
    read -p "确认要关闭密码登录吗？(yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${GREEN}✅ 取消操作${NC}"
        return
    fi
    
    # 创建备份
    backup_file="/etc/ssh/sshd_config.backup.$(date +%s)"
    cp /etc/ssh/sshd_config "$backup_file"
    echo -e "${GREEN}✅ 已创建备份: $backup_file${NC}"
    
    # 修改配置
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    if ! grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
        echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    fi
    
    # 测试并重载
    if sshd -t 2>&1; then
        systemctl reload sshd
        echo -e "${GREEN}✅ 密码登录已关闭${NC}"
        echo ""
        sshd -T | grep -E "^(port|passwordauthentication|permitrootlogin)"
    else
        echo -e "${RED}❌ 配置错误，恢复备份${NC}"
        cp "$backup_file" /etc/ssh/sshd_config
    fi
}

# ===========================================
# 功能5：一键创建新密钥（从VPS生成）
# ===========================================
generate_new_keypair() {
    title "🔐 生成新的SSH密钥对"
    
    echo -e "${YELLOW}此功能将在VPS上生成新密钥对${NC}"
    echo -e "${RED}⚠️  私钥将显示在屏幕上，请务必保存！${NC}"
    echo ""
    
    read -p "输入密钥名称（如：vps_rescue）: " keyname
    
    if [ -z "$keyname" ]; then
        keyname="vps_rescue_$(date +%Y%m%d)"
    fi
    
    tmpdir="/tmp/ssh_keys_$$"
    mkdir -p "$tmpdir"
    
    echo -e "${YELLOW}生成ED25519密钥...${NC}"
    ssh-keygen -t ed25519 -f "$tmpdir/$keyname" -N "" -C "rescue_key_$(date +%Y%m%d)"
    
    echo ""
    echo -e "${GREEN}✅ 密钥生成成功！${NC}"
    echo ""
    
    # 显示私钥
    echo -e "${RED}=== 私钥（请立即复制保存到本地）===${NC}"
    cat "$tmpdir/$keyname"
    echo -e "${RED}=== 私钥结束 ===${NC}"
    echo ""
    
    # 添加公钥到authorized_keys
    echo -e "${YELLOW}是否立即添加到authorized_keys？(yes/no): ${NC}"
    read add_key
    
    if [[ "$add_key" == "yes" ]]; then
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        cat "$tmpdir/$keyname.pub" >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        echo -e "${GREEN}✅ 公钥已添加${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}【使用方法】${NC}"
    echo "1. 复制上方私钥到本地文件: ~/.ssh/$keyname"
    echo "2. 设置权限: chmod 600 ~/.ssh/$keyname"
    echo "3. 登录命令: ssh -p $(sshd -T | grep "^port" | awk '{print $2}') -i ~/.ssh/$keyname root@你的IP"
    
    # 清理临时文件
    rm -rf "$tmpdir"
}

# ===========================================
# 主菜单
# ===========================================
main_menu() {
    clear
    title "🛠️  SSH紧急救援工具"
    
    echo ""
    echo "【查看配置】"
    echo "  1) 查看当前SSH配置"
    echo ""
    echo "【紧急操作】"
    echo "  2) 🚨 紧急开启密码登录"
    echo "  3) 🔑 设置Root密码"
    echo "  4) 🔐 生成新的SSH密钥对"
    echo ""
    echo "【安全恢复】"
    echo "  5) 🔒 关闭密码登录（恢复安全）"
    echo ""
    echo "  0) 退出"
    echo ""
    
    read -p "请选择操作 [0-5]: " choice
    
    case $choice in
        1)
            view_ssh_config
            ;;
        2)
            enable_password_login
            ;;
        3)
            set_root_password
            ;;
        4)
            generate_new_keypair
            ;;
        5)
            disable_password_login
            ;;
        0)
            echo -e "${GREEN}再见！${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            ;;
    esac
    
    echo ""
    read -p "按Enter继续..." 
    main_menu
}

# 启动脚本
main_menu
