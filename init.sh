#!/usr/bin/env bash
set -Eeuo pipefail

LOG="/var/log/vps_init.log"

################################
# 日志函数
################################
log_msg() {
    local level="$1"; shift
    local color prefix
    case "$level" in
        info)  color='\033[32m'; prefix='[INFO]' ;;
        warn)  color='\033[33m'; prefix='[WARN]' ;;
        error) color='\033[31m'; prefix='[ERR ]' ;;
        *)     color='';        prefix="[UNK]" ;;
    esac
    printf "${color}%s\033[0m %s\n" "$prefix" "$*" | tee -a "$LOG" >&2
}
info()  { log_msg info  "$@"; }
warn()  { log_msg warn  "$@"; }
err()   { log_msg error "$@"; exit 1; }

################################
# 权限检查
################################
require_root() {
    [[ $EUID -eq 0 ]] || err "必须以 root 用户运行"
}

################################
# 安全输入
################################
prompt() {
    local msg="${1:-}"
    local def="${2:-}"
    local val
    read -r -p "$msg [${def}]: " val </dev/tty
    printf '%s\n' "${val:-$def}"
}

pause() {
    read -rp "按回车继续..." _ </dev/tty
}

################################
# 系统初始化
################################
sys_update() {
    info "开始系统更新与基础组件安装..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y || err "apt-get update 失败"
    apt-get upgrade -y || warn "部分包升级失败（非致命）"
    apt-get autoremove -y

    apt-get install -y \
        curl wget sudo cron unzip rsync dnsutils net-tools \
        vnstat bc psmisc ca-certificates lsb-release jq

    timedatectl set-timezone Asia/Shanghai || warn "设置时区失败"

    cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null || warn "BBR 配置加载失败"

    systemctl enable --now cron || warn "cron 启动失败"

    info "✅ 系统初始化完成"
}

################################
# SSH 安全加固
################################
ssh_security() {
    info "配置 SSH 安全策略..."

    local port key
    port=$(prompt "SSH 端口" "50440")
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        err "无效的端口号：$port"
    fi

    key=$(prompt "粘贴 authorized_keys 公钥（必须）" "")
    [[ -z "$key" ]] && err "公钥不能为空！否则将无法登录"

    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "$key" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    chown -R root:root /root/.ssh

    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port $port
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 120
ClientAliveCountMax 3
EOF

    if ! sshd -t; then
        err "SSH 配置语法错误，请手动修复后再重启"
    fi

    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl restart ssh
    else
        err "未检测到活跃的 SSH 服务"
    fi

    info "✅ SSH 已加固"
    info "请使用新端口重新连接：ssh -p $port root@<your_ip>"
}

################################
# 幂等 crontab
################################
cron_add() {
    local tag="$1"
    local job="$2"
    local tmp_cron="/tmp/cron.$$"
    (crontab -l 2>/dev/null || true) | grep -v "#$tag" > "$tmp_cron"
    echo "$job #$tag" >> "$tmp_cron"
    crontab "$tmp_cron"
    rm -f "$tmp_cron"
    info "计划任务已更新 ($tag)"
}

################################
# 流量监控（兼容 vnstat v1.x 和 v2+）
################################
traffic_check() {
    info "配置流量监控..."

    systemctl enable --now vnstat || err "vnstat 服务启动失败"

    # 检测主网卡
    local iface
    iface=$(ip route show default | awk '{print $5; exit}')
    [[ -z "$iface" ]] && iface=$(ls /sys/class/net/ | grep -E '^(eth|ens|enp|em)' | head -n1)
    [[ -z "$iface" ]] && err "无法检测主网络接口"

    # 兼容 vnstat 版本
    if vnstat --version 2>/dev/null | grep -qE '2\.|3\.'; then
        info "检测到 vnstat v2+，使用 -u 初始化"
        vnstat -u -i "$iface" 2>/dev/null || true
    else
        info "检测到 vnstat v1.x，依赖自动初始化"
        systemctl restart vnstat
        sleep 8
        # 尝试触发数据库创建
        vnstat -i "$iface" >/dev/null 2>&1 || true
    fi

    # 用户输入
    local limit token chatid
    limit=$(prompt "月流量限制 (GB)" "500")
    if ! [[ "$limit" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        err "流量限制必须为数字"
    fi

    token=$(prompt "Telegram Bot Token" "")
    chatid=$(prompt "Telegram Chat ID" "")

    # 创建监控脚本（带容错）
    cat > /usr/local/bin/traffic_check.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail

iface='$iface'
limit=$limit
token='$token'
chatid='$chatid'

# 容错：检查 vnstat 数据库是否存在
if ! vnstat -i "\$iface" >/dev/null 2>&1; then
    logger -t traffic_monitor "vnstat 数据库未就绪 for \$iface, skipping check"
    exit 0
fi

# 获取当月总流量（字节）—— 兼容 v1/v2 JSON 输出
if command -v jq >/dev/null; then
    json=\$(vnstat -i "\$iface" --json 2>/dev/null || echo '{}')
    tx=\$(echo "\$json" | jq -r '.interfaces[0].traffic.months[-1].tx // "0"')
    rx=\$(echo "\$json" | jq -r '.interfaces[0].traffic.months[-1].rx // "0"')
    traffic=\$((tx + rx))
else
    # fallback to oneline (less reliable)
    line=\$(vnstat -i "\$iface" --oneline 2>/dev/null | head -n1)
    if [[ -z "\$line" ]]; then
        logger -t traffic_monitor "vnstat 无有效输出"
        exit 0
    fi
    # oneline 格式: version;iface;...;rx_bytes;tx_bytes;...
    IFS=';' read -ra F <<< "\$line"
    rx=\${F[9]:-0}
    tx=\${F[10]:-0}
    traffic=\$((rx + tx))
fi

gb=\$(echo "scale=2; \$traffic / 1024 / 1024 / 1024" | bc -l)

if (( \$(echo "\$gb > \$limit" | bc -l) )); then
    msg="⚠️ VPS 流量超限：\$gb GB / \$limit GB"
    logger -t traffic_monitor "\$msg"
    if [[ -n "\$token" ]] && [[ -n "\$chatid" ]]; then
        curl -s -m 10 -X POST "https://api.telegram.org/bot\$token/sendMessage" \\
            -d "chat_id=\$chatid" \\
            -d "text=\$msg" >/dev/null
    fi
    shutdown -h now
fi
EOF

    chmod +x /usr/local/bin/traffic_check.sh

    cron_add "traffic_monitor" "*/10 * * * * /usr/local/bin/traffic_check.sh"

    info "✅ 流量监控已启用（每10分钟检查一次）"
}

################################
# 修改 hostname
################################
hostname_change() {
    local new
    new=$(prompt "新 hostname" "$(hostname)")
    [[ -z "$new" ]] && err "hostname 不能为空"

    hostnamectl set-hostname "$new" || err "设置 hostname 失败"

    if grep -q "^127\.0\.1\.1" /etc/hosts; then
        sed -i "s/^127\.0\.1\.1.*/127.0.1.1 $new/" /etc/hosts
    else
        echo "127.0.1.1 $new" >> /etc/hosts
    fi

    info "✅ hostname 已修改为：$new"
}

################################
# 菜单
################################
menu() {
    cat >&2 <<'EOF'

==============================
 VPS 初始化工具
==============================
1. 系统初始化
2. SSH 安全加固
3. 流量监控 (Telegram)
4. 修改 hostname
0. 退出
EOF
}

################################
# 主程序
################################
main() {
    require_root

    while true; do
        menu
        read -rp "请选择 (0-4): " choice </dev/tty
        case "$choice" in
            1) sys_update; pause ;;
            2) ssh_security; pause ;;
            3) traffic_check; pause ;;
            4) hostname_change; pause ;;
            0) info "退出"; exit 0 ;;
            *) warn "无效选项，请重试" ;;
        esac
    done
}

main "$@"
