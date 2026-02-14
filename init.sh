#!/usr/bin/env bash
set -Eeuo pipefail

############################
# 基础工具
############################

LOG="/var/log/vps_init.log"

info()  { echo -e "\033[32m[INFO]\033[0m  $*" | tee -a "$LOG"; }
warn()  { echo -e "\033[33m[WARN]\033[0m  $*" | tee -a "$LOG"; }
error() { echo -e "\033[31m[ERR ]\033[0m  $*" | tee -a "$LOG"; exit 1; }

require_root() {
    [[ $EUID -ne 0 ]] && error "必须 root 运行"
}

prompt() {
    local msg="$1"
    local def="${2:-}"
    local val

    read -r -p "$msg [$def]: " val
    echo "${val:-$def}"
}

############################
# 系统更新 + BBR
############################
sys_update() {

    info "更新系统并安装基础软件"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get upgrade -y
    apt-get install -y \
        curl wget sudo cron unzip rsync dnsutils net-tools \
        vnstat bc psmisc ca-certificates

    timedatectl set-timezone Asia/Shanghai

    info "启用 BBR"

    cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sysctl --system

    info "系统初始化完成"
}

############################
# SSH安全配置
############################
ssh_security() {

    local port
    port=$(prompt "SSH端口" "50440")

    local key
    key=$(prompt "粘贴 authorized_keys 公钥" "")

    [[ -z "$key" ]] && error "必须提供公钥，否则会锁死 SSH"

    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "$key" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys

    info "写入 SSH drop-in 配置"

    mkdir -p /etc/ssh/sshd_config.d

    cat >/etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port $port
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 120
ClientAliveCountMax 3
EOF

    sshd -t || error "SSH配置错误，未应用"
    systemctl restart ssh

    info "SSH加固完成，端口: $port"
}

############################
# cron 管理（幂等）
############################
cron_add() {

    local tag="$1"
    local job="$2"

    (crontab -l 2>/dev/null | grep -v "#$tag"; echo "$job #$tag") | crontab -

    info "计划任务已更新: $tag"
}

############################
# 流量监控
############################
traffic_check() {

    systemctl enable vnstat --now

    local iface
    iface=$(ip route | awk '/default/ {print $5; exit}')

    vnstat -u -i "$iface" || true

    local limit
    limit=$(prompt "月流量限制(GB)" "500")

    local token
    token=$(prompt "Telegram bot token" "")

    local chatid
    chatid=$(prompt "Telegram chat_id" "")

    cat >/usr/local/bin/traffic_check.sh <<EOF
#!/usr/bin/env bash
limit=$limit
iface=$iface

traffic=\$(vnstat -i \$iface --oneline b | awk -F';' '{print \$10}')
gb=\$(echo "scale=2; \$traffic/1024/1024/1024" | bc)

if (( \$(echo "\$gb > \$limit" | bc -l) )); then
    curl -s -X POST https://api.telegram.org/bot$token/sendMessage \
        -d chat_id="$chatid" \
        -d text="VPS流量超限: \$gb GB / \$limit GB"
    shutdown -h now
fi
EOF

    chmod +x /usr/local/bin/traffic_check.sh

    cron_add "traffic_monitor" "*/10 * * * * /usr/local/bin/traffic_check.sh"
}

############################
# hostname
############################
hostname_change() {

    local new
    new=$(prompt "新hostname" "")

    hostnamectl set-hostname "$new"
    sed -i "s/127.0.1.1.*/127.0.1.1 $new/g" /etc/hosts

    info "hostname 已修改为 $new"
}

############################
# 菜单
############################
menu() {
    echo
    echo "1. 系统初始化"
    echo "2. SSH安全加固"
    echo "3. 流量监控"
    echo "4. 修改hostname"
    echo "0. 退出"
}

require_root

while true; do
    menu
    read -rp "选择: " c
    case $c in
        1) sys_update ;;
        2) ssh_security ;;
        3) traffic_check ;;
        4) hostname_change ;;
        0) exit 0 ;;
    esac
done
