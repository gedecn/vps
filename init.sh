#!/usr/bin/env bash
set -Eeuo pipefail

LOG="/var/log/vps_init.log"

################################
# 基础输出
################################
info(){ echo -e "\033[32m[INFO]\033[0m $*" | tee -a "$LOG" > /dev/tty; }
warn(){ echo -e "\033[33m[WARN]\033[0m $*" | tee -a "$LOG" > /dev/tty; }
err(){  echo -e "\033[31m[ERR ]\033[0m $*" | tee -a "$LOG" > /dev/tty; exit 1; }

require_root(){
    [[ $EUID -ne 0 ]] && err "必须使用 root 运行"
}

################################
# 关键：从终端读取输入
################################
prompt(){
    local msg="$1"
    local def="${2:-}"
    local val
    read -r -p "$msg [$def]: " val < /dev/tty
    echo "${val:-$def}"
}

pause(){
    read -rp "按回车继续..." _ < /dev/tty
}

################################
# 系统初始化
################################
sys_update(){

    info "更新系统并安装基础组件..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y
    apt-get upgrade -y
    apt-get autoremove -y

    apt-get install -y \
        curl wget sudo cron unzip rsync dnsutils net-tools \
        vnstat bc psmisc ca-certificates

    timedatectl set-timezone Asia/Shanghai || true

    info "启用 BBR"

    cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sysctl --system

    systemctl enable cron --now

    info "系统初始化完成"
}

################################
# SSH 安全
################################
ssh_security(){

    info "配置 SSH 安全"

    local port
    port=$(prompt "SSH端口" "50440")

    local key
    key=$(prompt "粘贴 authorized_keys 公钥" "")

    [[ -z "$key" ]] && err "必须提供公钥！否则你会直接锁死服务器"

    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "$key" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys

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

    sshd -t || err "SSH配置错误，未应用"

    systemctl restart ssh || systemctl restart sshd

    info "SSH已加固完成"
    info "请重新连接: ssh -p $port root@你的IP"
}

################################
# cron 幂等
################################
cron_add(){

    local tag="$1"
    local job="$2"

    (crontab -l 2>/dev/null | grep -v "#$tag"; echo "$job #$tag") | crontab -

    info "计划任务已更新 ($tag)"
}

################################
# 流量监控
################################
traffic_check(){

    info "配置流量监控"

    systemctl enable vnstat --now

    local iface
    iface=$(ip route | awk '/default/ {print $5; exit}')

    vnstat -u -i "$iface" || true

    local limit
    limit=$(prompt "月流量限制(GB)" "500")

    local token
    token=$(prompt "Telegram Bot Token" "")

    local chatid
    chatid=$(prompt "Telegram Chat ID" "")

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

    info "流量监控已启用"
}

################################
# hostname
################################
hostname_change(){

    local new
    new=$(prompt "新hostname" "")

    hostnamectl set-hostname "$new"

    if grep -q "127.0.1.1" /etc/hosts; then
        sed -i "s/127.0.1.1.*/127.0.1.1 $new/g" /etc/hosts
    else
        echo "127.0.1.1 $new" >> /etc/hosts
    fi

    info "hostname 已修改为 $new"
}

################################
# 菜单
################################
menu(){
cat > /dev/tty <<'EOF'

==============================
 VPS 初始化工具
==============================
1. 系统初始化
2. SSH安全加固
3. 流量监控(Telegram)
4. 修改hostname
0. 退出

EOF
}

################################
# 主循环
################################
require_root

while true; do
    menu
    read -rp "请选择: " c < /dev/tty
    case $c in
        1) sys_update; pause ;;
        2) ssh_security; pause ;;
        3) traffic_check; pause ;;
        4) hostname_change; pause ;;
        0) exit 0 ;;
    esac
done
