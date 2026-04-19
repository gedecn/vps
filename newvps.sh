#!/usr/bin/env bash
# bash <(wget -qO- https://raw.githubusercontent.com/gedecn/vps/main/newvps.sh)

set -Eeuo pipefail

# ===== 基础 =====
log() { echo -e "\033[1;32m[INFO]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; exit 1; }
trap 'err "line $LINENO 执行失败"' ERR

# ===== root =====
[[ "$(id -u)" = "0" ]] || err "必须 root 执行"

# ===== 必填变量校验（严格）=====
: "${SSH_PUBLIC_KEY:?缺少 SSH_PUBLIC_KEY}"
: "${DOMAIN:?缺少 DOMAIN}"
: "${CF_Token:?缺少 CF_Token}"
: "${UUID:?缺少 UUID}"
: "${PRIKEY:?缺少 PRIKEY}"
: "${SID:?缺少 SID}"

# ===== 默认值 =====
SSH_PORT="${SSH_PORT:-50440}"

# ===== 系统 =====
log "系统更新"
apt-get update -y
apt-get upgrade -y

apt-get install -y curl wget cron psmisc fail2ban gettext

timedatectl set-timezone Asia/Shanghai

# ===== 系统优化（代理+转发）=====
log "内核优化"

cat >/etc/security/limits.d/99-nofile.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

cat >/etc/sysctl.d/99-proxy.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1

net.core.somaxconn=65535
net.core.netdev_max_backlog=16384

net.ipv4.ip_local_port_range=1024 65535

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728

net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1

net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1

net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=5

net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384

net.netfilter.nf_conntrack_max=1000000
net.netfilter.nf_conntrack_buckets=262144
net.netfilter.nf_conntrack_tcp_timeout_established=7200
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=180
net.netfilter.nf_conntrack_checksum=0

net.ipv4.route.gc_timeout=100
net.ipv4.route.max_size=2147483647

net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

sysctl --system

# ===== SSH =====
log "SSH"

install -d -m 700 /root/.ssh
echo "$SSH_PUBLIC_KEY" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port ${SSH_PORT}
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
EOF

systemctl restart ssh || systemctl restart sshd

# ===== fail2ban =====
systemctl enable fail2ban
systemctl restart fail2ban

# ===== sing-box =====
log "安装 sing-box"

mkdir -p /etc/apt/keyrings

curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
chmod a+r /etc/apt/keyrings/sagernet.asc

rm -f /etc/apt/sources.list.d/*sagernet*
cat >/etc/apt/sources.list.d/sagernet.sources <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF

apt-get update -y || err "apt-get update 失败"
apt-get install -y sing-box || err "sing-box 安装失败"

install -d /etc/sing-box

# ===== 模板处理 =====
log "下载模板"

tpl="/etc/sing-box/config.json.tpl"
cfg="/etc/sing-box/config.json"

curl -fsSL "https://raw.githubusercontent.com/gedecn/vps/refs/heads/main/sing-box/reality.json" -o "$tpl"
[[ -s "$tpl" ]] || err "模板下载失败"

log "变量替换"

envsubst < "$tpl" > "$cfg"

# ===== 校验 =====
grep -q '\${' "$cfg" && err "存在未替换变量"
[[ -s "$cfg" ]] || err "config.json 为空"

systemctl enable sing-box
systemctl restart sing-box

# ===== 健康检查 =====
log "健康检查"

sleep 2
systemctl is-active --quiet sing-box || err "sing-box 启动失败"

# ===== 完成 =====
log "完成"
echo "SSH端口: ${SSH_PORT}"
echo "日志: journalctl -u sing-box -f"
