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

# ===== 系统优化（bbr）=====
log "bbr优化"

cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

sysctl --system

log "当前拥塞控制算法"
sysctl net.ipv4.tcp_congestion_control

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
