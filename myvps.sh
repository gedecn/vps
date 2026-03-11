#!/usr/bin/env bash
set -Eeuo pipefail

LOG_FILE="/var/log/myvps.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=============================="
echo "VPS INIT START $(date)"
echo "=============================="

#################################
# root 检查
#################################

[ "$(id -u)" = "0" ] || { echo "必须 root"; exit 1; }

cd /opt

#################################
# 读取 env
#################################

ENV_FILE="/opt/.env"

[ -f "$ENV_FILE" ] || { echo ".env 不存在"; exit 1; }

source "$ENV_FILE"

: "${CF_Token:?}"
: "${SSH_PUBLIC_KEY:?}"
: "${DOMAIN:?}"

#################################
# 系统更新
#################################

echo "[1] 系统更新"

export DEBIAN_FRONTEND=noninteractive

apt update
apt upgrade -y
apt autoremove -y

apt install -y \
curl wget sudo cron unzip vnstat bc \
net-tools dnsutils openssl ca-certificates \
ufw fail2ban

#################################
# 时区
#################################

echo "[2] 时区"

timedatectl set-timezone Asia/Shanghai

#################################
# docker
#################################

echo "[3] docker"

if ! command -v docker >/dev/null; then
curl -fsSL https://get.docker.com | bash
fi

systemctl enable docker
systemctl start docker

#################################
# docker 日志优化
#################################

echo "[4] docker logging"

mkdir -p /etc/docker

cat >/etc/docker/daemon.json <<EOF
{
"log-driver": "json-file",
"log-opts": {
"max-size": "10m",
"max-file": "3"
}
}
EOF

systemctl restart docker

#################################
# BBR
#################################

echo "[5] BBR"

cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

#################################
# TCP 调优
#################################

echo "[6] TCP tuning"

cat >/etc/sysctl.d/98-tcp.conf <<EOF
fs.file-max = 1000000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF

sysctl --system

#################################
# VPS 指纹隐藏
#################################

echo "[7] VPS 指纹"

rm -f /etc/motd
rm -f /etc/update-motd.d/*

echo "" > /etc/issue
echo "" > /etc/issue.net

#################################
# root 密码
#################################

echo "[8] root 密码"

ROOT_PASS=$(openssl rand -base64 18)

echo "root:$ROOT_PASS" | chpasswd

echo "ROOT PASSWORD: $ROOT_PASS"

#################################
# SSH key
#################################

echo "[9] SSH key"

mkdir -p /root/.ssh
chmod 700 /root/.ssh

echo "$SSH_PUBLIC_KEY" > /root/.ssh/authorized_keys

chmod 600 /root/.ssh/authorized_keys

#################################
# SSH 配置
#################################

echo "[10] SSH 安全"

cat >/etc/ssh/sshd_config <<EOF
Port 50440

PermitRootLogin prohibit-password
PasswordAuthentication no

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

ChallengeResponseAuthentication no
UsePAM no

X11Forwarding no
AllowTcpForwarding no

Subsystem sftp /usr/lib/openssh/sftp-server
EOF

systemctl restart ssh || systemctl restart sshd

#################################
# 防火墙
#################################

echo "[11] 防火墙"

ufw default deny incoming
ufw default allow outgoing

ufw allow 50440/tcp
ufw allow 50443/tcp
ufw allow 50443/udp

for p in 50444 50445 50446 50447 50448 50449
do
ufw allow $p/tcp
done

ufw --force enable

#################################
# fail2ban
#################################

echo "[12] fail2ban"

systemctl enable fail2ban
systemctl start fail2ban


#################################
# ACME
#################################

echo "[13] ACME"

cd /opt/acme || exit 1

docker compose pull
docker compose run --rm acme --set-default-ca --server letsencrypt
docker compose run --rm acme --issue --dns dns_cf -d $DOMAIN -d "*.$DOMAIN" --keylength ec-256
docker compose run --rm acme --install-cert -d $DOMAIN --ecc --key-file /cert/$DOMAIN.key --fullchain-file /cert/$DOMAIN.pem
docker compose up -d

cd /opt || exit 1

#################################
# sing-box
#################################

echo "[14] sing-box"

cd /opt/sing-box || exit 1

docker compose pull
docker compose up -d

cd /opt || exit 1

#################################
# reload
#################################

echo "[15] reload"

chmod +x /opt/reload.sh

#################################
# cron
#################################

echo "[16] cron"

(crontab -l 2>/dev/null || true; echo "*/10 * * * * /opt/reload.sh >> /var/log/reload.log 2>&1") | crontab -

#################################
# docker 自动清理
#################################

echo "[17] docker cleanup"

(crontab -l 2>/dev/null || true; echo "0 4 * * * docker system prune -af >/dev/null 2>&1") | crontab -

#################################

echo "=============================="
echo "初始化完成"
echo "SSH端口: 50440"
echo "日志: $LOG_FILE"
echo "=============================="
