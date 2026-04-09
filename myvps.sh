#!/usr/bin/env bash
#bash <(wget -qO- https://raw.githubusercontent.com/gedecn/vps/main/myvps.sh)

set -Eeuo pipefail

# ===== 函数定义区 =====

prompt_input() {
    local var_name="$1"
    local prompt_text="$2"
    local is_secret="${3:-false}"
    local regex="${4:-}"   # 可选：输入校验（正则）

    local input

    while true; do
        if [ "$is_secret" = "true" ]; then
            read -rsp "$prompt_text: " input
            echo
        else
            read -rp "$prompt_text: " input
        fi

        # 判空
        if [ -z "$input" ]; then
            echo "❌ 不能为空"
            continue
        fi

        # 正则校验（可选）
        if [ -n "$regex" ] && ! [[ "$input" =~ $regex ]]; then
            echo "❌ 格式不正确"
            continue
        fi

        # 赋值
        printf -v "$var_name" '%s' "$input"
        export "$var_name"
        break
    done
}

enter_dir() {
    local dir="$1"

    if [ ! -d "$dir" ]; then
        echo "📁 创建目录: $dir"
        mkdir -p "$dir"
    fi

    cd "$dir" || {
        echo "❌ 无法进入目录: $dir"
        exit 1
    }
}

echo "=============================="
echo "= root 检查"
echo "=============================="

[ "$(id -u)" = "0" ] || { echo "必须 root"; exit 1; }
enter_dir "/opt"

echo "=============================="
echo "= 输入参数"
echo "=============================="

prompt_input SSH_PUBLIC_KEY "SSH 公钥" true
prompt_input CF_Token "Cloudflare API Token" true
prompt_input DOMAIN "域名" false '^[a-zA-Z0-9.-]+$'
prompt_input UUID "用户UUID" false '^[0-9a-fA-F-]{36}$'
prompt_input PRIKEY "reality private key" true
prompt_input SID "reality short id" false


echo "=============================="
echo "= 系统更新"
echo "=============================="

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -y
apt-get autoremove -y

apt-get install -y curl wget sudo cron unzip vnstat bc net-tools dnsutils psmisc openssl ca-certificates ufw fail2ban

echo "=============================="
echo "= 时区"
echo "=============================="


timedatectl set-timezone Asia/Shanghai

echo "=============================="
echo "= docker"
echo "=============================="


if ! command -v docker >/dev/null; then
curl -fsSL https://get.docker.com | bash
fi

systemctl enable docker
systemctl start docker

echo "=============================="
echo "= docker 日志优化"
echo "=============================="

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

echo "=============================="
echo "= TCP 调优"
echo "=============================="

echo "===> 删除所有自定义配置"
find /etc/sysctl.d -type f ! -path "/usr/lib/sysctl.d/*" -delete 2>/dev/null || true

echo "===> 写入 VPN 优化配置"
cat > /etc/sysctl.d/99-vpn-tune.conf << 'EOC'
# ========= 基础 =========
fs.file-max = 1000000
kernel.pid_max = 4194304
# ========= 网络队列 =========
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 25165824
# ========= 端口 =========
net.ipv4.ip_local_port_range = 1024 65535
# ========= BBR =========
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# ========= TCP buffer =========
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
# ========= UDP 优化 =========
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
# ========= TCP 性能 =========
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_autocorking = 0
# ========= 连接优化 =========
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
# ========= keepalive =========
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 5
# ========= conntrack =========
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_buckets = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 180
# ========= 内存 =========
vm.swappiness = 10
vm.max_map_count = 262144
EOC

sysctl --system


echo "=============================="
echo "= VPS 指纹隐藏"
echo "=============================="

rm -f /etc/motd
rm -f /etc/update-motd.d/*

echo "" > /etc/issue
echo "" > /etc/issue.net

echo "=============================="
echo "= root 密码"
echo "=============================="


ROOT_PASS=$(openssl rand -base64 18)

echo "root:$ROOT_PASS" | chpasswd
echo "ROOT PASSWORD: $ROOT_PASS"

echo "=============================="
echo "= SSH key"
echo "=============================="

mkdir -p /root/.ssh
chmod 700 /root/.ssh

echo "$SSH_PUBLIC_KEY" > /root/.ssh/authorized_keys

chmod 600 /root/.ssh/authorized_keys

echo "=============================="
echo "= SSH 配置"
echo "=============================="

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

echo "=============================="
echo "= fail2ban"
echo "=============================="


systemctl enable fail2ban
systemctl start fail2ban


echo "=============================="
echo "= ACME"
echo "=============================="

enter_dir "/opt/acme"

curl -fsSL "https://raw.githubusercontent.com/gedecn/vps/refs/heads/main/acme/docker-compose.yml" -o "docker-compose.yml"

docker compose pull
docker compose run --rm acme --set-default-ca --server letsencrypt
docker compose run --rm acme --issue --dns dns_cf -d $DOMAIN -d "*.$DOMAIN" --keylength ec-256
docker compose run --rm acme --install-cert -d $DOMAIN --ecc --key-file /cert/$DOMAIN.key --fullchain-file /cert/$DOMAIN.pem
docker compose up -d

cd /opt || exit 1

echo "=============================="
echo "= sing-box"
echo "=============================="

enter_dir "/opt/sing-box"

curl -fsSL "https://raw.githubusercontent.com/gedecn/vps/refs/heads/main/sing-box/config.json" -o "config.json.tpl"
envsubst < "config.json.tpl" > "config.json"

curl -fsSL "https://raw.githubusercontent.com/gedecn/vps/refs/heads/main/sing-box/docker-compose.yml" -o "docker-compose.yml"

docker compose pull
docker compose up -d

cd /opt || exit 1

echo "=============================="
echo "= reload cron"
echo "=============================="

curl -fsSL "https://raw.githubusercontent.com/gedecn/vps/refs/heads/main/reload.sh" -o "reload.sh"
chmod +x /opt/reload.sh

(crontab -l 2>/dev/null || true; echo "*/10 * * * * /opt/reload.sh >> /var/log/reload.log 2>&1") | crontab -

echo "=============================="
echo "= docker 自动清理"
echo "=============================="


(crontab -l 2>/dev/null || true; echo "0 4 * * * docker system prune -af >/dev/null 2>&1") | crontab -


echo "=============================="
echo "= 设置swap为内存2倍"
echo "=============================="

swapfile="/swapfile"

echo "===> Detecting memory..."

mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
mem_mb=$((mem_kb / 1024))
swap_mb=$((mem_mb * 2))

echo "Memory: ${mem_mb} MB"
echo "Target swap: ${swap_mb} MB"

# 判断是否已有 swap
if swapon --show | grep -q '^'; then
    echo "===> Swap exists, removing..."
    swapoff -a || true

    # 删除旧 swapfile（如果存在）
    [ -f "$swapfile" ] && rm -f "$swapfile"

    # 清理 fstab 中旧记录
    sed -i '\|/swapfile|d' /etc/fstab
else
    echo "===> No swap found, creating..."
fi

echo "===> Creating swapfile..."

# 优先 fallocate
if command -v fallocate >/dev/null 2>&1; then
    fallocate -l ${swap_mb}M $swapfile || dd if=/dev/zero of=$swapfile bs=1M count=$swap_mb
else
    dd if=/dev/zero of=$swapfile bs=1M count=$swap_mb
fi

chmod 600 $swapfile
mkswap $swapfile
swapon $swapfile

# 写入 fstab（避免重复）
if ! grep -q "^$swapfile" /etc/fstab; then
    echo "$swapfile none swap sw 0 0" >> /etc/fstab
fi

echo "===> Done!"
swapon --show
free -h

echo "=============================="
echo "初始化完成"
echo "SSH端口: 50440"
echo "=============================="
