#!/bin/bash
#VPS常用脚本命令
#bash <(wget -qO- https://raw.githubusercontent.com/gedecn/vps/main/init.sh)

prompt_input() {
    local prompt=$1
    local default=$2
    local value=""
    while [[ -z "$value" ]]; do
        # 打印提示信息并读取用户输入
        read -r -p "$prompt [$default]: " value
        value=${value:-$default}
    done
    echo $value
}

function sys_update {

    echo "安装必须软件"

    apt update
    apt upgrade -y
    apt autoremove -y
    apt install curl wget sudo psmisc cron unzip net-tools dnsutils rsync vnstat bc -y
    timedatectl set-timezone Asia/Shanghai

    echo "开启BBR和优化网络参数"

    #调整网络参数
    cat <<EOF > /etc/sysctl.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

    #参数生效
    sysctl -p

    echo "✓ 操作完成"
}

function ssh_security {

    echo "配置SSH安全"

    authorized_keys=$(prompt_input "ssh authorized_keys" "")
    newport=$(prompt_input "ssh port" "22")
    newpw=$(prompt_input "root password" "")

    echo "root:$newpw" | chpasswd

    cat <<EOF > /etc/ssh/sshd_config
Port $newport
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 2m
PermitRootLogin yes
StrictModes yes
MaxAuthTries 5
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 120
ClientAliveCountMax 10
PidFile /var/run/sshd.pid
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    # Write authorized keys
    [ ! -d /root/.ssh ] && mkdir -p /root/.ssh
    echo $authorized_keys > /root/.ssh/authorized_keys

    systemctl restart sshd

    echo "✓ 操作完成"
}

function sb_install {

    echo "安装sing-box正式版"
    #安装sing-box
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)

    echo "✓ 操作完成"
}

function sb_config {

    echo "配置sing-box"

    # Create directory if not exists
    [ ! -d /etc/sing-box ] && mkdir -p /etc/sing-box

    # User inputs
    domain_root=$(prompt_input "domain root" "")
    domain=$(prompt_input "domain" "")
    hysteria2_port=$(prompt_input "hysteria2 udp port" 1443)
    vless_port=$(prompt_input "vless tcp port" 1443)
    ss_port=$(prompt_input "shadowsocks port" 10443)
    uuid=$(prompt_input "uuid" "")
    reality_private=$(prompt_input "reality private_key" "")
    reality_short_id=$(prompt_input "reality short_id" "")

    # Configure sing-box
    cat <<EOF > /etc/sing-box/config.json
{
    "log": {
        "disabled": true,
        "level": "error",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": $hysteria2_port,
            "users": [
                {
                    "password": "$uuid"
                }
            ],
            "masquerade": "https://$domain",
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "/etc/cert/$domain_root/cert.crt",
                "key_path": "/etc/cert/$domain_root/private.key"
            }
        },
        {
            "type": "vless",
            "listen": "::",
            "listen_port": $vless_port,
            "users": [
                {
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "$domain",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "$domain",
                        "server_port": 443
                    },
                    "private_key": "$reality_private",
                    "short_id": ["$reality_short_id"]
                }
            }
        },
        {
            "type": "shadowsocks",
            "listen": "::",
            "listen_port": $ss_port,
            "method": "aes-256-gcm",
            "password": "$uuid"
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

    # Start sing-box service
    systemctl enable sing-box
    systemctl restart sing-box
    systemctl status sing-box

    echo "✓ 操作完成"
}

function sb_uninstall {

    echo "卸载sing-box"

    systemctl stop sing-box
    systemctl disable sing-box
    apt -y autoremove sing-box
    rm -rf /etc/sing-box

    echo "✓ 操作完成"
}

function traffic_check {

    echo "流量监控关机"

    limit=$(prompt_input "monthly outbound traffic in GB" "")
    server=$(prompt_input "server identification name" "")
    bottoken=$(prompt_input "telegram bot token" "")
    chatid=$(prompt_input "telegram bot chat_id" "")

    cat <<EOF > /root/traffic_check.sh
#!/bin/bash

limit=$limit
server="$server"
data_file="/root/traffic_data.txt"

# 获取当前流量
traffic=\$(vnstat --oneline b | awk -F';' '{print \$10}')
traffic_gb=\$(echo "scale=2; \$traffic / 1024 / 1024 / 1024" | bc)
echo "本月流量: \$traffic_gb GB, 流量限制: \$limit GB"

# 检查是否存在上次记录
if [ -f "\$data_file" ]; then
    read last_time last_traffic < "\$data_file"
    current_time=\$(date +%s)
    time_diff=\$((current_time - last_time))
    
    # 计算时间间隔（分钟）
    time_diff_min=\$((time_diff / 60))
    
    # 计算每分钟消耗的流量（MB）
    traffic_diff=\$(echo "\$traffic - \$last_traffic" | bc)
    if [ "\$time_diff_min" -gt 0 ]; then
        consumption_per_min=\$(echo "scale=2; \$traffic_diff / \$time_diff_min / 1024 / 1024" | bc)  # 转换为MB
    else
        consumption_per_min=0
    fi
    
    echo "上次流量: \$(echo "scale=2; \$last_traffic / 1024 / 1024 / 1024" | bc) GB, 时间间隔: \$time_diff_min 分钟, 每分钟消耗: \$consumption_per_min MB"
else
    echo "这是第一次运行，未找到上次记录"
fi

# 更新记录
echo "\$current_time \$traffic" > "\$data_file"

# 检查流量限制
if (( \$(echo "\$traffic_gb > \$limit" | bc -l) )); then
    echo "月流量超过 \$limit GB，自动关机"
    shutdown -h now
fi

# 计算进度条
usage_ratio=\$(echo "scale=2; \$traffic_gb / \$limit * 100" | bc)

# 推送Telegram Bot
curl -X POST "https://api.telegram.org/bot$bottoken/sendMessage" \
-F "chat_id=$chatid" \
-F "text=\${server} 已用 \${traffic_gb} / \${limit} GB / \${usage_ratio}%"
EOF

    #增加执行权限
    chmod +x /root/traffic_check.sh

    # Prompt user for interval in minutes
    interval=$(prompt_input "interval in minutes" "10")
    #添加计划任务
    cron_add "traffic_check" "*/$interval * * * * /root/traffic_check.sh > /root/traffic_check.log"

    echo "✓ 操作完成"
}

function cron_add {
    local fstr=$1
    local rstr=$2

    existing_job=$(crontab -l | grep "$fstr")
    if [ -z "$existing_job" ]; then
        # Add a new cron job to run /root/check.sh at the specified interval
        (crontab -l ; echo "$rstr") | crontab -
        echo "已添加计划任务"
    else
        # Modify the existing cron job to run /root/check.sh at the specified interval
        (crontab -l | sed "s|.*$fstr.*|$rstr|g") | crontab -
        echo "已修改计划任务"
    fi

    #展示计划任务
    crontab -l    
}

function hostname_change {
    echo "修改hostname"

    NEW_HOSTNAME=$(prompt_input "hostname" "")

    # 显示当前主机名
    CURRENT_HOSTNAME=$(hostname)
    echo "当前主机名: $CURRENT_HOSTNAME"

    # 更新 /etc/hostname 文件
    echo "$NEW_HOSTNAME" > /etc/hostname
    echo "/etc/hostname 文件已更新为: $NEW_HOSTNAME"

    # 更新 /etc/hosts 文件
    if grep -q "$CURRENT_HOSTNAME" /etc/hosts; then
    sed -i "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" /etc/hosts
    echo "/etc/hosts 文件中的 $CURRENT_HOSTNAME 已更新为 $NEW_HOSTNAME"
    else
    echo "127.0.1.1   $NEW_HOSTNAME" >> /etc/hosts
    echo "$NEW_HOSTNAME 已添加到 /etc/hosts 文件"
    fi

    # 使用 hostnamectl 设置新的主机名（适用于 systemd）
    hostnamectl set-hostname "$NEW_HOSTNAME"
    echo "hostnamectl 已将主机名设置为: $NEW_HOSTNAME"

    # 确保主机名立即生效
    hostname "$NEW_HOSTNAME"
    echo "主机名已立即生效: $NEW_HOSTNAME"

    echo "✓ 操作完成"
}


# 更新系统包索引和安装包的函数
function update_and_install {
    sudo apt update
    sudo apt install -y "$@"
}


# Nginx安装和配置
function nginx_install {
    domain_root=$(prompt_input "domain root" "")
    domain=$(prompt_input "domain" "")
    webroot=$(prompt_input "nginx web dir" "/data/wwwroot")

    update_and_install curl gnupg2 ca-certificates lsb-release
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 1000" | sudo tee /etc/apt/preferences.d/99nginx

    update_and_install nginx

    # 创建网站根目录
    mkdir -p "$webroot/$domain"

    # 删除默认的 Nginx 配置
    sudo rm -f /etc/nginx/conf.d/default.conf

    NGINX_CONF="/etc/nginx/nginx.conf"

    # 备份原始配置文件
    sudo cp $NGINX_CONF $NGINX_CONF.bak

    # 写入新的配置内容
    cat << EOF | sudo tee $NGINX_CONF > /dev/null
user www-data;
worker_processes auto;

error_log /var/log/nginx/error.log crit;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log off;
    error_log /var/log/nginx/error.log crit;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    keepalive_timeout 65;
    keepalive_requests 100;

    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    client_max_body_size 100M;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 32k;
    client_body_timeout 30;
    client_header_timeout 30;
    send_timeout 30;

    include /etc/nginx/conf.d/*.conf;
}
EOF

    cat > "/etc/nginx/conf.d/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    root $webroot/$domain;
    access_log off;
    return 301 https://$domain\$request_uri;
}
server {
    listen 443 ssl;
    server_name $domain;
    root $webroot/$domain;
    index index.php index.html index.htm;
    access_log off;

    ssl_certificate /etc/cert/$domain_root/cert.crt;
    ssl_certificate_key /etc/cert/$domain_root/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php(/|$) {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF

    sudo nginx -t
    sudo systemctl enable nginx
    sudo systemctl start nginx
}

# PHP安装和配置
function php_install {
    phpv=$(prompt_input "php version" "php8.2")

    sudo apt update
    sudo apt install -y ca-certificates lsb-release apt-transport-https
    sudo add-apt-repository ppa:ondrej/php
    update_and_install "$phpv-fpm" "$phpv-cli" "$phpv-redis" "$phpv-mbstring" "$phpv-mysql" "$phpv-gd" "$phpv-curl" "$phpv-xml"

    sudo systemctl restart "$phpv-fpm"
    sudo systemctl enable "$phpv-fpm"
}

# MySQL安装和配置
function mysql_install {
    update_and_install gnupg
    wget https://dev.mysql.com/get/mysql-apt-config_0.8.29-1_all.deb
    sudo dpkg -i mysql-apt-config_0.8.29-1_all.deb
    sudo apt -f install
    update_and_install mysql-server

    sudo systemctl stop mysql

    datadir=$(prompt_input "datadir" "/data/mysql")

    if [ "$datadir" != "/var/lib/mysql" ]; then
        sudo mkdir -p $datadir
        sudo rsync -av /var/lib/mysql/ $datadir
    fi

    cat << EOF | sudo tee /etc/mysql/mysql.conf.d/mysqld.cnf > /dev/null
[mysqld]
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
#datadir	= /var/lib/mysql
datadir		= $datadir
log-error	= /var/log/mysql/error.log
skip-log-bin
innodb_compression_level = 3
# 缓存大小设置
innodb_buffer_pool_size = 2G  # 设置为系统内存的 60%-80%，对于大多数工作负载
innodb_log_file_size = 256M   # 设置适合的大小，通常为 128M 或 256M
innodb_log_buffer_size = 16M  # 提高写性能
# 缓冲区和缓存设置
table_open_cache = 400       # 增加表缓存大小
table_definition_cache = 200 # 增加表定义缓存
# InnoDB 设置
innodb_flush_log_at_trx_commit = 2  # 改善写性能，可能会略微降低数据一致性
innodb_thread_concurrency = 0       # 让 InnoDB 自动管理线程并发
# I/O 设置
innodb_io_capacity = 2000           # 根据你的硬盘性能进行调整
innodb_io_capacity_max = 4000
# 日志设置
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2                 # 记录执行时间超过 2 秒的查询
# 其他设置
tmp_table_size = 64M                # 增加临时表大小
max_heap_table_size = 64M           # 增加内存临时表大小
max_connections = 500               # 增加最大连接数
thread_cache_size = 50              # 提高线程缓存，提高连接性能
# 文件和表设置
max_allowed_packet = 64M            # 增加最大允许的包大小
open_files_limit = 65535            # 增加打开文件的限制
#bind-address = 0.0.0.0
character-set-server=utf8mb4
collation-server=utf8mb4_unicode_ci
default_authentication_plugin=mysql_native_password
[client]
default-character-set=utf8mb4
default_authentication_plugin=mysql_native_password
EOF

    sudo systemctl start mysql
    sudo systemctl enable mysql
    sudo mysql_secure_installation
}

# Redis安装和配置
function redis_install {
    update_and_install redis-server

    sudo systemctl restart redis-server
    sudo systemctl enable redis-server

    redis-server --version
}

# SSL证书安装和配置
function ssl_install {
    # 获取用户输入
    cftoken=$(prompt_input "CF_Token" "")
    domain_root=$(prompt_input "domain root" "")
    email=$(prompt_input "email" "")

    # 安装 acme.sh 如果未安装
    curl https://get.acme.sh | sh -s email="$email"

    # 创建证书存储目录
    mkdir -p "/etc/cert/$domain_root"

    export CF_Token="$cftoken"
    /root/.acme.sh/acme.sh --force --issue --server letsencrypt -d "$domain_root" -d "*.$domain_root" --dns dns_cf --keylength ec-256
    /root/.acme.sh/acme.sh --installcert -d "$domain_root" --key-file "/etc/cert/$domain_root/private.key" --fullchain-file "/etc/cert/$domain_root/cert.crt"

    echo "SSL certificate installation completed"
}

function main_menu {

    #标准输入
    echo
    echo
    cat <<'EOF'

    功能菜单:
    1)  系统升级
    2)  SSH安全配置
    3)  申请ssl证书
    4)  安装sing-box
    5)  配置sing-box
    6)  卸载sing-box
    7)  流量tg监控
    8)  修改hostname
    9)  安装nginx
    10)  安装php8
    11)  安装mysql8
    12)  安装redis7
    13)  退出
EOF
}


while [ 2 -gt 0 ]
  do
  main_menu
  echo -n "请选择: "
  read main_choice
  echo
  case $main_choice in
          1)
            sys_update
          ;;
          2)
            ssh_security
          ;;
          3)
            ssl_install
          ;;
          4)
            sb_install
          ;;
          5)
            sb_config
          ;;
          6)
            sb_uninstall
          ;;
          7)
            traffic_check
          ;;
          8)
            hostname_change
          ;;
          9)
            nginx_install
          ;;
          10)
            php_install
          ;;
          11)
            mysql_install
          ;;
          12)
            redis_install
          ;;
          13)
            exit
          ;;
          *)
          clear
          continue
          ;;
  esac
done
