#!/bin/bash
#VPS常用脚本命令
#bash <(wget -qO- https://raw.githubusercontent.com/gedecn/vps/main/init.sh)


input_file="vps_config.txt"
# 检查文件是否存在，如果不存在则创建一个空文件
if [ ! -f "$input_file" ]; then
    touch "$input_file"
fi

# 函数用于将用户输入的key:value保存到文件，如果key已存在则更新对应的value
save_input() {
    local key=$1
    local value=$2

    fstr="$key="
    rstr="$key=$value"

    if grep -q "^$key=" "$input_file"; then
        sed -i "s|.*$fstr.*|$rstr|g" "$input_file"
    else
        echo "$key=$value" >> "$input_file"
    fi
}

# 函数用于根据key从文件中读取对应的value
read_value() {
    local key=$1
    local value

    value=$(grep "^$key=" "$input_file" | awk -F '=' '{print $2}' | tr -d '\r')
    echo -n "$value"
}

prompt_input() {
    local prompt=$1
    local default=$2
    local value=""

    result=$(read_value "$prompt")

    while [[ -z "$value" ]]; do

        # 打印提示信息并读取用户输入
        read -r -p "$prompt [$default][$result]: " value

        value=${value:-$result}
        value=${value:-$default}
    done
    echo $value

    save_input "$1" "$value"
}

function sys_update {

    echo "安装必须软件"
    apt update
    apt upgrade -y
    #apt dist-upgrade -y
    #apt full-upgrade -y
    apt autoremove -y
    apt install curl wget sudo psmisc cron unzip net-tools dnsutils rsync vnstat bc -y
    timedatectl set-timezone Asia/Shanghai

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

    # Restart SSH service
    #sshd 对 socket 的依赖
    #mv /etc/systemd/system/ssh.service.d/ /etc/systemd/system/ssh.service.d.disabed/
    #systemctl disable --now ssh.socket
    #systemctl enable  --now ssh.service
    #systemctl restart ssh.service
    systemctl restart sshd

    echo "✓ 操作完成"
}

function bbr_open {

    echo "开启BBR和优化网络参数"

    #调整网络参数
    cat <<EOF > /etc/sysctl.conf
# Switch to Google BBR congestion control algorithm
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF


    #参数生效
    sysctl -p

    echo "✓ 操作完成"
}

function cert_make {

    echo "生成bing.com的证书"

    [ ! -d /etc/cert/bing.com ] && mkdir -p /etc/cert/bing.com
    openssl ecparam -genkey -name prime256v1 -out /etc/cert/bing.com/private.key
    openssl req -new -x509 -days 3650 -key /etc/cert/bing.com/private.key -out /etc/cert/bing.com/cert.crt -subj "/CN=bing.com"

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

    # Generate certificate
    cert_make

    # Create directory if not exists
    [ ! -d /etc/sing-box ] && mkdir -p /etc/sing-box

    # User inputs
    hysteria2_port=$(prompt_input "hysteria2 udp port" 1443)
    vless_port=$(prompt_input "vless tcp port" 1443)
    socks_port=$(prompt_input "socks5 port" 1444)

    tuic_port=$(prompt_input "tuic udp port" 8443)
    vless_ws_port=$(prompt_input "vless ws tcp port" 8443)
    
    ss_port=$(prompt_input "shadowsocks port" 10443)
    #ss_method=$(prompt_input "shadowsocks method" "aes-256-gcm")
    #ss_password=$(prompt_input "shadowsocks password" "")

    uuid=$(prompt_input "uuid" "")
    reality_private=$(prompt_input "reality private_key" "")
    reality_short_id=$(prompt_input "reality short_id" "")
    reality_server=$(prompt_input "reality server" "")
    vless_path=$(prompt_input "vless ws path" "cf8443")

    # Configure sing-box
    cat <<EOF > /etc/sing-box/config.json
{
    "log": {
        "disabled": true,
        "level": "error",
        "timestamp": true
    },
    "inbounds": [
EOF

if [ "$socks_port" != "none" ]; then
    cat <<EOF >> /etc/sing-box/config.json
        {
            "type": "socks",
            "listen": "::",
            "listen_port": $socks_port,
            "users": [
                {
                    "username": "$uuid",
                    "password": "$uuid"
                }
            ]
        },
EOF
fi

if [ "$tuic_port" != "none" ]; then
    cat <<EOF >> /etc/sing-box/config.json
        {
            "type": "tuic",
            "listen": "::",
            "listen_port": $tuic_port,
            "users": [
                {
                    "uuid": "$uuid",
                    "password": "$uuid"
                }
            ],
            "congestion_control": "bbr",
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "/etc/cert/bing.com/cert.crt",
                "key_path": "/etc/cert/bing.com/private.key"
            }
        },
EOF
fi

if [ "$hysteria2_port" != "none" ]; then
    cat <<EOF >> /etc/sing-box/config.json
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": $hysteria2_port,
            "users": [
                {
                    "password": "$uuid"
                }
            ],
            "masquerade": "https://bing.com",
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "/etc/cert/cert.crt",
                "key_path": "/etc/cert/private.key"
            }
        },
EOF
fi

if [ "$vless_port" != "none" ]; then
    cat <<EOF >> /etc/sing-box/config.json
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
                "server_name": "$reality_server",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "$reality_server",
                        "server_port": 443
                    },
                    "private_key": "$reality_private",
                    "short_id": ["$reality_short_id"]
                }
            }
        },
EOF
fi

if [ "$vless_ws_port" != "none" ]; then
    cat <<EOF >> /etc/sing-box/config.json
        {
            "type": "vless",
            "listen": "::",
            "listen_port": $vless_ws_port,
            "users": [
                {
                    "name": "$uuid",
                    "uuid": "$uuid"
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/$vless_path"
            }
        },
EOF
fi


    cat <<EOF >> /etc/sing-box/config.json
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

# Function to download and install sing-box
install_sing_box() {
    local ver=$1
    wget https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-amd64.tar.gz
    tar -zxvf sing-box-${ver}-linux-amd64.tar.gz
    mv /root/sing-box-${ver}-linux-amd64/sing-box /usr/bin/sing-box
    mkdir -p /var/lib/sing-box
}

# Function to create systemd service for sing-box
create_systemd_service() {

    cat << 'EOF' > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
}

function sb_install_ver {

    # Main script
    ver=$(prompt_input "sing-box version" "1.8.9")

    echo "开始下载并安装 sing-box 版本: $ver"

    # Download and install sing-box
    install_sing_box $ver

    # Create systemd service for sing-box
    create_systemd_service

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

# 计算每分钟应该消耗的最大流量（MB）
total_minutes=\$((30*24*60))  # 修正为整数计算
max_consumption_per_min=\$(echo "scale=2; \$limit * 1024 / \$total_minutes" | bc)  # 转换为MB

# 推送Telegram Bot
curl -X POST "https://api.telegram.org/bot$bottoken/sendMessage" \
-F "chat_id=$chatid" \
-F "text=\${server} [每分 \${consumption_per_min} MB / \${max_consumption_per_min} MB] [流量 \${traffic_gb} / \${limit} GB / \${usage_ratio}%]"
EOF

    #增加执行权限
    chmod +x /root/traffic_check.sh

    # Prompt user for interval in minutes
    interval=$(prompt_input "interval in minutes" "10")
    #添加计划任务
    cron_add "traffic_check" "*/$interval * * * * /root/traffic_check.sh > /root/traffic_check.log"

    echo "✓ 操作完成"
}

function ufw_cron {

    echo "定时开关防火墙"

    allowport=$(prompt_input "ssh port" "22")
    hstart=$(prompt_input "firewall enable time (format: minute hour)" "0 1")
    hend=$(prompt_input "firewall disable time (format: minute hour)" "0 7")

    #安装ufw
    apt install ufw -y
    
    #只允许ssh
    ufw allow $allowport
    ufw default allow outgoing
    ufw default deny incoming

    #时区
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    cron_add "ufw --force enable" "$hstart * * * /usr/sbin/ufw --force enable >> /root/log_ufw.log"
    cron_add "ufw disable" "$hend * * * /usr/sbin/ufw disable >> /root/log_ufw.log"

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

function noip_ddns {

    echo "安装noip ddns"

    ddnsusername=$(prompt_input "DDNS key username" "")
    ddnspassword=$(prompt_input "DDNS key password" "")

    wget https://dmej8g5cpdyqd.cloudfront.net/downloads/noip-duc_3.0.0.tar.gz
    tar xf noip-duc_3.0.0.tar.gz
    cd noip-duc_3.0.0/binaries && sudo apt install ./noip-duc_3.0.0_amd64.deb

    noip-duc --daemonize -g all.ddnskey.com --username $ddnsusername --password $ddnspassword

    echo "✓ 操作完成"
}

function juicity_install {

    echo "安装juicity"

    #生成证书
    cert_make

    uuid=$(prompt_input "uuid" "")
    version=$(prompt_input "juicity version" "v0.4.0")
    juicity_port=$(prompt_input "juicity port" "8444")

    wget https://github.com/juicity/juicity/releases/download/${version}/juicity-linux-x86_64.zip
    unzip juicity-linux-x86_64.zip -d juicity
    cp ./juicity/juicity-server /usr/local/bin

    #配置文件
    [ ! -d /etc/juicity ] && mkdir -p /etc/juicity

    cat <<EOF > /etc/juicity/server.json
{
    "listen": ":$juicity_port",
    "users": {
        "$uuid": "$uuid"
    },
    "certificate": "/etc/cert/bing.com/cert.crt",
    "private_key": "/etc/cert/bing.com/private.key",
    "congestion_control": "bbr",
    "disable_outbound_udp443": true,
    "log_level": "error"
}
EOF

    #增加服务
    cat <<'EOF' > /etc/systemd/system/juicity.service
[Unit]
Description=juicity-server Service
Documentation=https://github.com/juicity/juicity
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/juicity-server run -c /etc/juicity/server.json --disable-timestamp
Restart=on-failure
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable juicity
    systemctl start juicity
    systemctl status juicity

    echo "✓ 操作完成"
}

function juicity_uninstall {
    echo "卸载juicity"

    systemctl stop juicity
    systemctl disable juicity
    rm -f /usr/local/bin/juicity-server
    rm -rf /etc/juicity

    echo "✓ 操作完成"
}

function hy2_install {
    echo "安装Hysteria 2"

    bash <(curl -fsSL https://get.hy2.sh/)

    hy2domain=$(prompt_input "Hysteria 2 domain" "")
    hy2mail=$(prompt_input "Hysteria 2 email" "")
    hy2password=$(prompt_input "password" "")
    hy2port=$(prompt_input "Hysteria 2 port" "443")

    [ ! -d /etc/hysteria ] && mkdir -p /etc/hysteria
    cat <<EOF > /etc/hysteria/config.yaml
listen: :$hy2port

acme:
  domains:
    - $hy2domain
  email: $hy2mail

auth:
  type: password
  password: $hy2password

masquerade: 
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF

    systemctl enable hysteria-server.service
    systemctl restart hysteria-server.service
    systemctl status hysteria-server.service

    echo "✓ 操作完成"
}

function hy2_uninstall {

    echo "卸载Hysteria 2"

    systemctl stop hysteria-server.service
    systemctl disable hysteria-server.service
    rm -f /usr/local/bin/hysteria-server
    rm -rf /etc/hysteria

    echo "✓ 操作完成"
}

function cf_ddns {

    echo "cloudflare 动态DDNS"

    auth_email=$(prompt_input "cloudflare email" "")
    api_token=$(prompt_input "cloudflare API Token" "")
    zone_name=$(prompt_input "cloudflare zone name" "example.com")
    record_name=$(prompt_input "cloudflare record name" "my.example.com")

    curl https://raw.githubusercontent.com/Leao9203/cloudflare-api-v4-ddns/dev/cf-v4-ddns.sh > /usr/local/bin/cf-ddns.sh
    chmod +x /usr/local/bin/cf-ddns.sh

    cat <<EOF > /root/cloudflare_ddns.sh
#!/bin/bash
/usr/local/bin/cf-ddns.sh -a $api_token \
-u $auth_email \
-h $record_name \
-z $zone_name \
-t A
EOF
    chmod +x /root/cloudflare_ddns.sh
    #添加计划任务
    cron_add "cloudflare_ddns" "*/5 * * * * /root/cloudflare_ddns.sh > /root/cloudflare_ddns.log"

    echo "✓ 操作完成"
}

function dd_os {

    os_name=$(prompt_input "dd os" "debian 12")

    wget --no-check-certificate -qO InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' && chmod a+x InstallNET.sh
    bash InstallNET.sh -$os_name --network "dhcp"
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

# 替换Nginx配置文件中的用户的函数
function replace_nginx_user {

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
    # Use multi_accept to accept as many connections as possible
    multi_accept on;
    # Use epoll (Linux 2.6+), if your platform supports it
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log off;
    error_log /dev/null crit;

    sendfile on;
    tcp_nopush on; # Enable to send files in one piece, without partial frames
    tcp_nodelay on; # Enable to send responses at once, without waiting for more data

    keepalive_timeout 65;
    keepalive_requests 100; # Limit the number of requests that can be sent over a single keepalive connection

    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Increase client body size to allow for large file uploads
    client_max_body_size 10M;

    # Buffer sizes
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 32k;

    # Timeouts
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;

    include /etc/nginx/conf.d/*.conf;
}
EOF

    # 检查 Nginx 配置文件是否有语法错误
    sudo nginx -t
}

# 创建nginx站点配置文件的函数
function create_nginx_site_config {
    local domain=$1
    local webroot=$2
    local ssl_cert=$3
    local ssl_key=$4

    # 定义通用的 Nginx 配置
    cat > "/etc/nginx/conf.d/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    root $webroot/$domain;
    access_log off;
    index index.html index.htm;
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # 如果提供了 SSL 证书和密钥，配置 HTTPS
    if [[ -n $ssl_cert && -n $ssl_key ]]; then

        phpfpm=$(prompt_input "PHP-FPM version" "php8.2-fpm")

        cat > "/etc/nginx/conf.d/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    access_log off;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $domain;
    root $webroot/$domain;
    index index.php index.html index.htm;
    access_log off;

    ssl_certificate $ssl_cert;
    ssl_certificate_key $ssl_key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php(/|$) {
        fastcgi_pass unix:/run/php/$phpfpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
    fi

    # 测试 Nginx 配置是否正确
    sudo nginx -t

    if [ $? -eq 0 ]; then
        # 重载 Nginx 服务
        sudo systemctl reload nginx
        echo "Nginx configuration for $domain has been created and reloaded successfully."
    else
        echo "Error in Nginx configuration. Please check the logs."
    fi
}


# Nginx安装和配置
function nginx_install {
    domain=$(prompt_input "your domain (xxx.com)" "")
    webroot=$(prompt_input "nginx web root path" "/data/wwwroot")

    update_and_install curl gnupg2 ca-certificates lsb-release
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 1000" | sudo tee /etc/apt/preferences.d/99nginx

    update_and_install nginx

    # 创建网站根目录
    mkdir -p "$webroot/$domain"

    # 删除默认的 Nginx 配置
    sudo rm -f /etc/nginx/conf.d/default.conf

    replace_nginx_user
    create_nginx_site_config "$domain" "$webroot"

    sudo systemctl enable nginx
    sudo systemctl start nginx
}

# PHP安装和配置
function php_install {
    phpv=$(prompt_input "php version" "php8.4")

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
    webroot=$(prompt_input "nginx web root path" "/data/wwwroot")
    domain=$(prompt_input "Your domain (xxx.com)" "")
    email=$(prompt_input "Your domain email" "")

    create_nginx_site_config "$domain" "$webroot"
    sudo systemctl restart nginx

    # 安装 acme.sh 如果未安装
    curl https://get.acme.sh | sh -s email="$email"

    # 设置默认 CA 为 Let's Encrypt
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # 创建证书存储目录
    mkdir -p "/etc/cert/$domain"

    /root/.acme.sh/acme.sh --force --issue -d "$domain" -w "$webroot/$domain" --debug
    /root/.acme.sh/acme.sh --installcert -d "$domain" \
        --key-file "/etc/cert/$domain/private.key" \
        --fullchain-file "/etc/cert/$domain/cert.crt"

    # 创建并重载 nginx 配置
    create_nginx_site_config "$domain" "$webroot" "/etc/cert/$domain/cert.crt" "/etc/cert/$domain/private.key"
    sudo systemctl restart nginx

    echo "SSL certificate installation completed for $domain."
}

function db_backup {

    DB_USER=$(prompt_input "DB USER" "")
    DB_PASSWORD=$(prompt_input "DB PASSWORD" "")
    DB_NAME=$(prompt_input "DB NAME" "")
    cronttime=$(prompt_input "cron time (format: minute hour)" "0 1")

    cat <<EOF > /root/mysql_backup.sh
#!/bin/bash

# MySQL数据库相关配置
DB_USER="$DB_USER"
DB_PASSWORD="$DB_PASSWORD"
DB_NAME="$DB_NAME"

# 备份文件存储路径及文件名
BACKUP_DIR="/root/backup/"
mkdir -p \$BACKUP_DIR
DATE=\$(date +%Y%m%d)
BACKUP_FILE="\$BACKUP_DIR\$DB_NAME-\$DATE.sql.gz"

# 备份数据库
mysqldump -u\$DB_USER -p\$DB_PASSWORD \$DB_NAME | gzip > \$BACKUP_FILE

# 检查备份是否成功
if [ \$? -eq 0 ]; then
    echo "Database backup completed successfully."
else
    echo "Database backup failed."
fi
exit 0
EOF

    chmod +x /root/mysql_backup.sh
    #添加计划任务
    cron_add "mysql_backup" "$cronttime * * * /root/mysql_backup.sh > /root/mysql_backup.log"
}

function oss_backup {
    #安装阿里云CLI
    FILE_URL="https://aliyuncli.alicdn.com/aliyun-cli-linux-latest-amd64.tgz"
    LOCAL_FILE="/root/aliyun-cli-linux-latest-amd64.tgz"

    # 检查文件是否已存在
    if [ -f "$LOCAL_FILE" ]; then
        echo "File '$LOCAL_FILE' already exists. Skipping download."
    else
        echo "Downloading the latest Aliyun CLI..."
        wget -q "$FILE_URL" -O "$LOCAL_FILE"
        if [ $? -eq 0 ]; then
            echo "Download of Aliyun CLI successful."
        else
            echo "Failed to download Aliyun CLI."
            exit 1
        fi
    fi

    tar xzvf aliyun-cli-linux-latest-amd64.tgz
    sudo mv aliyun /usr/local/bin

    
    OSS_BUCKET=$(prompt_input "OSS BUCKET" "")
    OSS_REGION=$(prompt_input "OSS REGION" "")
    OSS_PATH=$(prompt_input "OSS PATH" "")

    AccessKeyId=$(prompt_input "OSS AccessKeyId" "")
    AccessKeySecret=$(prompt_input "OSS AccessKeySecret" "")

    cronttime=$(prompt_input "cron time (format: minute hour)" "0 1")

cat <<EOF > /root/oss_backup.sh
#!/bin/bash

# OSS相关配置
OSS_BUCKET="$OSS_BUCKET"
OSS_REGION="$OSS_REGION"
OSS_PATH="$OSS_PATH"
AccessKeyId="$AccessKeyId"
AccessKeySecret="$AccessKeySecret"

# 备份文件存储路径及文件名
BACKUP_DIR="/root/backup/"
DATE=\$(date +%Y%m%d)
BACKUP_FILE="\$BACKUP_DIR\$DB_NAME-\$DATE.sql.gz"

# 使用阿里云CLI上传到OSS
aliyun configure set --profile akProfile --mode AK --region \$OSS_REGION --access-key-id \$AccessKeyId --access-key-secret \$AccessKeySecret
aliyun oss cp -f \$BACKUP_FILE oss://\$OSS_BUCKET/\$OSS_PATH/\$DB_NAME-\$DATE.sql.gz --region \$OSS_REGION --profile akProfile --update

if [ \$? -eq 0 ]; then
    echo "Backup file uploaded to Alibaba Cloud OSS successfully."
    rm -f \$BACKUP_FILE
else
    echo "Failed to upload the backup file to Alibaba Cloud OSS."
fi

exit 0
EOF

    chmod +x /root/oss_backup.sh
    #添加计划任务
    cron_add "oss_backup" "$cronttime * * * /root/oss_backup.sh > /root/oss_backup.log"
}

function aliyun_backup {
    #安装阿里云盘客户端
    sudo curl -fsSL http://file.tickstep.com/apt/pgp | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/tickstep-packages-archive-keyring.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/tickstep-packages-archive-keyring.gpg arch=amd64,arm64] http://file.tickstep.com/apt aliyunpan main" | sudo tee /etc/apt/sources.list.d/tickstep-aliyunpan.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y aliyunpan

    #登录云盘
    aliyunpan login

    backuppath=$(prompt_input "backup file path" "")
    cronttime=$(prompt_input "cron time (format: minute hour)" "0 1")

    #北京时间凌晨5点
    cron_add "aliyunpan upload" "$cronttime * * * /bin/bash -c 'aliyunpan upload $backuppath /backup/\$(date +\%Y\%m\%d)'"
    #所有备份保留7天
    cron_add "aliyunpan rm" "0 20 * * * /bin/bash -c 'aliyunpan rm /backup/\$(date --date=\"7 days ago\" +\%Y\%m\%d)'"
}

function realm_install {

    #https://github.com/zhboner/realm/releases
    realmreleases=$(prompt_input "realm releases" "v2.5.4")
    realmlistenport=$(prompt_input "realm listen port" "2443")
    realmremote=$(prompt_input "realm remote" "102.129.195.130:1443")

    wget -O realm.tar.gz https://github.com/zhboner/realm/releases/download/$realmreleases/realm-x86_64-unknown-linux-gnu.tar.gz
    tar -xvf realm.tar.gz
    chmod +x realm

    cat <<EOF > /root/realm_config.toml
[log]
level = "off"
[network]
use_udp = true
[[endpoints]]
listen = "0.0.0.0:$realmlistenport"
remote = "$realmremote"
EOF

    cat <<EOF > /etc/systemd/system/realm.service
[Unit]
Description=realm
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
DynamicUser=true
WorkingDirectory=/root
ExecStart=/root/realm -c /root/realm_config.toml

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable realm
    systemctl restart realm
    systemctl status realm

}

function gost_install {
    listen_port=$(prompt_input "listen port" 1443)
    node_ip_port=$(prompt_input "node ip and port" "")

    socks_port=$(prompt_input "socks5 port" 1444)
    uuid=$(prompt_input "uuid" "")
    ss_port=$(prompt_input "shadowsocks port" 10443)

    bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install

    cat <<EOF > /root/gost_config.yml
services:
EOF

if [ "$listen_port" != "none" ]; then
    cat <<EOF >> /root/gost_config.yml
- name: service-0
  addr: :$listen_port
  handler:
    type: tcp
  listener:
    type: tcp
  forwarder:
    nodes:
    - name: target-0
      addr: $node_ip_port
EOF
fi

if [ "$socks_port" != "none" ]; then
    cat <<EOF >> /root/gost_config.yml
- name: service-socks5
  addr: ":$socks_port"
  handler:
    type: socks5
    auth:
      username: "$uuid"
      password: "$uuid"
  listener:
    type: tcp
EOF
fi

if [ "$ss_port" != "none" ]; then
    cat <<EOF >> /root/gost_config.yml
- name: service-ss
  addr: ":$ss_port"
  handler:
    type: ss
    auth:
      username: aes-256-gcm
      password: "$uuid"
  listener:
    type: tcp
EOF
fi

cat <<EOF >> /root/gost_config.yml
log:
  output: none
  level: error
EOF

    cat <<EOF > /etc/systemd/system/gost.service
[Unit]
Description=GO Simple Tunnel
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -C /root/gost_config.yml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable gost
    systemctl start gost
    systemctl status gost
}

function dns_change {
    
    # 修改 /etc/dhcp/dhclient.conf 文件
    echo "supersede domain-name-servers 1.1.1.1, 8.8.8.8, 8.8.4.4;" | sudo tee -a /etc/dhcp/dhclient.conf

    # 备份 /etc/resolv.conf 文件
    sudo cp /etc/resolv.conf /etc/resolv.conf.bak
    echo "已备份 /etc/resolv.conf 到 /etc/resolv.conf.bak"

    # 修改 /etc/resolv.conf 文件
    sudo bash -c 'cat > /etc/resolv.conf << EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF'

    # 重启网络服务以应用更改
    sudo systemctl restart networking.service

    # 输出当前DNS设置以验证
    echo "当前DNS设置:"
    cat /etc/resolv.conf
}

function main_menu {

    #标准输入
    echo
    echo
    cat <<'EOF'

    功能菜单:
    11)  安装必须软件
    12)  SSH安全配置
    13)  开启BBR和网络优化
    14)  安装正式版sing-box
    15)  安装指定版本sing-box
    16)  ipv6 warp脚本
    17)  swap脚本
    18)  vnstat流量监控关机脚本
    19)  ufw定时开关防火墙
    20)  noip动态DDNS
    21)  安装juicity
    22)  打印本地配置
    23)  安装Hysteria 2
    24)  安装X-UI
    25)  安装3X-UI
    26)  cloudflare 动态DDNS
    27)  DD系统
    28)  科技lion脚本
    29)  安装realm转发
    30)  修改hostname
    31)  申请SSL证书
    32)  数据库导出备份
    33)  备份到阿里云OSS
    34)  备份到阿里云盘
    35)  安装哪吒面板
    36)  安装S-UI
    37)  安装nginx
    38)  安装php8
    39)  安装mysql8
    40)  安装redis7
    41)  安装gost
    42)  修改dns
    90)  卸载juicity
    91)  卸载sing-box
    92)  卸载Hysteria 2
    0)  退出

EOF
}


while [ 2 -gt 0 ]
  do
  main_menu
  echo -n "请选择: "
  read main_choice
  echo
  case $main_choice in
          11)
            sys_update
          ;;
          12)
            ssh_security
          ;;
          13)
            bbr_open
          ;;
          14)
            sb_install
            sb_config
          ;;
          15)
            sb_install_ver
            sb_config
          ;;
          16)
            bash <(wget -qO- https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh)
          ;;
          17)
            bash <(wget -qO- https://www.moerats.com/usr/shell/swap.sh)
          ;;
          18)
            traffic_check
          ;;
          19)
            ufw_cron
          ;;
          20)
            noip_ddns
          ;;
          21)
            juicity_install
          ;;
          22)
            cat $input_file
          ;;
          23)
            hy2_install
          ;;
          24)
            bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh) 0.3.4.4
          ;;
          25)
            bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
          ;;
          26)
            cf_ddns
          ;;
          27)
            dd_os
          ;;
          28)
            curl -sS -O https://raw.githubusercontent.com/kejilion/sh/main/kejilion.sh
            chmod +x kejilion.sh
            ./kejilion.sh
          ;;
          29)
            realm_install
          ;;
          30)
            hostname_change
          ;;
          31)
            ssl_install
          ;;
          32)
            db_backup
          ;;
          33)
            oss_backup
          ;;
          34)
            aliyun_backup
          ;;
          35)
            curl -L https://raw.githubusercontent.com/naiba/nezha/master/script/install.sh -o nezha.sh
            chmod +x nezha.sh
            sudo ./nezha.sh
          ;;
          36)
            bash <(curl -Ls https://raw.githubusercontent.com/alireza0/s-ui/master/install.sh)
          ;;
          37)
            nginx_install
          ;;
          38)
            php_install
          ;;
          39)
            mysql_install
          ;;
          40)
            redis_install
          ;;
          41)
            gost_install
          ;;
          42)
            dns_change
          ;;
          90)
            juicity_uninstall
          ;;
          91)
            sb_uninstall
          ;;
          92)
            hy2_uninstall
          ;;
          0)
            exit
          ;;
          *)
          clear
          continue
          ;;
  esac
done
