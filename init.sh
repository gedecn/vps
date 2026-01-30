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

    authorized_keys=$(prompt_input "SSH认证authorized_keys" "")
    newport=$(prompt_input "SSH端口号" "22")
    newpw=$(prompt_input "root用户新密码" "")

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
    systemctl enable sing-box

    echo "✓ 操作完成"
}

function traffic_check {

    echo "流量监控关机"

    limit=$(prompt_input "月度流量额度GB" "")
    server=$(prompt_input "服务器识别代号" "")
    bottoken=$(prompt_input "telegram机器人token" "")
    chatid=$(prompt_input "telegram机器人chat_id" "")

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
    update_and_install curl gnupg2 ca-certificates lsb-release
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 1000" | sudo tee /etc/apt/preferences.d/99nginx
    update_and_install nginx
    # 创建网站根目录
    mkdir -p "/data/wwwroot/default"
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

    cat > "/etc/nginx/conf.d/default.conf" <<EOF
server {
    listen 80;
    server_name _;
    root /data/wwwroot/default;
    access_log off;
    return 301 https://www.yourdomain.com\$request_uri;
}
#server {
#    listen 443 ssl;
#    server_name www.yourdomain.com;
#    root /data/wwwroot/www.yourdomain.com;
#    index index.php index.html index.htm;
#    access_log off;

#    ssl_certificate /etc/cert/www.yourdomain.com/cert.crt;
#    ssl_certificate_key /etc/cert/www.yourdomain.com/private.key;
#    ssl_protocols TLSv1.2 TLSv1.3;
#    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
#    ssl_prefer_server_ciphers off;

#    location / {
#        try_files \$uri \$uri/ /index.php?\$query_string;
#    }

#    location ~ \.php(/|$) {
#        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
#        fastcgi_index index.php;
#        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
#        include fastcgi_params;
#    }
#}
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
    update_and_install "$phpv-fpm" "$phpv-cli" "$phpv-redis" "$phpv-mbstring" "$phpv-mysql" "$phpv-gd" "$phpv-curl" "$phpv-xml" "$phpv-imagick"

    sudo systemctl restart "$phpv-fpm"
    sudo systemctl enable "$phpv-fpm"
}

# Redis安装和配置
function redis_install {
    update_and_install redis-server

    sudo systemctl restart redis-server
    sudo systemctl enable redis-server

    redis-server --version
}

# MariaDB安装和配置
function mariadb_install {
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/mariadb.gpg
    echo "deb [signed-by=/etc/apt/keyrings/mariadb.gpg] https://mariadb.org/repo/11.8.5/debian $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mariadb.list
    sudo apt update
    sudo apt install mariadb-server mariadb-client
    sudo mariadb-secure-installation
    sudo systemctl enable --now mariadb
}


function main_menu {

    #标准输入
    echo
    echo
    cat <<'EOF'
功能菜单:
1)  系统升级
2)  SSH安全配置
3)  安装sing-box
4)  流量tg监控
5)  修改hostname
6)  安装nginx
7)  安装php8
8)  安装redis7
9)  安装mariadb
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
          1)
            sys_update
          ;;
          2)
            ssh_security
          ;;
          3)
            sb_install
          ;;
          4)
            traffic_check
          ;;
          5)
            hostname_change
          ;;
          6)
            nginx_install
          ;;
          7)
            php_install
          ;;
          8)
            redis_install
          ;;
          9)
            mariadb_install
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
