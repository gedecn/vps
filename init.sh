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
        read -p "$prompt [$default][$result]: " value

        value=${value:-$result}
        value=${value:-$default}
    done
    echo $value

    save_input "$1" "$value"
}

function sys_update {

    echo "安装必须软件"
    apt update
    #apt upgrade -y
    #apt dist-upgrade -y
    #apt full-upgrade -y
    #apt autoremove -y
    apt install curl wget sudo psmisc cron pwgen unzip net-tools -y
    apt install vnstat bc -y

    echo "✓ 操作完成"
}

function ssh_security {
    echo "配置SSH安全"

    authorized_keys=$(prompt_input "ssh authorized_keys" "")
    newport=$(prompt_input "ssh port" "22")
    newpw=$(prompt_input "root password" $(pwgen -s 12 1))

    echo "root:$newpw" | chpasswd

    cat <<EOF > /etc/ssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf
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
    mv /etc/systemd/system/ssh.service.d/ /etc/systemd/system/ssh.service.d.disabed/
    systemctl disable --now ssh.socket
    systemctl enable  --now ssh.service
    systemctl restart ssh.service

    echo "✓ 操作完成"
}

function bbr_open {

    echo "开启BBR和优化网络参数"

    qdisc=$(prompt_input "net core default_qdisc(fq_pie|fq)" "fq")

    #调整网络参数
    cat <<EOF > /etc/sysctl.conf
# Switch to Google BBR congestion control algorithm
net.core.default_qdisc = $qdisc
net.ipv4.tcp_congestion_control = bbr
EOF

    # Ask the user if they want to enable IPv6
    choice=$(prompt_input "enable IPv6 yes or no" "no")

    if [ "$choice" = "yes" ]; then
        cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.eth0.autoconf = 0
net.ipv6.conf.eth0.accept_ra = 0
EOF
    fi

    #参数生效
    sysctl -p

    echo "✓ 操作完成"
}

function cert_make {

    echo "生成bing.com的证书"

    [ ! -d /root/cert ] && mkdir -p /root/cert
    openssl ecparam -genkey -name prime256v1 -out /root/cert/private.key
    openssl req -new -x509 -days 3650 -key /root/cert/private.key -out /root/cert/cert.pem -subj "/CN=bing.com"

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
    socks_port=$(prompt_input "socks5 port" 8444)
    hysteria2_port=$(prompt_input "hysteria2 udp port" 443)
    vless_port=$(prompt_input "vless tcp port" 443)
    tuic_port=$(prompt_input "tuic udp port" 8443)
    vmess_port=$(prompt_input "vmess tcp port" 8443)

    uuid=$(prompt_input "uuid" "")
    reality_private=$(prompt_input "reality private_key" "")
    reality_short_id=$(prompt_input "reality short_id" "")
    reality_server=$(prompt_input "reality server" "")
    vmess_path=$(prompt_input "vmess ws path" "cf8443")

    # Configure sing-box
    cat <<EOF > /etc/sing-box/config.json
{
    "log": {
        "disabled": false,
        "level": "error",
        "timestamp": true
    },
    "inbounds": [
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
                "certificate_path": "/root/cert/cert.pem",
                "key_path": "/root/cert/private.key"
            }
        },
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
                "certificate_path": "/root/cert/cert.pem",
                "key_path": "/root/cert/private.key"
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
        {
            "type": "vless",
            "listen": "::",
            "listen_port": $vmess_port,
            "users": [
                {
                    "name": "$uuid",
                    "uuid": "$uuid"
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/$vmess_path"
            }
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
traffic=\$(vnstat --oneline b | awk -F';' '{print \$10}')
traffic_gb=\$(echo "scale=2; \$traffic / 1024 / 1024 / 1024" | bc)
echo "本月流量: \$traffic_gb GB, 流量限制: \$limit GB"
if (( \$(echo "\$traffic_gb > \$limit" | bc -l) )); then
echo "月流量超过 \$limit GB，自动关机"
shutdown -h now
fi
# 推送Telegram Bot
curl -X POST "https://api.telegram.org/bot$bottoken/sendMessage" -F "chat_id=$chatid" -F "text=\${server}出站流量 \${traffic_gb} / \${limit} GB"
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
    "certificate": "/root/cert/cert.pem",
    "private_key": "/root/cert/private.key",
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

    hostname=$(prompt_input "hostname" "")

    hostnamectl set-hostname $hostname
    # 更新 /etc/hostname 文件
    echo $hostname > /etc/hostname

    echo "✓ 操作完成"
}

function nmpr_install {

    sudo apt update
    sudo apt install -y nginx

    sudo systemctl start nginx
    sudo systemctl enable nginx

    #配置文件 /etc/php/8.2/fpm/pool.d/www.conf
    #/run/php/php8.2-fpm.sock
    sudo apt install -y php8.2 php8.2-fpm

    # 安装PHP和PHP的扩展
    sudo apt install -y php-redis php-mbstring php-mysql php-gd php-curl

    sudo systemctl start php8.2-fpm
    sudo systemctl enable php8.2-fpm

    # 安装wget和GnuPG，这些是下载和验证MySQL APT配置包所必需的
    sudo apt install -y gnupg

    # 下载MySQL APT配置包
    wget https://dev.mysql.com/get/mysql-apt-config_0.8.29-1_all.deb

    # 安装MySQL APT配置包
    sudo dpkg -i mysql-apt-config_0.8.29-1_all.deb

    # 如果在安装过程中遇到任何问题，可以尝试使用以下命令修复依赖关系
    sudo apt -f install

    # 再次更新包列表以确保可以访问MySQL仓库
    sudo apt update

    # 安装MySQL服务器
    sudo apt install -y mysql-server

    # 启动MySQL服务
    sudo systemctl start mysql

    # 设置MySQL服务开机自启
    sudo systemctl enable mysql

    # 运行安全脚本来提高MySQL安全性
    sudo mysql_secure_installation

    # 安装Redis服务器
    sudo apt install -y redis-server

    # 启动Redis服务
    sudo systemctl start redis-server

    # 设置Redis服务开机自启
    sudo systemctl enable redis-server

    sudo systemctl status nginx
    sudo systemctl status php8.2-fpm
    php -m | grep redis
    # 输出MySQL版本以验证安装
    mysql -V
    # 检查Redis服务状态
    sudo systemctl status redis-server
    # 打印Redis版本信息，验证安装成功
    redis-server --version

}

function db_backup {

    cd /root
    wget https://aliyuncli.alicdn.com/aliyun-cli-linux-latest-amd64.tgz
    tar xzvf aliyun-cli-linux-latest-amd64.tgz
    sudo mv aliyun /usr/local/bin
    
    DB_USER=$(prompt_input "DB USER" "")
    DB_PASSWORD=$(prompt_input "DB PASSWORD" "")
    DB_NAME=$(prompt_input "DB NAME" "")

    OSS_BUCKET=$(prompt_input "OSS BUCKET" "")
    OSS_REGION=$(prompt_input "OSS REGION" "")
    OSS_PATH=$(prompt_input "OSS PATH" "")

    AccessKeyId=$(prompt_input "OSS AccessKeyId" "")
    AccessKeySecret=$(prompt_input "OSS AccessKeySecret" "")

    aliyun configure set \
  --profile akProfile \
  --mode AK \
  --region $OSS_REGION \
  --access-key-id $AccessKeyId \
  --access-key-secret $AccessKeySecret

    cat <<EOF > /root/mysql_backup.sh
#!/bin/bash

# MySQL数据库相关配置
DB_USER="$DB_USER"
DB_PASSWORD="$DB_PASSWORD"
DB_NAME="$DB_NAME"

# OSS相关配置
OSS_BUCKET="$OSS_BUCKET"
OSS_REGION="$OSS_REGION"
OSS_PATH="$OSS_PATH"

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

    # 使用阿里云CLI上传到OSS
    aliyun oss cp -f \$BACKUP_FILE oss://\$OSS_BUCKET/\$OSS_PATH/\$DB_NAME-\$DATE.sql.gz --region \$OSS_REGION --profile akProfile

    if [ \$? -eq 0 ]; then
        echo "Backup file uploaded to Alibaba Cloud OSS successfully."
        rm -f \$BACKUP_FILE
    else
        echo "Failed to upload the backup file to Alibaba Cloud OSS."
    fi
else
    echo "Database backup failed."
fi
exit 0
EOF

    chmod +x /root/mysql_backup.sh
    #添加计划任务
    cron_add "mysql_backup" "0 2 * * * /root/mysql_backup.sh > /root/mysql_backup.log"
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
    16)  ipv6 warp 脚本
    17)  swap 脚本
    18)  vnstat 流量监控关机脚本
    19)  ufw 定时开关防火墙
    20)  noip 动态DDNS
    21)  安装juicity
    22)  打印本地配置
    23)  安装 Hysteria 2
    24)  安装 X-UI
    25)  安装 3X-UI
    26)  cloudflare 动态DDNS
    27)  DD系统
    28)  科技lion脚本
    29)  安装 s-ui
    30)  修改hostname
    31)  安装nginx php8 mysql8 redis7
    32)  数据库每日备份到阿里云OSS
    90)  卸载juicity
    91)  卸载sing-box
    92)  卸载Hysteria 2
    99)  退出

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
            bash <(curl -Ls https://raw.githubusercontent.com/alireza0/s-ui/master/install.sh)
          ;;
          30)
            hostname_change
          ;;
          31)
            nmpr_install
          ;;
          32)
            db_backup
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
          99)
            exit
          ;;
          *)
          clear
          continue
          ;;
  esac
done
