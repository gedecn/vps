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
    curl -fsSL https://get.docker.com | bash -s docker

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
    newport=$(prompt_input "SSH端口号" "50440")
    #随机生成root密码
    rootpw=$(openssl rand -base64 12)
    newpw=$(prompt_input "root用户新密码" "$rootpw")

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

function main_menu {

    #标准输入
    echo
    echo
    cat <<'EOF'
功能菜单:
1)  系统升级
2)  SSH安全配置
3)  流量tg监控
4)  修改hostname
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
            traffic_check
          ;;
          4)
            hostname_change
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
