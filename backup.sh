#!/bin/bash
# =====================================================
# 企业级 MySQL 备份脚本
# 支持：并行上传 / 日志 / TG通知 / 健康检测
# =====================================================

set -e

# 读取 .env
SCRIPT_DIR=$(dirname "$(realpath "$0")")
set -a
source "$SCRIPT_DIR/.env"
set +a

# 转成 bash 数组
IFS=' ' read -r -a REMOTE_SERVERS_ARR <<< "$REMOTE_SERVERS"

# RSA 写入文件
echo "$RSA" > "$SSH_KEY"
chmod 600 "$SSH_KEY"

RETENTION_DAYS=3

# =========================
# 初始化
# =========================
DATE_STR=$(date +%F_%H-%M-%S)
BACKUP_FILE="$BACKUP_DIR/mysql_${DB_NAME}_${DATE_STR}.sql.gz"
LOG_FILE="$LOG_DIR/backup_${DATE_STR}.log"

mkdir -p "$BACKUP_DIR" "$LOG_DIR"

log() {
    echo "$(date '+%F %T') $1" | tee -a "$LOG_FILE"
}

send_tg() {
    if [ -n "$TG_BOT_TOKEN" ] && [ -n "$TG_CHAT_ID" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" \
        -d chat_id="$TG_CHAT_ID" \
        -d text="$1" > /dev/null
    fi
}

# =====================================================
# 执行备份
# =====================================================
log "开始备份数据库 $DB_NAME..."

# 执行 mysqldump，并直接 gzip 压缩输出到文件
if ! mysqldump \
    -h"$MYSQL_HOST" \
    -u"$MYSQL_USER" \
    -p"$MYSQL_PASS" \
    --single-transaction \
    --quick \
    --routines \
    --events \
    --triggers \
    --databases "$DB_NAME" \
    --default-character-set=utf8mb4 \
    --max_allowed_packet=512M \
    | gzip > "$BACKUP_FILE"
then
    log "❌ 备份失败"
    send_tg "❌ MySQL 备份失败"
    exit 1
fi

log "✅ 备份完成: $BACKUP_FILE"

# =====================================================
# gzip 完整性校验
# =====================================================
log "开始校验压缩文件完整性..."

if ! gzip -t "$BACKUP_FILE"
then
    log "❌ gzip 文件损坏"
    send_tg "❌ MySQL 备份失败：压缩文件损坏"
    exit 1
fi

log "✅ gzip 校验通过"

# =====================================================
# 清理本地
# =====================================================
log "清理本地 $RETENTION_DAYS 天前备份..."
find "$BACKUP_DIR" -type f -name "mysql_${DB_NAME}_*.sql.gz" -mtime +"$RETENTION_DAYS" -delete

# =====================================================
# 并行上传
# =====================================================
log "开始并行上传到远程服务器..."

upload_remote() {
    IFS="|" read -r REMOTE_HOST REMOTE_PORT REMOTE_DIR REMOTE_RETENTION <<< "$1"

    log "上传到 $REMOTE_HOST"

    # 修正：使用双引号或不加引号，确保变量被解析
    ssh -i "$SSH_KEY" -p "$REMOTE_PORT" "$REMOTE_HOST" "mkdir -p $REMOTE_DIR" || {
        log "❌ 远程目录创建失败：$REMOTE_HOST"
        return 1
    }

    if ! scp -i "$SSH_KEY" -P "$REMOTE_PORT" "$BACKUP_FILE" "${REMOTE_HOST}:${REMOTE_DIR}/"
    then
        log "❌ 上传失败：$REMOTE_HOST"
        return 1
    fi

    log "✅ 上传成功：$REMOTE_HOST"

    # 修正：使用双引号包裹命令
    ssh -i "$SSH_KEY" -p "$REMOTE_PORT" "$REMOTE_HOST" \
        "find '$REMOTE_DIR' -type f -name 'mysql_${DB_NAME}_*.sql.gz' -mtime +$REMOTE_RETENTION -delete"

    log "远程清理完成：$REMOTE_HOST"
}

for SERVER in "${REMOTE_SERVERS_ARR[@]}"
do
    upload_remote "$SERVER" &
done

wait

# =====================================================
# 完成
# =====================================================
log "🎉 所有任务执行完成"
send_tg "✅ MySQL 备份成功：$DB_NAME"

exit 0
