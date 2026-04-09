#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

CERT_DIR="/data/cert"
STATE_FILE="/tmp/cert_state.sha1"
LOG_TAG="[cert-reloader]"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_TAG} $*"
}

error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_TAG} [错误] $*" >&2
}

# ---------- 前置检查 ----------
if [ ! -d "$CERT_DIR" ]; then
    error "证书目录不存在: $CERT_DIR"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    error "未找到 docker 命令，cron 环境 PATH 可能不完整"
    exit 1
fi

log "开始检测证书目录变化: $CERT_DIR"

# ---------- 计算当前目录指纹 ----------
new_state=$(find "$CERT_DIR" -type f -exec sha1sum {} \; 2>/dev/null | sort | sha1sum | awk '{print $1}')

if [ -z "$new_state" ]; then
    error "未计算出证书指纹（目录可能为空或权限不足）"
    exit 1
fi

# ---------- 首次运行 ----------
if [ ! -f "$STATE_FILE" ]; then
    echo "$new_state" > "$STATE_FILE"
    log "首次运行，建立基线指纹: $new_state"
    exit 0
fi

old_state=$(cat "$STATE_FILE")

# ---------- 未变化 ----------
if [ "$new_state" = "$old_state" ]; then
    log "证书未变化，无需重载服务"
    exit 0
fi

# ---------- 发现变化 ----------
log "检测到证书文件变化！"
log "旧指纹: $old_state"
log "新指纹: $new_state"

echo "$new_state" > "$STATE_FILE"

# 列出变化文件（尽量）
log "尝试列出最近修改的证书文件："
find "$CERT_DIR" -type f -mmin -15 -printf "  变更文件: %p\n" 2>/dev/null || true

# ---------- 重载服务 ----------
reload_container() {
    local name="$1"

    if docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
        if docker kill -s HUP "$name" >/dev/null 2>&1; then
            log "已向容器发送 HUP 重载信号: $name"
        else
            error "向容器发送 HUP 失败: $name"
        fi
    else
        log "容器未运行，跳过: $name"
    fi
}

log "开始重载相关服务..."

reload_container nginx
reload_container sing-box

log "处理完成"
echo "--------------------------------------------------"
