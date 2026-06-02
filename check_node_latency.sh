#!/bin/bash
# HAProxy external-check script (HTTP Proxy Version) - v2
#
# 改进点:
#   1. [Bug修复] 实际读取并校验 HTTP 状态码（原脚本写入文件后立即删除）
#   2. [精度]   使用 curl 内置 %{time_total} 计时，避免 date 子进程开销
#   3. [核心]   Best-of-2 策略，区分失败类型:
#               - TCP连接拒绝 (curl exit 7) → 立即不健康，不重试（节点确实挂了）
#               - 延迟超标 / curl超时       → 等待后重试一次（可能是瞬时抖动窗口）
#   4. [快速失败] 分离 connect-timeout 与 max-time

SERVER_ADDR="${HAPROXY_SERVER_ADDR}"
SERVER_PORT="${HAPROXY_SERVER_PORT}"

CONNECT_TIMEOUT=2       # TCP 握手超时（秒），连接不上时快速失败
MAX_TIME=5              # 单次请求总超时（秒）
LATENCY_THRESHOLD=3800  # 健康延迟上限（毫秒）
RETRY_WAIT=1            # 延迟超标后重试等待（秒）
TARGET_URL="http://www.gstatic.com/generate_204"

if [ -z "$SERVER_ADDR" ] || [ -z "$SERVER_PORT" ]; then
    exit 1
fi

PROXY_URL="http://${SERVER_ADDR}:${SERVER_PORT}"

# 单次检查函数
# 返回值:
#   0 = 健康  (HTTP 204 且延迟在阈值内)
#   1 = 可重试失败  (延迟超标 / curl超时，可能是瞬时抖动)
#   2 = 不可重试失败 (TCP连接被拒，节点确实不可用)
do_check() {
    local result exit_code http_code time_sec latency_ms

    result=$(curl -x "${PROXY_URL}" \
        --connect-timeout ${CONNECT_TIMEOUT} \
        --max-time ${MAX_TIME} \
        -s -o /dev/null \
        -w "%{http_code}:%{time_total}" \
        "${TARGET_URL}" 2>/dev/null)
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        # exit 7 = CURLE_COULDNT_CONNECT（端口拒绝/节点下线），无需重试
        [ $exit_code -eq 7 ] && return 2
        # 其他错误（28=超时 等），可能是延迟窗口，允许重试
        return 1
    fi

    http_code="${result%%:*}"
    time_sec="${result##*:}"

    # 必须是 204，代理返回 200/403 等均视为不健康
    [ "$http_code" != "204" ] && return 2

    # curl 返回小数秒，转为整数毫秒
    latency_ms=$(awk "BEGIN { printf \"%d\", ${time_sec} * 1000 }")

    [ "$latency_ms" -lt "$LATENCY_THRESHOLD" ] && return 0
    return 1  # 延迟超标，可重试
}

# 首次检查
do_check
case $? in
    0) exit 0 ;;   # 健康，直接返回

    2) exit 1 ;;   # 连接失败，不等不重试

    1)             # 延迟/超时失败：等待后重试一次
                   # 等待 1s 有大概率跳出瞬时抖动窗口
        sleep ${RETRY_WAIT}
        if do_check; then
            exit 0
        else
            exit 1
        fi
        ;;
esac