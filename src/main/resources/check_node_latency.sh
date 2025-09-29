#!/bin/bash

# HAProxy external-check script (HTTP Proxy Version)
# 测试通过指定HTTP代理节点访问gstatic.com的延迟
# 延迟超过5秒则标记为不健康

# HAProxy会传递以下环境变量:
# HAPROXY_SERVER_ADDR - 服务器地址
# HAPROXY_SERVER_PORT - 服务器端口
# HAPROXY_SERVER_NAME - 服务器名称

SERVER_ADDR="${HAPROXY_SERVER_ADDR}"
SERVER_PORT="${HAPROXY_SERVER_PORT}"
TIMEOUT=5

# 检查参数
if [ -z "$SERVER_ADDR" ] || [ -z "$SERVER_PORT" ]; then
    exit 1
fi

# 使用curl通过节点作为HTTP代理访问gstatic.com
START_TIME=$(date +%s%N)

# 通过HTTP代理访问gstatic.com
curl -x "http://${SERVER_ADDR}:${SERVER_PORT}" \
     --connect-timeout ${TIMEOUT} \
     --max-time ${TIMEOUT} \
     -s -o /dev/null \
     -w "%{http_code}" \
     "http://www.gstatic.com/generate_204" > /tmp/curl_result_$$ 2>/dev/null

CURL_EXIT=$?
END_TIME=$(date +%s%N)

# 计算延迟（毫秒）
LATENCY=$(( (END_TIME - START_TIME) / 1000000 ))

# 清理临时文件
rm -f /tmp/curl_result_$$

# 检查结果
if [ $CURL_EXIT -eq 0 ] && [ $LATENCY -lt 5000 ]; then
    # 健康
    exit 0
else
    # 不健康
    exit 1
fi