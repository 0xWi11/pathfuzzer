FROM haproxy:2.8

# 切换到root用户安装curl
USER root

# 安装curl
RUN apt-get update && \
    apt-get install -y curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 切换回haproxy用户
USER haproxy

# 使用原镜像的入口点
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]