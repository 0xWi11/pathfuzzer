package pzfzr.core;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.proxy.HttpProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import io.netty.util.AttributeKey;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CompressionUtils;
import burp.api.montoya.utilities.CompressionType;

import javax.net.ssl.SSLException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Netty客户端管理器 - 替代OkHttpManager
 * 保持原始请求格式，避免URL规范化，支持非规范化URL
 */
public class NettyManager {
    private static volatile NettyManager instance;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CompressionUtils compressionUtils;
    private final EventLoopGroup workerGroup;
    private final Bootstrap bootstrap;
    private final SslContext sslContext;

    // 连接池
    private final Map<String, Channel> connectionPool = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor;

    // 代理配置
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 20808;

    // 超时配置
    private static final int CONNECT_TIMEOUT = 15000; // ms
    private static final int READ_TIMEOUT = 120; // seconds
    private static final int WRITE_TIMEOUT = 60; // seconds

    // 请求追踪
    private final Map<Integer, RequestContext> activeRequests = new ConcurrentHashMap<>();
    private final AtomicLong requestIdGenerator = new AtomicLong(0);

    // AttributeKey for request tracking
    private static final AttributeKey<RequestContext> REQUEST_CONTEXT_KEY =
            AttributeKey.valueOf("requestContext");

    private NettyManager(Logging logging, RateLimiter rateLimiter, CompressionUtils compressionUtils) {
        this.logging = logging;
        this.rateLimiter = rateLimiter;
        this.compressionUtils = compressionUtils;

        // 初始化SSL上下文
        try {
            this.sslContext = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            throw new RuntimeException("Failed to initialize SSL context", e);
        }

        // 创建EventLoopGroup - 100个线程
        this.workerGroup = new NioEventLoopGroup(100);

        // 创建Bootstrap
        this.bootstrap = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true);

        // 启动连接池清理任务
        this.cleanupExecutor = Executors.newScheduledThreadPool(1);
        this.cleanupExecutor.scheduleAtFixedRate(this::cleanupIdleConnections, 30, 30, TimeUnit.SECONDS);

        logging.logToOutput("[NettyManager] 初始化完成，工作线程: 100，代理: " + PROXY_HOST + ":" + PROXY_PORT);
    }

    /**
     * 获取单例实例 - 带参数版本（用于首次初始化）
     */
    public static NettyManager getInstance(Logging logging, RateLimiter rateLimiter, CompressionUtils compressionUtils) {
        if (instance == null) {
            synchronized (NettyManager.class) {
                if (instance == null) {
                    if (logging == null || rateLimiter == null || compressionUtils == null) {
                        throw new IllegalArgumentException("NettyManager首次初始化时，所有参数都不能为null");
                    }
                    instance = new NettyManager(logging, rateLimiter, compressionUtils);
                }
            }
        }
        return instance;
    }

    /**
     * 获取单例实例 - 无参数版本（用于后续调用）
     */
    public static NettyManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException("NettyManager尚未初始化，请先调用getInstance(logging, rateLimiter, compressionUtils)进行初始化");
        }
        return instance;
    }

    /**
     * 手动解析URL信息，避免使用URI类的规范化
     */
    private static class UrlInfo {
        final String scheme;
        final String host;
        final int port;
        final String pathAndQuery;

        UrlInfo(String url) {
            // 解析scheme
            int schemeEnd = url.indexOf("://");
            if (schemeEnd == -1) {
                throw new IllegalArgumentException("Invalid URL: " + url);
            }
            this.scheme = url.substring(0, schemeEnd);

            // 跳过 ://
            int hostStart = schemeEnd + 3;

            // 查找路径开始位置
            int pathStart = url.indexOf('/', hostStart);
            if (pathStart == -1) {
                // 没有路径，整个剩余部分都是host:port
                this.pathAndQuery = "/";
                pathStart = url.length();
            } else {
                // 保留原始路径和查询参数，不进行任何处理
                this.pathAndQuery = url.substring(pathStart);
            }

            // 解析host和port
            String hostPort = url.substring(hostStart, pathStart);
            int portSeparator = hostPort.lastIndexOf(':');

            if (portSeparator == -1) {
                // 没有指定端口
                this.host = hostPort;
                this.port = "https".equals(scheme) ? 443 : 80;
            } else {
                // 检查是否是IPv6地址
                if (hostPort.startsWith("[") && hostPort.contains("]:")) {
                    // IPv6地址格式: [::1]:8080
                    int ipv6End = hostPort.indexOf(']');
                    this.host = hostPort.substring(1, ipv6End); // 去掉方括号
                    this.port = Integer.parseInt(hostPort.substring(ipv6End + 2));
                } else if (hostPort.startsWith("[")) {
                    // IPv6地址没有端口: [::1]
                    this.host = hostPort.substring(1, hostPort.length() - 1);
                    this.port = "https".equals(scheme) ? 443 : 80;
                } else {
                    // 普通IPv4地址或域名
                    this.host = hostPort.substring(0, portSeparator);
                    this.port = Integer.parseInt(hostPort.substring(portSeparator + 1));
                }
            }
        }
    }

    /**
     * 发送HTTP请求
     */
    public CompletableFuture<NettyResponse> sendRequest(HttpRequest burpRequest) {
        CompletableFuture<NettyResponse> future = new CompletableFuture<>();
        long startTime = System.nanoTime();

        try {
            // 使用手动解析避免URI规范化
            UrlInfo urlInfo = new UrlInfo(burpRequest.url());
            String host = urlInfo.host;
            int port = urlInfo.port;
            boolean isHttps = "https".equals(urlInfo.scheme);

            // 创建请求上下文
            RequestContext context = new RequestContext(burpRequest, future, startTime);
            int requestId = (int) requestIdGenerator.incrementAndGet();
            activeRequests.put(requestId, context);

            // 创建channel
            ChannelFuture channelFuture = bootstrap.handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ChannelPipeline pipeline = ch.pipeline();

                    // 添加代理处理器
                    pipeline.addFirst("proxy", new HttpProxyHandler(
                            new InetSocketAddress(PROXY_HOST, PROXY_PORT)));

                    // SSL处理（如果需要）
                    if (isHttps) {
                        pipeline.addLast("ssl", sslContext.newHandler(ch.alloc(), host, port));
                    }

                    // 超时处理器
                    pipeline.addLast("readTimeout", new ReadTimeoutHandler(READ_TIMEOUT));
                    pipeline.addLast("writeTimeout", new WriteTimeoutHandler(WRITE_TIMEOUT));

                    // HTTP编解码器 - 不进行聚合以保持原始格式
                    pipeline.addLast("httpEncoder", new HttpRequestEncoder());
                    pipeline.addLast("httpDecoder", new HttpResponseDecoder());

                    // 自定义响应处理器
                    pipeline.addLast("responseHandler", new SimpleChannelInboundHandler<HttpObject>() {
                        private io.netty.handler.codec.http.HttpResponse response;
                        private final List<HttpContent> contents = new ArrayList<>();

                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) {
                            if (msg instanceof io.netty.handler.codec.http.HttpResponse) {
                                response = (io.netty.handler.codec.http.HttpResponse) msg;
                            } else if (msg instanceof HttpContent) {
                                contents.add(((HttpContent) msg).retain());

                                if (msg instanceof LastHttpContent) {
                                    // 响应完成
                                    long responseTime = (System.nanoTime() - startTime) / 1_000_000;
                                    NettyResponse nettyResponse = new NettyResponse(response, contents, responseTime);
                                    future.complete(nettyResponse);

                                    // 清理
                                    activeRequests.remove(requestId);
                                }
                            }
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                            future.completeExceptionally(cause);
                            activeRequests.remove(requestId);
                            ctx.close();
                        }
                    });
                }
            }).connect(host, port);

            // 发送请求
            channelFuture.addListener((ChannelFutureListener) f -> {
                if (f.isSuccess()) {
                    Channel channel = f.channel();

                    // 构建原始HTTP请求 - 保持原始格式
                    FullHttpRequest nettyRequest = buildRawHttpRequest(burpRequest, urlInfo);

                    // 发送请求
                    channel.writeAndFlush(nettyRequest).addListener((ChannelFutureListener) writeFuture -> {
                        if (!writeFuture.isSuccess()) {
                            future.completeExceptionally(writeFuture.cause());
                            activeRequests.remove(requestId);
                        }
                    });
                } else {
                    future.completeExceptionally(f.cause());
                    activeRequests.remove(requestId);
                }
            });

        } catch (Exception e) {
            future.completeExceptionally(e);
            logging.logToError("[NettyManager] 发送请求失败: " + e.getMessage());
        }

        return future;
    }

    /**
     * 构建原始HTTP请求 - 保持原始格式不进行规范化
     */
    private FullHttpRequest buildRawHttpRequest(HttpRequest burpRequest, UrlInfo urlInfo) throws Exception {
        // 获取原始路径和查询字符串 - 完全不进行任何规范化
        String rawPathAndQuery = urlInfo.pathAndQuery;

        // 确定HTTP方法
        HttpMethod method = HttpMethod.valueOf(burpRequest.method());

        // 确定HTTP版本
        HttpVersion version = burpRequest.httpVersion().equals("HTTP/2") ?
                HttpVersion.HTTP_1_1 : HttpVersion.HTTP_1_1; // Netty HTTP/2需要特殊处理

        // 创建请求体
        ByteBuf content = burpRequest.body() != null && burpRequest.body().length() > 0 ?
                Unpooled.wrappedBuffer(burpRequest.body().getBytes()) :
                Unpooled.EMPTY_BUFFER;

        // 创建请求 - 使用原始路径和查询参数
        FullHttpRequest nettyRequest = new DefaultFullHttpRequest(
                version, method, rawPathAndQuery, content);

        // 添加headers - 保持原始headers
        for (HttpHeader header : burpRequest.headers()) {
            String headerName = header.name();
            String headerValue = header.value();

            // 保留所有headers，包括Connection: close等
            if (!headerName.equalsIgnoreCase("Host")) {
                nettyRequest.headers().add(headerName, headerValue);
            }
        }

        // 设置Host header
        nettyRequest.headers().set(HttpHeaderNames.HOST, urlInfo.host);

        // 设置Content-Length
        if (content.readableBytes() > 0) {
            nettyRequest.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        }

        return nettyRequest;
    }

    /**
     * 将Netty响应转换为Burp响应
     */
    public HttpResponse convertToBurpResponse(NettyResponse nettyResponse) {
        try {
            StringBuilder responseBuilder = new StringBuilder();

            // 构建状态行
            io.netty.handler.codec.http.HttpResponse response = nettyResponse.getResponse();
            responseBuilder.append(response.protocolVersion().text())
                    .append(" ")
                    .append(response.status().code())
                    .append(" ")
                    .append(response.status().reasonPhrase())
                    .append("\r\n");

            // 处理响应体
            byte[] bodyBytes = nettyResponse.getBodyBytes();
            String contentEncoding = response.headers().get(HttpHeaderNames.CONTENT_ENCODING);
            byte[] decompressedBody = bodyBytes;
            boolean wasDecompressed = false;

            // 解压缩响应体
            if (contentEncoding != null && !contentEncoding.isEmpty() && bodyBytes.length > 0) {
                try {
                    decompressedBody = decompressResponseBody(bodyBytes, contentEncoding);
                    wasDecompressed = true;
                } catch (Exception e) {
                    logging.logToError("[NettyManager] 解压缩失败: " + e.getMessage());
                    decompressedBody = bodyBytes;
                }
            }

            // 构建headers
            HttpHeaders headers = response.headers();
            for (Map.Entry<String, String> header : headers) {
                String headerName = header.getKey();
                String headerValue = header.getValue();

                // 跳过某些headers
                if (wasDecompressed && headerName.equalsIgnoreCase("Content-Encoding")) {
                    continue;
                }

                if (headerName.equalsIgnoreCase("Transfer-Encoding")) {
                    continue;
                }

                if (wasDecompressed && headerName.equalsIgnoreCase("Content-Length")) {
                    headerValue = String.valueOf(decompressedBody.length);
                }

                responseBuilder.append(headerName).append(": ").append(headerValue).append("\r\n");
            }

            // 确保有Content-Length
            if (!headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
                responseBuilder.append("Content-Length: ").append(decompressedBody.length).append("\r\n");
            }

            responseBuilder.append("\r\n");

            // 组合完整响应
            byte[] headerBytes = responseBuilder.toString().getBytes(StandardCharsets.UTF_8);
            byte[] fullResponse = new byte[headerBytes.length + decompressedBody.length];
            System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
            System.arraycopy(decompressedBody, 0, fullResponse, headerBytes.length, decompressedBody.length);

            return HttpResponse.httpResponse(ByteArray.byteArray(fullResponse));

        } catch (Exception e) {
            logging.logToError("[NettyManager] 转换响应失败: " + e.getMessage());
            throw new RuntimeException("Failed to convert response", e);
        }
    }

    /**
     * 解压缩响应体 - 使用Burp自带的解压缩工具
     */
    private byte[] decompressResponseBody(byte[] compressedData, String contentEncoding) {
        if (compressedData == null || compressedData.length == 0) {
            return compressedData;
        }

        try {
            CompressionType compressionType = null;

            if ("gzip".equalsIgnoreCase(contentEncoding)) {
                compressionType = CompressionType.GZIP;
            } else if ("deflate".equalsIgnoreCase(contentEncoding)) {
                compressionType = CompressionType.DEFLATE;
            } else if ("br".equalsIgnoreCase(contentEncoding)) {
                compressionType = CompressionType.BROTLI;
            } else {
                return compressedData;
            }

            ByteArray compressedByteArray = ByteArray.byteArray(compressedData);
            ByteArray decompressedByteArray = compressionUtils.decompress(compressedByteArray, compressionType);

            return decompressedByteArray.getBytes();

        } catch (Exception e) {
            logging.logToError("[NettyManager] 使用Burp解压缩工具失败: " + e.getMessage());
            return compressedData;
        }
    }

    /**
     * 清理空闲连接
     */
    private void cleanupIdleConnections() {
        Iterator<Map.Entry<String, Channel>> iterator = connectionPool.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Channel> entry = iterator.next();
            Channel channel = entry.getValue();
            if (!channel.isActive()) {
                iterator.remove();
                channel.close();
            }
        }
    }

    /**
     * 关闭管理器
     */
    public void shutdown() {
        try {
            // 取消所有活动请求
            for (RequestContext context : activeRequests.values()) {
                context.future.completeExceptionally(new InterruptedException("Manager shutting down"));
            }
            activeRequests.clear();

            // 关闭所有连接
            for (Channel channel : connectionPool.values()) {
                channel.close();
            }
            connectionPool.clear();

            // 关闭清理执行器
            cleanupExecutor.shutdown();

            // 关闭EventLoopGroup
            workerGroup.shutdownGracefully(1, 5, TimeUnit.SECONDS).sync();

            logging.logToOutput("[NettyManager] 已关闭");
        } catch (Exception e) {
            logging.logToError("[NettyManager] 关闭时出错: " + e.getMessage());
        }
    }

    /**
     * Netty响应包装类
     */
    public static class NettyResponse {
        private final io.netty.handler.codec.http.HttpResponse response;
        private final List<HttpContent> contents;
        private final long responseTimeMs;

        public NettyResponse(io.netty.handler.codec.http.HttpResponse response,
                             List<HttpContent> contents, long responseTimeMs) {
            this.response = response;
            this.contents = new ArrayList<>(contents);
            this.responseTimeMs = responseTimeMs;
        }

        public io.netty.handler.codec.http.HttpResponse getResponse() {
            return response;
        }

        public byte[] getBodyBytes() {
            int totalSize = contents.stream()
                    .mapToInt(content -> content.content().readableBytes())
                    .sum();

            byte[] bodyBytes = new byte[totalSize];
            int offset = 0;

            for (HttpContent content : contents) {
                ByteBuf buf = content.content();
                int length = buf.readableBytes();
                buf.readBytes(bodyBytes, offset, length);
                offset += length;
                content.release();
            }

            return bodyBytes;
        }

        public long getResponseTimeMs() {
            return responseTimeMs;
        }

        public int getStatusCode() {
            return response.status().code();
        }
    }

    /**
     * 请求上下文
     */
    private static class RequestContext {
        final HttpRequest burpRequest;
        final CompletableFuture<NettyResponse> future;
        final long startTime;

        RequestContext(HttpRequest burpRequest, CompletableFuture<NettyResponse> future, long startTime) {
            this.burpRequest = burpRequest;
            this.future = future;
            this.startTime = startTime;
        }
    }
}