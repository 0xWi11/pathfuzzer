package pzfzr.core;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.proxy.Socks5ProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CompressionUtils;
import pzfzr.config.PluginConfigManager;

import javax.net.ssl.SSLException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NettyManager - 修改版支持可配置端口
 */
public class NettyManager {
    private static volatile NettyManager instance;

    // 核心组件
    private final Logging logging;
    private final CompressionUtils compressionUtils;
    private final EventLoopGroup eventLoopGroup;
    private final Bootstrap bootstrap;
    private final SslContext sslContext;

    // 连接池
    private final Map<String, Queue<Channel>> channelPools = new ConcurrentHashMap<>();
    private final Map<Channel, ChannelInfo> channelInfoMap = new ConcurrentHashMap<>();

    // 流控
    private final Semaphore requestSemaphore = new Semaphore(300);
    private final AtomicInteger activeRequests = new AtomicInteger(0);
    private final AtomicInteger acquiredPermits = new AtomicInteger(0);

    // 业务线程池
    private final ExecutorService businessExecutor;
    private static final AtomicInteger BUSINESS_THREAD_COUNTER = new AtomicInteger(1);

    // 监控线程池
    private final ScheduledExecutorService monitorExecutor;

    // 配置管理器
    private final PluginConfigManager configManager;

    // 配置
    private static final String PROXY_HOST = "127.0.0.1";
    private final int PROXY_PORT; // 从配置读取
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_SEC = 120;
    private static final int WRITE_TIMEOUT_SEC = 60;

    // 重试配置
    private static final int MAX_RETRY_COUNT = 2; // 最大重试次数
    private static final long RETRY_DELAY_MS = 500; // 重试延迟时间(毫秒)

    // 统计
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong successRequests = new AtomicLong(0);
    private final AtomicLong failedRequests = new AtomicLong(0);
    private final AtomicLong retryRequests = new AtomicLong(0); // 重试请求统计
    private final AtomicLong connectionCreated = new AtomicLong(0);
    private final AtomicLong connectionReused = new AtomicLong(0);
    private final AtomicLong connectionClosed = new AtomicLong(0);

    // 调试开关
    private static final boolean DEBUG = false;

    // 关闭控制
    private final AtomicBoolean isShutdown = new AtomicBoolean(false);
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);
    private final AtomicBoolean shutdownStarted = new AtomicBoolean(false);

    private NettyManager(Logging logging, CompressionUtils compressionUtils) {
        this.logging = logging;
        this.compressionUtils = compressionUtils;
        this.configManager = PluginConfigManager.getInstance();

        // 从配置读取端口
        this.PROXY_PORT = configManager.getNettyPort();

        try {
            // 创建SSL上下文
            this.sslContext = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }

        // 创建EventLoopGroup
        this.eventLoopGroup = new NioEventLoopGroup(Math.min(Runtime.getRuntime().availableProcessors() * 2, 16));

        // 创建Bootstrap
        this.bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_REUSEADDR, true);

        // 创建业务线程池
        this.businessExecutor = new ThreadPoolExecutor(
                10, 50,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                r -> {
                    Thread t = new Thread(r, "netty-business-" + BUSINESS_THREAD_COUNTER.getAndIncrement() );
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        // 创建监控线程池
        this.monitorExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "netty-monitor");
            t.setDaemon(true);
            return t;
        });

        // 启动监控线程
        startMonitorThread();

        logging.logToOutput("[NettyManager] Initialization complete, EventLoop threads: " +
                ((NioEventLoopGroup)eventLoopGroup).executorCount() +
                ", Proxy: " + PROXY_HOST + ":" + PROXY_PORT +
                ", Plugin: " + configManager.getPluginName());
    }

    /**
     * 启动监控线程
     */
    private void startMonitorThread() {
        monitorExecutor.scheduleAtFixedRate(() -> {
            // 检查是否已关闭
            if (isShutdown.get()) {
                return;
            }

            if (DEBUG) {
                logging.logToOutput(String.format(
                        "[NettyManager Monitor] Permits: %d/%d, Active: %d, Total: %d, Success: %d, Failed: %d, Retry: %d, " +
                                "Connections - Created: %d, Reused: %d, Closed: %d, Pools: %d",
                        requestSemaphore.availablePermits(), 300,
                        activeRequests.get(),
                        totalRequests.get(),
                        successRequests.get(),
                        failedRequests.get(),
                        retryRequests.get(),
                        connectionCreated.get(),
                        connectionReused.get(),
                        connectionClosed.get(),
                        getTotalPooledConnections()
                ));
            }
        }, 10, 10, TimeUnit.SECONDS);
    }

    /**
     * 获取池中总连接数
     */
    private int getTotalPooledConnections() {
        return channelPools.values().stream()
                .mapToInt(Queue::size)
                .sum();
    }

    /**
     * 获取单例实例
     */
    public static NettyManager getInstance(Logging logging, CompressionUtils compressionUtils) {
        if (instance == null || instance.isShutdown.get()) {
            synchronized (NettyManager.class) {
                if (instance == null || instance.isShutdown.get()) {
                    if (instance != null && instance.isShutdown.get()) {
                        logging.logToOutput("[NettyManager] Detected closed instance, creating new instance");
                    }
                    instance = new NettyManager(logging, compressionUtils);
                }
            }
        }
        return instance;
    }

    public static NettyManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException("NettyManager not initialized");
        }
        return instance;
    }

    /**
     * 发送HTTP请求 - 新增重试功能
     */
    public CompletableFuture<HttpResponse> sendRequest(HttpRequest burpRequest, ResponseCallback callback) {
        return sendRequestWithRetry(burpRequest, callback, 0);
    }

    /**
     * 带重试的发送请求方法
     */
    private CompletableFuture<HttpResponse> sendRequestWithRetry(HttpRequest burpRequest, ResponseCallback callback, int retryCount) {
        CompletableFuture<HttpResponse> future = new CompletableFuture<>();

        if (isShutdown.get()) {
            future.completeExceptionally(new IllegalStateException("NettyManager is shutdown"));
            return future;
        }

        long requestId = totalRequests.incrementAndGet();

        if (DEBUG || retryCount > 0) {
            logging.logToError("[NettyManager] Request #" + requestId + " starting" +
                    (retryCount > 0 ? " (retry " + retryCount + ")" : "") + ", URL: " + burpRequest.url());
        }

        // 异步处理
        CompletableFuture.runAsync(() -> {
            final boolean[] permitAcquired = {false};

            try {
                // 再次检查关闭状态
                if (isShutdown.get()) {
                    throw new IllegalStateException("NettyManager is shutdown");
                }

                // 获取许可
                requestSemaphore.acquire();
                permitAcquired[0] = true;
                acquiredPermits.incrementAndGet();
                activeRequests.incrementAndGet();

                // 解析请求
                RequestInfo requestInfo = parseRequest(burpRequest);

                // 检查是否应该使用keep-alive
                boolean shouldKeepAlive = shouldUseKeepAlive(burpRequest);

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + requestId +
                            " - Host: " + requestInfo.host +
                            ", Keep-Alive: " + shouldKeepAlive);
                }

                // 获取或创建Channel
                CompletableFuture<Channel> channelFuture = shouldKeepAlive
                        ? acquirePooledChannel(requestInfo.host, requestInfo.port, requestInfo.isHttps)
                        : createNewChannel(requestInfo.host, requestInfo.port, requestInfo.isHttps);

                channelFuture.thenAccept(channel -> {
                    // 发送请求
                    sendRequestOnChannel(channel, requestInfo, burpRequest, future, callback,
                            requestId, shouldKeepAlive, retryCount);
                }).exceptionally(ex -> {
                    handleRequestError(ex, future, callback, requestId, permitAcquired[0], burpRequest, retryCount);
                    return null;
                });

            } catch (Exception e) {
                handleRequestError(e, future, callback, requestId, permitAcquired[0], burpRequest, retryCount);
            }
        }, businessExecutor);

        return future;
    }

    /**
     * 判断是否使用keep-alive
     */
    private boolean shouldUseKeepAlive(HttpRequest request) {
        String connectionHeader = request.headerValue("Connection");
        if (connectionHeader != null) {
            return !connectionHeader.equalsIgnoreCase("close");
        }
        // 默认使用keep-alive
        return true;
    }

    /**
     * 判断是否为可重试的错误
     */
    private boolean isRetryableError(Throwable ex) {
        if (ex == null) return false;

        String message = ex.getMessage();
        if (message == null) return false;

        message = message.toLowerCase();

        // 检查是否为握手超时错误
        return message.contains("handshake timed out") ||
                message.contains("connection timeout") ||
                message.contains("connect timeout") ||
                message.contains("connection reset") ||
                message.contains("connection refused");
    }

    /**
     * 处理请求错误 - 新增重试逻辑
     */
    private void handleRequestError(Throwable ex, CompletableFuture<HttpResponse> future,
                                    ResponseCallback callback, long requestId, boolean permitAcquired,
                                    HttpRequest burpRequest, int retryCount) {

        // 检查是否可以重试
        if (retryCount < MAX_RETRY_COUNT && isRetryableError(ex) && !isShutdown.get()) {
            // 释放当前请求的资源
            if (permitAcquired) {
                requestSemaphore.release();
                acquiredPermits.decrementAndGet();
            }
            activeRequests.decrementAndGet();
            retryRequests.incrementAndGet();

            logging.logToError("[NettyManager] Request #" + requestId + " failed with retryable error: " +
                    ex.getMessage() + ", will retry after " + RETRY_DELAY_MS + "ms");

            // 延迟后重试
            CompletableFuture.runAsync(() -> {
                try {
                    Thread.sleep(RETRY_DELAY_MS);
                    // 递归调用重试
                    CompletableFuture<HttpResponse> retryFuture = sendRequestWithRetry(burpRequest, callback, retryCount + 1);

                    // 将重试结果转发到原来的future
                    retryFuture.whenComplete((response, throwable) -> {
                        if (throwable != null) {
                            future.completeExceptionally(throwable);
                        } else {
                            future.complete(response);
                        }
                    });

                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    future.completeExceptionally(ie);
                }
            }, businessExecutor);

            return; // 不执行下面的失败处理逻辑
        }

        // 不可重试或重试次数已达上限，执行原来的错误处理逻辑
        if (permitAcquired) {
            requestSemaphore.release();
            acquiredPermits.decrementAndGet();
        }
        activeRequests.decrementAndGet();
        failedRequests.incrementAndGet();

        String errorMsg = "[NettyManager] Request #" + requestId + " failed" +
                (retryCount > 0 ? " after " + retryCount + " retries" : "") + ": " + ex.getMessage();
        logging.logToError(errorMsg);

        future.completeExceptionally(ex);
        if (callback != null) {
            try {
                businessExecutor.execute(() -> callback.onError(ex));
            } catch (RejectedExecutionException e) {
                // 线程池已关闭，忽略
            }
        }
    }

    /**
     * 从池中获取Channel
     */
    private CompletableFuture<Channel> acquirePooledChannel(String host, int port, boolean isHttps) {
        String key = host + ":" + port;
        Queue<Channel> pool = channelPools.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

        // 尝试从池中获取
        Channel channel = null;
        while ((channel = pool.poll()) != null) {
            if (channel.isActive()) {
                connectionReused.incrementAndGet();
                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Reusing connection for " + key);
                }
                return CompletableFuture.completedFuture(channel);
            } else {
                // 清理无效连接
                channelInfoMap.remove(channel);
                connectionClosed.incrementAndGet();
            }
        }

        // 创建新连接
        return createNewChannel(host, port, isHttps);
    }

    /**
     * 创建新连接
     */
    private CompletableFuture<Channel> createNewChannel(String host, int port, boolean isHttps) {
        CompletableFuture<Channel> future = new CompletableFuture<>();

        Bootstrap b = bootstrap.clone();
        b.handler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ChannelPipeline p = ch.pipeline();

                // SOCKS5代理 - 使用可配置端口
                p.addLast("socks5", new Socks5ProxyHandler(
                        new InetSocketAddress(PROXY_HOST, PROXY_PORT)));

                // SSL处理
                if (isHttps) {
                    p.addLast("ssl", sslContext.newHandler(ch.alloc(), host, port));
                }

                // 超时处理
                p.addLast("readTimeout", new ReadTimeoutHandler(READ_TIMEOUT_SEC));
                p.addLast("writeTimeout", new WriteTimeoutHandler(WRITE_TIMEOUT_SEC));

                // HTTP编解码
                p.addLast("codec", new HttpClientCodec());
                p.addLast("aggregator", new HttpObjectAggregator(30 * 1024 * 1024));// 30MB

                // 响应处理
                p.addLast("handler", new ResponseChannelHandler());
            }
        });

        // 连接
        b.connect(host, port).addListener((ChannelFutureListener) f -> {
            if (f.isSuccess()) {
                Channel channel = f.channel();
                channelInfoMap.put(channel, new ChannelInfo(host, port, isHttps));
                connectionCreated.incrementAndGet();

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Created new connection to " + host + ":" + port);
                }

                future.complete(channel);
            } else {
                future.completeExceptionally(f.cause());
            }
        });

        return future;
    }

    /**
     * 在Channel上发送请求 - 修改增加重试计数参数
     */
    private void sendRequestOnChannel(Channel channel, RequestInfo requestInfo,
                                      HttpRequest burpRequest, CompletableFuture<HttpResponse> future,
                                      ResponseCallback callback, long requestId, boolean keepAlive, int retryCount) {
        try {
            // 转换为Netty请求
            FullHttpRequest nettyRequest = convertToNettyRequest(burpRequest, requestInfo, keepAlive);

            // 记录开始时间
            long startTime = System.nanoTime();

            // 设置响应处理器
            ResponseContext context = new ResponseContext(future, callback, startTime, requestId, keepAlive, burpRequest, retryCount);
            channel.attr(AttributeKey.<ResponseContext>valueOf("context")).set(context);

            // 发送请求
            channel.writeAndFlush(nettyRequest).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    handleChannelError(channel, f.cause(), context);
                } else if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + requestId + " sent successfully");
                }
            });

        } catch (Exception e) {
            handleChannelError(channel, e,
                    new ResponseContext(future, callback, 0, requestId, keepAlive, burpRequest, retryCount));
        }
    }

    /**
     * 处理Channel错误 - 修改增加重试逻辑
     */
    private void handleChannelError(Channel channel, Throwable cause, ResponseContext context) {
        // 关闭并移除失败的连接
        channel.close();
        channelInfoMap.remove(channel);
        connectionClosed.incrementAndGet();

        logging.logToError("[NettyManager] Request #" + context.requestId + " channel error: " +
                (cause != null ? cause.getMessage() : "unknown error"));

        // 检查是否可以重试
        if (context.retryCount < MAX_RETRY_COUNT && isRetryableError(cause) && !isShutdown.get()) {
            // 释放当前请求的资源
            requestSemaphore.release();
            acquiredPermits.decrementAndGet();
            activeRequests.decrementAndGet();
            retryRequests.incrementAndGet();

            logging.logToError("[NettyManager] Request #" + context.requestId + " will retry due to channel error");

            // 延迟后重试
            CompletableFuture.runAsync(() -> {
                try {
                    Thread.sleep(RETRY_DELAY_MS);
                    // 递归调用重试
                    CompletableFuture<HttpResponse> retryFuture = sendRequestWithRetry(context.originalRequest, context.callback, context.retryCount + 1);

                    // 将重试结果转发到原来的future
                    retryFuture.whenComplete((response, throwable) -> {
                        if (throwable != null) {
                            context.future.completeExceptionally(throwable);
                        } else {
                            context.future.complete(response);
                        }
                    });

                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    context.future.completeExceptionally(ie);
                }
            }, businessExecutor);

            return; // 不执行下面的失败处理逻辑
        }

        // 不可重试或重试次数已达上限
        requestSemaphore.release();
        acquiredPermits.decrementAndGet();
        activeRequests.decrementAndGet();
        failedRequests.incrementAndGet();

        context.future.completeExceptionally(cause != null ? cause : new RuntimeException("Channel error"));
        if (context.callback != null) {
            final Throwable error = cause != null ? cause : new RuntimeException("Channel error");
            try {
                businessExecutor.execute(() -> context.callback.onError(error));
            } catch (RejectedExecutionException e) {
                // 线程池已关闭，忽略
            }
        }
    }

    /**
     * 响应处理器
     */
    private class ResponseChannelHandler extends SimpleChannelInboundHandler<FullHttpResponse> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
            ResponseContext context = ctx.channel().attr(AttributeKey.<ResponseContext>valueOf("context")).get();

            if (context == null) {
                logging.logToError("[NettyManager] No context found for response");
                ReferenceCountUtil.release(msg);
                return;
            }

            try {
                long responseTime = (System.nanoTime() - context.startTime) / 1_000_000;

                // 保留消息
                msg.retain();

                // 从channelInfoMap获取isHttps信息
                ChannelInfo channelInfo = channelInfoMap.get(ctx.channel());
                boolean isHttps = channelInfo != null ? channelInfo.isHttps : false;

                // 转换响应
                HttpResponse burpResponse = convertToBurpResponse(msg, isHttps);

                // 释放资源
                requestSemaphore.release();
                acquiredPermits.decrementAndGet();
                activeRequests.decrementAndGet();
                successRequests.incrementAndGet();

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + context.requestId +
                            " completed in " + responseTime + "ms");
                }

                // 处理连接
                if (context.keepAlive && !isConnectionClose(msg)) {
                    // 返回连接池
                    returnToPool(ctx.channel());
                } else {
                    // 关闭连接
                    ctx.close();
                    channelInfoMap.remove(ctx.channel());
                    connectionClosed.incrementAndGet();
                }

                // 完成Future
                context.future.complete(burpResponse);

                // 调用回调
                if (context.callback != null) {
                    try {
                        businessExecutor.execute(() -> context.callback.onResponse(burpResponse, responseTime));
                    } catch (RejectedExecutionException e) {
                        // 线程池已关闭，忽略
                    }
                }

            } finally {
                ReferenceCountUtil.release(msg);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ResponseContext context = ctx.channel().attr(AttributeKey.<ResponseContext>valueOf("context")).get();

            if (context != null) {
                handleChannelError(ctx.channel(), cause, context);
            } else {
                ctx.close();
            }
        }
    }

    /**
     * 检查响应是否要求关闭连接
     */
    private boolean isConnectionClose(FullHttpResponse response) {
        String connection = response.headers().get(HttpHeaderNames.CONNECTION);
        return connection != null && connection.equalsIgnoreCase("close");
    }

    /**
     * 返回连接到池
     */
    private void returnToPool(Channel channel) {
        if (isShutdown.get()) {
            // 如果正在关闭，直接关闭连接
            channel.close();
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();
            return;
        }

        ChannelInfo info = channelInfoMap.get(channel);
        if (info != null && channel.isActive()) {
            String key = info.host + ":" + info.port;
            Queue<Channel> pool = channelPools.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

            // 限制池大小
            if (pool.size() < 300) {
                pool.offer(channel);
                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Returned connection to pool: " + key);
                }
            } else {
                channel.close();
                channelInfoMap.remove(channel);
                connectionClosed.incrementAndGet();
            }
        }
    }

    /**
     * 解析请求信息
     */
    private RequestInfo parseRequest(HttpRequest request) {
        String url = request.url();
        RequestInfo info = new RequestInfo();

        // 手动解析URL
        if (url.startsWith("https://")) {
            info.isHttps = true;
            url = url.substring(8);
        } else if (url.startsWith("http://")) {
            info.isHttps = false;
            url = url.substring(7);
        }

        // 提取host和port
        int pathIndex = url.indexOf('/');
        String hostPort = pathIndex > 0 ? url.substring(0, pathIndex) : url;
        info.path = pathIndex > 0 ? url.substring(pathIndex) : "/";

        int portIndex = hostPort.lastIndexOf(':');
        if (portIndex > 0) {
            info.host = hostPort.substring(0, portIndex);
            info.port = Integer.parseInt(hostPort.substring(portIndex + 1));
        } else {
            info.host = hostPort;
            info.port = info.isHttps ? 443 : 80;
        }

        return info;
    }

    /**
     * 转换为Netty请求
     */
    private FullHttpRequest convertToNettyRequest(HttpRequest burpRequest, RequestInfo info, boolean keepAlive) {
        // 构建请求体
        ByteBuf content = burpRequest.body().length() > 0
                ? Unpooled.wrappedBuffer(burpRequest.body().getBytes())
                : Unpooled.EMPTY_BUFFER;

        // 创建请求
        FullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.valueOf(burpRequest.method()),
                info.path,
                content
        );

        // 添加headers
        for (HttpHeader header : burpRequest.headers()) {
            String name = header.name();
            if (!shouldSkipHeader(name)) {
                // 特殊处理Connection头部
                if (name.equalsIgnoreCase("Connection")) {
                    request.headers().set(HttpHeaderNames.CONNECTION,
                            keepAlive ? HttpHeaderValues.KEEP_ALIVE : HttpHeaderValues.CLOSE);
                } else {
                    request.headers().add(name, header.value());
                }
            }
        }

        // 设置必要的headers
        request.headers().set(HttpHeaderNames.HOST, info.host);
        if (content.readableBytes() > 0) {
            request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        }

        // 如果没有Connection头部，根据keepAlive设置
        if (!request.headers().contains(HttpHeaderNames.CONNECTION)) {
            request.headers().set(HttpHeaderNames.CONNECTION,
                    keepAlive ? HttpHeaderValues.KEEP_ALIVE : HttpHeaderValues.CLOSE);
        }

        return request;
    }

    /**
     * 转换为Burp响应
     */
    private HttpResponse convertToBurpResponse(FullHttpResponse nettyResponse, boolean isHttps) {
        StringBuilder responseBuilder = new StringBuilder();

        // 状态行
        responseBuilder.append("HTTP/1.1 ")
                .append(nettyResponse.status().code())
                .append(" ")
                .append(nettyResponse.status().reasonPhrase())
                .append("\r\n");

        // Headers
        for (Map.Entry<String, String> header : nettyResponse.headers()) {
            responseBuilder.append(header.getKey())
                    .append(": ")
                    .append(header.getValue())
                    .append("\r\n");
        }
        responseBuilder.append("\r\n");

        // Body
        byte[] headerBytes = responseBuilder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = new byte[nettyResponse.content().readableBytes()];
        nettyResponse.content().readBytes(bodyBytes);

        // 合并
        byte[] fullResponse = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, fullResponse, headerBytes.length, bodyBytes.length);

        return HttpResponse.httpResponse(ByteArray.byteArray(fullResponse));
    }

    /**
     * 判断是否跳过header
     */
    private boolean shouldSkipHeader(String headerName) {
        String lower = headerName.toLowerCase();
        return lower.equals("content-length") ||
                lower.equals("host");
    }

    /**
     * 关闭管理器
     */
    public void shutdown() {
        // 使用CAS确保只执行一次
        if (!shutdownStarted.compareAndSet(false, true)) {
            // 如果已经开始关闭，等待完成
            try {
                shutdownLatch.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return;
        }

        logging.logToOutput("[NettyManager] Starting shutdown for " + configManager.getPluginName() + "...");

        // 标记为关闭状态
        isShutdown.set(true);

        // 异步执行关闭过程，避免阻塞
        CompletableFuture.runAsync(this::performShutdown);
    }

    private void performShutdown() {
        try {
            // 第一步：停止监控线程
            shutdownMonitorExecutor();

            // 第二步：等待当前请求完成
            waitForPendingRequests();

            // 第三步：关闭所有池中的连接
            closeAllPooledConnections();

            // 第四步：关闭EventLoopGroup
            shutdownEventLoopGroup();

            // 第五步：关闭业务线程池
            shutdownBusinessExecutor();

            logging.logToOutput(String.format("[NettyManager] %s shutdown complete. Total requests: %d, Success: %d, Failed: %d, Retry: %d",
                    configManager.getPluginName(), totalRequests.get(), successRequests.get(), failedRequests.get(), retryRequests.get()));

        } catch (Exception e) {
            logging.logToError("[NettyManager] Error occurred during shutdown: " + e.getMessage());
        } finally {
            shutdownLatch.countDown();
        }
    }
    /**
     * 关闭监控线程池
     */
    private void shutdownMonitorExecutor() {
        try {
            logging.logToOutput("[NettyManager] Shutting down monitor thread...");
            monitorExecutor.shutdown();

            if (!monitorExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                monitorExecutor.shutdownNow();

                if (!monitorExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                    logging.logToError("[NettyManager] Monitor thread pool forced shutdown failed");
                }
            }
            logging.logToOutput("[NettyManager] Monitor thread shutdown complete");
        } catch (InterruptedException e) {
            monitorExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 等待pending请求完成
     */
    private void waitForPendingRequests() {
        try {
            int waitTime = 0;
            while (activeRequests.get() > 0 && waitTime < 5000) {
                Thread.sleep(100);
                waitTime += 100;
            }

            if (activeRequests.get() > 0) {
                logging.logToOutput("[NettyManager] There are still " + activeRequests.get() + " pending requests, forcing shutdown");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void closeAllPooledConnections() {
        try {
            logging.logToOutput("[NettyManager] Closing connection pools...");
            List<CompletableFuture<Void>> closeFutures = new ArrayList<>();

            for (Map.Entry<String, Queue<Channel>> entry : channelPools.entrySet()) {
                Queue<Channel> pool = entry.getValue();

                closeFutures.add(CompletableFuture.runAsync(() -> {
                    Channel ch;
                    while ((ch = pool.poll()) != null) {
                        try {
                            if (ch.isActive()) {
                                ch.close().sync();
                            }
                        } catch (Exception e) {
                            // 忽略关闭错误
                        }
                    }
                }));
            }

            // 等待所有连接关闭，最多等待5秒
            CompletableFuture.allOf(closeFutures.toArray(new CompletableFuture[0]))
                    .get(5, TimeUnit.SECONDS);

            logging.logToOutput("[NettyManager] Connection pools shutdown complete");
        } catch (Exception e) {
            logging.logToError("[NettyManager] Error closing connection pools: " + e.getMessage());
        } finally {
            channelPools.clear();
            channelInfoMap.clear();
        }
    }

    private void shutdownEventLoopGroup() {
        try {
            logging.logToOutput("[NettyManager] Shutting down EventLoopGroup...");
            Future<?> shutdownFuture = eventLoopGroup.shutdownGracefully(1, 5, TimeUnit.SECONDS);
            shutdownFuture.get(10, TimeUnit.SECONDS);
            logging.logToOutput("[NettyManager] EventLoopGroup shutdown complete");
        } catch (Exception e) {
            logging.logToError("[NettyManager] EventLoopGroup shutdown error: " + e.getMessage());
        }
    }

    private void shutdownBusinessExecutor() {
        try {
            logging.logToOutput("[NettyManager] Shutting down business executor...");
            businessExecutor.shutdown();

            if (!businessExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                // 如果优雅关闭失败，强制关闭
                logging.logToOutput("[NettyManager] Business executor graceful shutdown timeout, forcing shutdown...");
                businessExecutor.shutdownNow();

                if (!businessExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                    // 强制关闭也失败了
                    logging.logToError("[NettyManager] Business executor forced shutdown failed");
                } else {
                    // 强制关闭成功
                    logging.logToOutput("[NettyManager] Business executor forced shutdown complete");
                }
            } else {
                // 优雅关闭成功
                logging.logToOutput("[NettyManager] Business executor graceful shutdown complete");
            }
        } catch (InterruptedException e) {
            businessExecutor.shutdownNow();
            Thread.currentThread().interrupt();
            logging.logToOutput("[NettyManager] Business executor shutdown interrupted, forced shutdown executed");
        }
    }

    // 等待关闭完成
    public boolean awaitShutdown(long timeout, TimeUnit unit) {
        try {
            return shutdownLatch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * 请求信息
     */
    private static class RequestInfo {
        String host;
        int port;
        String path;
        boolean isHttps;
    }

    /**
     * Channel信息
     */
    private static class ChannelInfo {
        final String host;
        final int port;
        final boolean isHttps;

        ChannelInfo(String host, int port, boolean isHttps) {
            this.host = host;
            this.port = port;
            this.isHttps = isHttps;
        }
    }

    /**
     * 响应上下文 - 修改增加重试相关字段
     */
    private static class ResponseContext {
        final CompletableFuture<HttpResponse> future;
        final ResponseCallback callback;
        final long startTime;
        final long requestId;
        final boolean keepAlive;
        final HttpRequest originalRequest; // 新增：保存原始请求用于重试
        final int retryCount; // 新增：当前重试次数

        ResponseContext(CompletableFuture<HttpResponse> future, ResponseCallback callback,
                        long startTime, long requestId, boolean keepAlive,
                        HttpRequest originalRequest, int retryCount) {
            this.future = future;
            this.callback = callback;
            this.startTime = startTime;
            this.requestId = requestId;
            this.keepAlive = keepAlive;
            this.originalRequest = originalRequest;
            this.retryCount = retryCount;
        }
    }

    /**
     * 响应回调接口
     */
    public interface ResponseCallback {
        void onResponse(HttpResponse response, long responseTimeMs);
        void onError(Throwable error);
    }
}