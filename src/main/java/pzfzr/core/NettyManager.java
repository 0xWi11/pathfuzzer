package pzfzr.core;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.proxy.HttpProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import io.netty.handler.timeout.ReadTimeoutException;
import io.netty.handler.timeout.WriteTimeoutException;
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
 * NettyManager - 修改版支持可配置端口和响应大小限制
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

    // 超时监控线程池（新增）
    private final ScheduledExecutorService timeoutExecutor;

    // 配置管理器
    private final PluginConfigManager configManager;

    // 配置
    private static final String PROXY_HOST = "127.0.0.1";
    private final int PROXY_PORT; // 从配置读取
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_SEC = 120;
    private static final int WRITE_TIMEOUT_SEC = 60;
    private static final int MAX_RESPONSE_SIZE = 30 * 1024 * 1024; // 30MB 响应大小限制

    // 超时配置（新增）
    private static final long OVERALL_REQUEST_TIMEOUT_MS = 300000; // 整体请求超时：5分钟
    private static final long SSL_HANDSHAKE_TIMEOUT_MS = 60000; // SSL握手超时：60秒
    private static final long TOTAL_RETRY_TIMEOUT_MS = 600000; // 包含所有重试的总超时：10分钟

    // 重试配置
    private static final int MAX_RETRY_COUNT = 4; // 最大重试次数（修改为4，总共尝试5次）
    private static final long RETRY_DELAY_MS = 500; // 重试延迟时间(毫秒)

    // 连接池清理配置（新增）
    private static final long POOL_CLEANUP_INTERVAL_SEC = 60; // 连接池清理间隔：60秒
    private static final long CHANNEL_IDLE_TIMEOUT_MS = 300000; // Channel空闲超时：5分钟

    // 统计
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong successRequests = new AtomicLong(0);
    private final AtomicLong failedRequests = new AtomicLong(0);
    private final AtomicLong retryRequests = new AtomicLong(0); // 重试请求统计
    private final AtomicLong oversizedResponses = new AtomicLong(0); // 超大响应统计
    private final AtomicLong timeoutRequests = new AtomicLong(0); // 超时请求统计（新增）
    private final AtomicLong connectionCreated = new AtomicLong(0);
    private final AtomicLong connectionReused = new AtomicLong(0);
    private final AtomicLong connectionClosed = new AtomicLong(0);
    private final AtomicLong poolCleaned = new AtomicLong(0); // 连接池清理统计（新增）

    // 调试开关
    private static final boolean DEBUG = false;

    // 关闭控制
    private final AtomicBoolean isShutdown = new AtomicBoolean(false);
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);
    private final AtomicBoolean shutdownStarted = new AtomicBoolean(false);

    // 超时任务跟踪（新增）
    private final ConcurrentHashMap<Long, ScheduledFuture<?>> timeoutTasks = new ConcurrentHashMap<>();

    // AttributeKey 缓存（优化：避免重复创建）
    private static final AttributeKey<ResponseContext> CONTEXT_KEY = AttributeKey.valueOf("context");
    private static final AttributeKey<Long> LAST_USED_KEY = AttributeKey.valueOf("lastUsed");

    // 优化：StringBuilder 对象池（减少GC压力）
    private final ThreadLocal<StringBuilder> stringBuilderPool = ThreadLocal.withInitial(() -> new StringBuilder(512));

    private NettyManager(Logging logging, CompressionUtils compressionUtils) {
        this.logging = logging;
        this.compressionUtils = compressionUtils;
        this.configManager = PluginConfigManager.getInstance();

        // 从配置读取端口
        this.PROXY_PORT = configManager.getNettyPort();

        try {
            // 创建SSL上下文（增加握手超时配置）
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

        // 创建超时监控线程池（新增）
        this.timeoutExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "netty-timeout-monitor");
            t.setDaemon(true);
            return t;
        });

        // 启动监控线程
        startMonitorThread();

        // 启动连接池清理线程（新增）
        startPoolCleanupThread();

        logging.logToOutput("[NettyManager] Initialization complete, EventLoop threads: " +
                ((NioEventLoopGroup)eventLoopGroup).executorCount() +
                ", Proxy: " + PROXY_HOST + ":" + PROXY_PORT +
                ", Max response size: " + (MAX_RESPONSE_SIZE / 1024 / 1024) + "MB" +
                ", Max retry count: " + MAX_RETRY_COUNT +
                ", Overall timeout: " + (OVERALL_REQUEST_TIMEOUT_MS / 1000) + "s" +
                ", Total retry timeout: " + (TOTAL_RETRY_TIMEOUT_MS / 1000) + "s" +
                ", Pool cleanup interval: " + POOL_CLEANUP_INTERVAL_SEC + "s" +
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
                        "[NettyManager Monitor] Permits: %d/%d, Active: %d, Total: %d, Success: %d, Failed: %d, Retry: %d, Timeout: %d, Oversized: %d, " +
                                "Connections - Created: %d, Reused: %d, Closed: %d, Pools: %d, Cleaned: %d",
                        requestSemaphore.availablePermits(), 300,
                        activeRequests.get(),
                        totalRequests.get(),
                        successRequests.get(),
                        failedRequests.get(),
                        retryRequests.get(),
                        timeoutRequests.get(),
                        oversizedResponses.get(),
                        connectionCreated.get(),
                        connectionReused.get(),
                        connectionClosed.get(),
                        getTotalPooledConnections(),
                        poolCleaned.get()
                ));
            }
        }, 10, 10, TimeUnit.SECONDS);
    }

    /**
     * 启动连接池清理线程（新增）
     */
    private void startPoolCleanupThread() {
        monitorExecutor.scheduleAtFixedRate(() -> {
            if (isShutdown.get()) {
                return;
            }

            try {
                cleanupConnectionPools();
            } catch (Exception e) {
                logging.logToError("[NettyManager] Error during pool cleanup: " + e.getMessage());
            }
        }, POOL_CLEANUP_INTERVAL_SEC, POOL_CLEANUP_INTERVAL_SEC, TimeUnit.SECONDS);
    }

    /**
     * 清理连接池中的无效或空闲连接（新增）
     */
    private void cleanupConnectionPools() {
        long now = System.currentTimeMillis();
        int totalCleaned = 0;

        for (Map.Entry<String, Queue<Channel>> entry : channelPools.entrySet()) {
            Queue<Channel> pool = entry.getValue();
            List<Channel> toRemove = new ArrayList<>();

            // 检查池中的每个连接
            for (Channel channel : pool) {
                // 检查连接是否活跃
                if (!channel.isActive()) {
                    toRemove.add(channel);
                    continue;
                }

                // 检查连接是否空闲超时
                Long lastUsed = channel.attr(LAST_USED_KEY).get();
                if (lastUsed != null && (now - lastUsed) > CHANNEL_IDLE_TIMEOUT_MS) {
                    toRemove.add(channel);
                }
            }

            // 移除无效连接
            for (Channel channel : toRemove) {
                if (pool.remove(channel)) {
                    safeCloseChannel(channel);
                    channelInfoMap.remove(channel);
                    connectionClosed.incrementAndGet();
                    totalCleaned++;
                }
            }
        }

        if (totalCleaned > 0) {
            poolCleaned.addAndGet(totalCleaned);
            if (DEBUG) {
                logging.logToOutput("[NettyManager] Pool cleanup: removed " + totalCleaned + " stale connections");
            }
        }
    }

    /**
     * 安全关闭Channel（优化：确保资源释放）
     */
    private void safeCloseChannel(Channel channel) {
        if (channel == null) {
            return;
        }
        try {
            if (channel.isOpen()) {
                channel.close();
            }
        } catch (Exception e) {
            // 忽略关闭错误
        }
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
     * 发送HTTP请求 - 新增重试功能和总超时控制
     */
    public CompletableFuture<HttpResponse> sendRequest(HttpRequest burpRequest, ResponseCallback callback) {
        long totalStartTime = System.currentTimeMillis();
        return sendRequestWithRetry(burpRequest, callback, 0, totalStartTime);
    }

    /**
     * 带重试的发送请求方法（新增总超时参数）
     */
    private CompletableFuture<HttpResponse> sendRequestWithRetry(HttpRequest burpRequest, ResponseCallback callback,
                                                                 int retryCount, long totalStartTime) {
        CompletableFuture<HttpResponse> future = new CompletableFuture<>();

        if (isShutdown.get()) {
            future.completeExceptionally(new IllegalStateException("NettyManager is shutdown"));
            return future;
        }

        // 检查总超时（新增）
        long elapsedTime = System.currentTimeMillis() - totalStartTime;
        if (elapsedTime > TOTAL_RETRY_TIMEOUT_MS) {
            String errorMsg = "Total retry timeout exceeded (" + (TOTAL_RETRY_TIMEOUT_MS / 1000) + "s)";
            logging.logToError("[NettyManager] Request timeout: " + errorMsg);
            timeoutRequests.incrementAndGet();
            failedRequests.incrementAndGet();
            future.completeExceptionally(new TimeoutException(errorMsg));
            if (callback != null) {
                safeExecuteCallback(() -> callback.onError(new TimeoutException(errorMsg)));
            }
            return future;
        }

        long requestId = totalRequests.incrementAndGet();

        // 修改：只在DEBUG模式或首次请求时记录到output，重试时不记录error
        if (DEBUG && retryCount == 0) {
            logging.logToOutput("[NettyManager] Request #" + requestId + " starting, URL: " + burpRequest.url());
        } else if (DEBUG && retryCount > 0) {
            logging.logToOutput("[NettyManager] Request #" + requestId + " retry " + retryCount + ", URL: " + burpRequest.url());
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
                            requestId, shouldKeepAlive, retryCount, totalStartTime);
                }).exceptionally(ex -> {
                    handleRequestError(ex, future, callback, requestId, permitAcquired[0], burpRequest, retryCount, totalStartTime);
                    return null;
                });

            } catch (Exception e) {
                handleRequestError(e, future, callback, requestId, permitAcquired[0], burpRequest, retryCount, totalStartTime);
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
     * 判断是否为可重试的错误（增强版 - 优先判断异常类型）
     */
    private boolean isRetryableError(Throwable ex) {
        if (ex == null) return false;

        // 优先检查异常类型（不依赖message）
        if (ex instanceof TimeoutException ||
                ex instanceof ReadTimeoutException ||
                ex instanceof WriteTimeoutException ||
                ex instanceof java.net.ConnectException ||
                ex instanceof java.net.SocketTimeoutException ||
                ex instanceof java.nio.channels.ClosedChannelException ||
                ex instanceof io.netty.channel.ConnectTimeoutException ||
                ex instanceof java.io.IOException) {
            return true;
        }

        // 检查Netty特定的异常
        String className = ex.getClass().getName();
        if (className.contains("DecoderException") || className.contains("EncoderException")) {
            // 解码/编码错误通常不应重试
            return false;
        }

        // 检查消息内容（message可能为null，需要安全处理）
        String message = ex.getMessage();
        if (message != null) {
            String lowerMessage = message.toLowerCase();

            // 检查常见的可重试错误消息
            return lowerMessage.contains("handshake timed out") ||
                    lowerMessage.contains("connection timeout") ||
                    lowerMessage.contains("connect timeout") ||
                    lowerMessage.contains("connection reset") ||
                    lowerMessage.contains("connection refused") ||
                    lowerMessage.contains("timeout") ||
                    lowerMessage.contains("timed out") ||
                    lowerMessage.contains("broken pipe") ||
                    lowerMessage.contains("connection closed") ||
                    lowerMessage.contains("remotely closed");
        }

        // 如果message为null但不是已知的可重试类型，保守起见不重试
        // 但记录警告日志
        if (DEBUG) {
            logging.logToOutput("[NettyManager] Unknown error type with null message: " + className);
        }

        return false;
    }

    /**
     * 获取异常的详细描述（用于日志）- 优化：使用StringBuilder池
     */
    private String getErrorDescription(Throwable ex) {
        if (ex == null) {
            return "Unknown error (null exception)";
        }

        String message = ex.getMessage();
        String exceptionType = ex.getClass().getSimpleName();

        if (message != null && !message.isEmpty()) {
            StringBuilder sb = stringBuilderPool.get();
            sb.setLength(0);
            sb.append(exceptionType).append(": ").append(message);
            return sb.toString();
        } else {
            // message为null时，返回异常类型
            return exceptionType + " (no message)";
        }
    }

    /**
     * 处理请求错误 - 使用增强的错误描述
     */
    private void handleRequestError(Throwable ex, CompletableFuture<HttpResponse> future,
                                    ResponseCallback callback, long requestId, boolean permitAcquired,
                                    HttpRequest burpRequest, int retryCount, long totalStartTime) {

        // 检查总超时
        long elapsedTime = System.currentTimeMillis() - totalStartTime;
        if (elapsedTime > TOTAL_RETRY_TIMEOUT_MS) {
            if (permitAcquired) {
                requestSemaphore.release();
                acquiredPermits.decrementAndGet();
            }
            activeRequests.decrementAndGet();
            failedRequests.incrementAndGet();
            timeoutRequests.incrementAndGet();

            String errorMsg = "[NettyManager] Request #" + requestId + " total timeout exceeded after " +
                    (elapsedTime / 1000) + "s";
            logging.logToError(errorMsg);

            TimeoutException timeoutEx = new TimeoutException("Total retry timeout exceeded");
            future.completeExceptionally(timeoutEx);
            if (callback != null) {
                safeExecuteCallback(() -> callback.onError(timeoutEx));
            }
            return;
        }

        // 检查是否可以重试
        if (retryCount < MAX_RETRY_COUNT && isRetryableError(ex) && !isShutdown.get()) {
            // 释放当前请求的资源
            if (permitAcquired) {
                requestSemaphore.release();
                acquiredPermits.decrementAndGet();
            }
            activeRequests.decrementAndGet();
            retryRequests.incrementAndGet();

            // 使用增强的错误描述
            if (DEBUG) {
                logging.logToOutput("[NettyManager] Request #" + requestId + " encountered retryable error: " +
                        getErrorDescription(ex) + ", will retry (" + (retryCount + 1) + "/" + MAX_RETRY_COUNT + ") after " + RETRY_DELAY_MS + "ms");
            }

            // 延迟后重试
            scheduleRetry(burpRequest, callback, future, requestId, retryCount, totalStartTime);
            return;
        }

        // 最终失败 - 使用增强的错误描述
        if (permitAcquired) {
            requestSemaphore.release();
            acquiredPermits.decrementAndGet();
        }
        activeRequests.decrementAndGet();
        failedRequests.incrementAndGet();

        // 如果是超时错误，增加超时统计
        if (ex instanceof TimeoutException || ex instanceof ReadTimeoutException || ex instanceof WriteTimeoutException) {
            timeoutRequests.incrementAndGet();
        }

        String errorMsg = "[NettyManager] Request #" + requestId + " failed" +
                (retryCount > 0 ? " after " + retryCount + " retries" : "") + ": " + getErrorDescription(ex);
        logging.logToError(errorMsg);

        future.completeExceptionally(ex);
        if (callback != null) {
            safeExecuteCallback(() -> callback.onError(ex));
        }
    }

    /**
     * 调度重试任务（优化：提取方法避免代码重复）
     */
    private void scheduleRetry(HttpRequest burpRequest, ResponseCallback callback,
                               CompletableFuture<HttpResponse> future, long requestId,
                               int retryCount, long totalStartTime) {
        try {
            CompletableFuture.runAsync(() -> {
                try {
                    Thread.sleep(RETRY_DELAY_MS);
                    // 递归调用重试
                    CompletableFuture<HttpResponse> retryFuture = sendRequestWithRetry(burpRequest, callback, retryCount + 1, totalStartTime);

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
                    if (DEBUG) {
                        logging.logToOutput("[NettyManager] Request #" + requestId + " retry interrupted");
                    }
                    future.completeExceptionally(ie);
                    if (callback != null) {
                        safeExecuteCallback(() -> callback.onError(ie));
                    }
                }
            }, businessExecutor);
        } catch (RejectedExecutionException ree) {
            logging.logToError("[NettyManager] Request #" + requestId + " retry task rejected: " + getErrorDescription(ree));
            failedRequests.incrementAndGet();
            future.completeExceptionally(ree);
            if (callback != null) {
                safeExecuteCallback(() -> callback.onError(ree));
            }
        }
    }

    /**
     * 安全执行回调 - 新增方法:处理线程池关闭情况
     */
    private void safeExecuteCallback(Runnable callback) {
        try {
            businessExecutor.execute(callback);
        } catch (RejectedExecutionException e) {
            // 线程池已关闭或队列已满，直接在当前线程执行
            try {
                callback.run();
            } catch (Exception ex) {
                logging.logToError("[NettyManager] Callback execution error: " + ex.getMessage());
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
        Channel channel;
        while ((channel = pool.poll()) != null) {
            if (channel.isActive()) {
                // 更新最后使用时间（新增）
                channel.attr(LAST_USED_KEY).set(System.currentTimeMillis());
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
     * 创建新连接（增加SSL握手超时处理）
     */
    private CompletableFuture<Channel> createNewChannel(String host, int port, boolean isHttps) {
        CompletableFuture<Channel> future = new CompletableFuture<>();

        Bootstrap b = bootstrap.clone();
        b.handler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ChannelPipeline p = ch.pipeline();

                // HTTP CONNECT代理 - 使用可配置端口
                p.addLast("httpProxy", new HttpProxyHandler(
                        new InetSocketAddress(PROXY_HOST, PROXY_PORT)));

                // SSL处理（增加握手超时监控）
                if (isHttps) {
                    p.addLast("ssl", sslContext.newHandler(ch.alloc(), host, port));
                }

                // 超时处理
                p.addLast("readTimeout", new ReadTimeoutHandler(READ_TIMEOUT_SEC));
                p.addLast("writeTimeout", new WriteTimeoutHandler(WRITE_TIMEOUT_SEC));

                // HTTP编解码
                p.addLast("codec", new HttpClientCodec());
                p.addLast("aggregator", new HttpObjectAggregator(MAX_RESPONSE_SIZE));

                // 响应处理
                p.addLast("handler", new ResponseChannelHandler());
            }
        });

        // 连接（增加超时处理）
        ChannelFuture connectFuture = b.connect(host, port);

        // SSL握手超时监控（新增）
        if (isHttps) {
            ScheduledFuture<?> sslTimeoutTask = timeoutExecutor.schedule(() -> {
                if (!connectFuture.isDone() || !future.isDone()) {
                    String errorMsg = "SSL handshake timeout after " + (SSL_HANDSHAKE_TIMEOUT_MS / 1000) + "s";
                    if (DEBUG) {
                        logging.logToOutput("[NettyManager] " + errorMsg + " for " + host + ":" + port);
                    }
                    connectFuture.cancel(true);
                    future.completeExceptionally(new TimeoutException(errorMsg));
                    safeCloseChannel(connectFuture.channel());
                }
            }, SSL_HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS);

            connectFuture.addListener((ChannelFutureListener) f -> {
                // 确保超时任务被取消（新增）
                sslTimeoutTask.cancel(false);

                if (f.isSuccess()) {
                    Channel channel = f.channel();
                    channelInfoMap.put(channel, new ChannelInfo(host, port, isHttps));
                    // 设置创建时间（新增）
                    channel.attr(LAST_USED_KEY).set(System.currentTimeMillis());
                    connectionCreated.incrementAndGet();

                    if (DEBUG) {
                        logging.logToOutput("[NettyManager] Created new connection to " + host + ":" + port);
                    }

                    future.complete(channel);
                } else {
                    future.completeExceptionally(f.cause());
                }
            });
        } else {
            connectFuture.addListener((ChannelFutureListener) f -> {
                if (f.isSuccess()) {
                    Channel channel = f.channel();
                    channelInfoMap.put(channel, new ChannelInfo(host, port, isHttps));
                    // 设置创建时间（新增）
                    channel.attr(LAST_USED_KEY).set(System.currentTimeMillis());
                    connectionCreated.incrementAndGet();

                    if (DEBUG) {
                        logging.logToOutput("[NettyManager] Created new connection to " + host + ":" + port);
                    }

                    future.complete(channel);
                } else {
                    future.completeExceptionally(f.cause());
                }
            });
        }

        return future;
    }

    /**
     * 在Channel上发送请求 - 修改增加重试计数参数和整体超时控制（优化：确保ByteBuf释放）
     */
    private void sendRequestOnChannel(Channel channel, RequestInfo requestInfo,
                                      HttpRequest burpRequest, CompletableFuture<HttpResponse> future,
                                      ResponseCallback callback, long requestId, boolean keepAlive,
                                      int retryCount, long totalStartTime) {
        FullHttpRequest nettyRequest = null;
        try {
            // 转换为Netty请求
            nettyRequest = convertToNettyRequest(burpRequest, requestInfo, keepAlive);

            // 记录开始时间
            long startTime = System.nanoTime();

            // 设置响应处理器
            ResponseContext context = new ResponseContext(future, callback, startTime, requestId, keepAlive, burpRequest, retryCount, totalStartTime);
            channel.attr(CONTEXT_KEY).set(context);

            // 设置整体请求超时监控（新增）
            ScheduledFuture<?> timeoutTask = timeoutExecutor.schedule(() -> {
                if (!future.isDone()) {
                    String errorMsg = "Overall request timeout after " + (OVERALL_REQUEST_TIMEOUT_MS / 1000) + "s";
                    if (DEBUG) {
                        logging.logToOutput("[NettyManager] Request #" + requestId + " " + errorMsg);
                    }
                    timeoutRequests.incrementAndGet();

                    // 关闭连接
                    safeCloseChannel(channel);
                    channelInfoMap.remove(channel);
                    connectionClosed.incrementAndGet();

                    // 完成future
                    TimeoutException timeoutEx = new TimeoutException(errorMsg);
                    handleChannelError(channel, timeoutEx, context);
                }
            }, OVERALL_REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);

            // 保存超时任务以便取消
            timeoutTasks.put(requestId, timeoutTask);

            // 保存引用以便在异常时释放（新增）
            final FullHttpRequest finalRequest = nettyRequest;

            // 发送请求
            channel.writeAndFlush(nettyRequest).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    // 确保取消超时任务（新增）
                    cancelTimeoutTask(requestId);
                    // ByteBuf已由writeAndFlush处理，无需手动释放
                    handleChannelError(channel, f.cause(), context);
                } else if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + requestId + " sent successfully");
                }
            });

        } catch (Exception e) {
            // 异常路径：确保释放ByteBuf（优化：安全释放）
            ReferenceCountUtil.safeRelease(nettyRequest);
            handleChannelError(channel, e,
                    new ResponseContext(future, callback, 0, requestId, keepAlive, burpRequest, retryCount, totalStartTime));
        }
    }

    /**
     * 取消超时任务（优化：提取方法避免代码重复）
     */
    private void cancelTimeoutTask(long requestId) {
        ScheduledFuture<?> task = timeoutTasks.remove(requestId);
        if (task != null) {
            task.cancel(false);
        }
    }

    /**
     * 处理Channel错误 - 使用增强的错误描述
     */
    private void handleChannelError(Channel channel, Throwable cause, ResponseContext context) {
        // 取消超时任务
        cancelTimeoutTask(context.requestId);

        // 安全关闭连接（优化：避免重复关闭）
        safeCloseChannel(channel);
        channelInfoMap.remove(channel);
        connectionClosed.incrementAndGet();

        // 修改：只在DEBUG模式记录channel错误详情
        if (DEBUG) {
            logging.logToOutput("[NettyManager] Request #" + context.requestId + " channel error: " +
                    getErrorDescription(cause));
        }

        // 检查总超时
        long elapsedTime = System.currentTimeMillis() - context.totalStartTime;
        if (elapsedTime > TOTAL_RETRY_TIMEOUT_MS) {
            requestSemaphore.release();
            acquiredPermits.decrementAndGet();
            activeRequests.decrementAndGet();
            failedRequests.incrementAndGet();
            timeoutRequests.incrementAndGet();

            String errorMsg = "[NettyManager] Request #" + context.requestId + " total timeout exceeded";
            logging.logToError(errorMsg);

            TimeoutException timeoutEx = new TimeoutException("Total retry timeout exceeded");
            context.future.completeExceptionally(timeoutEx);
            if (context.callback != null) {
                safeExecuteCallback(() -> context.callback.onError(timeoutEx));
            }
            return;
        }

        // 检查是否可以重试
        if (context.retryCount < MAX_RETRY_COUNT && isRetryableError(cause) && !isShutdown.get()) {
            // 释放当前请求的资源
            requestSemaphore.release();
            acquiredPermits.decrementAndGet();
            activeRequests.decrementAndGet();
            retryRequests.incrementAndGet();

            // 修改：重试信息记录到output
            if (DEBUG) {
                logging.logToOutput("[NettyManager] Request #" + context.requestId +
                        " will retry due to channel error: " + getErrorDescription(cause));
            }

            // 延迟后重试
            scheduleRetry(context.originalRequest, context.callback, context.future,
                    context.requestId, context.retryCount, context.totalStartTime);
            return;
        }

        // 最终失败
        requestSemaphore.release();
        acquiredPermits.decrementAndGet();
        activeRequests.decrementAndGet();
        failedRequests.incrementAndGet();

        // 如果是超时错误，增加超时统计
        if (cause instanceof TimeoutException || cause instanceof ReadTimeoutException || cause instanceof WriteTimeoutException) {
            timeoutRequests.incrementAndGet();
        }

        String errorMsg = "[NettyManager] Request #" + context.requestId + " failed" +
                (context.retryCount > 0 ? " after " + context.retryCount + " retries" : "") +
                ": " + getErrorDescription(cause);
        logging.logToError(errorMsg);

        context.future.completeExceptionally(cause != null ? cause : new RuntimeException("Channel error"));
        if (context.callback != null) {
            final Throwable error = cause != null ? cause : new RuntimeException("Channel error");
            safeExecuteCallback(() -> context.callback.onError(error));
        }
    }

    /**
     * 创建超大响应的替代响应（优化：使用StringBuilder池）
     */
    private HttpResponse createOversizedResponse(boolean isHttps) {
        String errorMessage = "Message too large to display (response exceeds " +
                (MAX_RESPONSE_SIZE / 1024 / 1024) + "MB limit)";

        StringBuilder sb = stringBuilderPool.get();
        sb.setLength(0);
        sb.append("HTTP/1.1 200 OK\r\n");
        sb.append("Content-Type: text/plain; charset=UTF-8\r\n");
        sb.append("Content-Length: ").append(errorMessage.length()).append("\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        sb.append(errorMessage);

        byte[] responseBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        return HttpResponse.httpResponse(ByteArray.byteArray(responseBytes));
    }

    /**
     * 响应处理器 - 添加响应大小检查（优化：确保ByteBuf释放）
     */
    private class ResponseChannelHandler extends SimpleChannelInboundHandler<FullHttpResponse> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
            ResponseContext context = ctx.channel().attr(CONTEXT_KEY).get();

            if (context == null) {
                logging.logToError("[NettyManager] No context found for response");
                return;
            }

            // 取消超时任务
            cancelTimeoutTask(context.requestId);

            // 保留消息（在try-finally中确保释放）
            msg.retain();

            try {
                long responseTime = (System.nanoTime() - context.startTime) / 1_000_000;

                // 从channelInfoMap获取isHttps信息（优化：减少查找次数）
                ChannelInfo channelInfo = channelInfoMap.get(ctx.channel());
                boolean isHttps = channelInfo != null && channelInfo.isHttps;

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
                    final long finalResponseTime = responseTime;
                    safeExecuteCallback(() -> context.callback.onResponse(burpResponse, finalResponseTime));
                }

            } finally {
                ReferenceCountUtil.release(msg);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ResponseContext context = ctx.channel().attr(CONTEXT_KEY).get();

            // 检查是否为响应过大异常
            if (cause instanceof TooLongFrameException) {
                if (context != null) {
                    handleOversizedResponse(ctx.channel(), context);
                } else {
                    logging.logToError("[NettyManager] Response too large but context is null");
                    ctx.close();
                }
                return;
            }

            if (context != null) {
                handleChannelError(ctx.channel(), cause, context);
            } else {
                ctx.close();
            }
        }
    }

    /**
     * 处理超大响应 - 新增方法
     */
    private void handleOversizedResponse(Channel channel, ResponseContext context) {
        // 取消超时任务
        cancelTimeoutTask(context.requestId);

        try {
            long responseTime = (System.nanoTime() - context.startTime) / 1_000_000;

            oversizedResponses.incrementAndGet();

            logging.logToOutput("[NettyManager] Request #" + context.requestId +
                    " response exceeds size limit, returning placeholder response");

            // 从channelInfoMap获取isHttps信息
            ChannelInfo channelInfo = channelInfoMap.get(channel);
            boolean isHttps = channelInfo != null && channelInfo.isHttps;

            // 创建替代响应
            HttpResponse burpResponse = createOversizedResponse(isHttps);

            // 释放资源
            requestSemaphore.release();
            acquiredPermits.decrementAndGet();
            activeRequests.decrementAndGet();
            successRequests.incrementAndGet();

            // 关闭连接（超大响应不复用连接）
            safeCloseChannel(channel);
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();

            // 完成Future
            context.future.complete(burpResponse);

            // 调用回调
            if (context.callback != null) {
                final long finalResponseTime = responseTime;
                safeExecuteCallback(() -> context.callback.onResponse(burpResponse, finalResponseTime));
            }

        } catch (Exception e) {
            logging.logToError("[NettyManager] Error handling oversized response: " + e.getMessage());
            handleChannelError(channel, e, context);
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
            safeCloseChannel(channel);
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();
            return;
        }

        ChannelInfo info = channelInfoMap.get(channel);
        if (info != null && channel.isActive()) {
            String key = info.host + ":" + info.port;
            Queue<Channel> pool = channelPools.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

            // 更新最后使用时间（新增）
            channel.attr(LAST_USED_KEY).set(System.currentTimeMillis());

            // 限制池大小
            if (pool.size() < 300) {
                pool.offer(channel);
                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Returned connection to pool: " + key);
                }
            } else {
                safeCloseChannel(channel);
                channelInfoMap.remove(channel);
                connectionClosed.incrementAndGet();
            }
        } else {
            // 连接无效，关闭（优化：使用安全关闭）
            safeCloseChannel(channel);
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();
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

        // 修改：对于可能有 body 的方法，总是设置 Content-Length（即使为0）
        String method = burpRequest.method().toUpperCase();
        if (method.equals("POST") || method.equals("PUT") || method.equals("PATCH") ||
                method.equals("DELETE") || content.readableBytes() > 0) {
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
        StringBuilder responseBuilder = stringBuilderPool.get();
        responseBuilder.setLength(0);

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
            // 第一步：取消所有超时任务（新增）
            cancelAllTimeoutTasks();

            // 第二步：停止监控线程
            shutdownMonitorExecutor();

            // 第三步：停止超时监控线程（新增）
            shutdownTimeoutExecutor();

            // 第四步：等待当前请求完成
            waitForPendingRequests();

            // 第五步：关闭所有池中的连接
            closeAllPooledConnections();

            // 第六步：关闭EventLoopGroup
            shutdownEventLoopGroup();

            // 第七步：关闭业务线程池
            shutdownBusinessExecutor();

            logging.logToOutput(String.format("[NettyManager] %s shutdown complete. Total requests: %d, Success: %d, Failed: %d, Retry: %d, Timeout: %d, Oversized: %d, Cleaned: %d",
                    configManager.getPluginName(), totalRequests.get(), successRequests.get(),
                    failedRequests.get(), retryRequests.get(), timeoutRequests.get(), oversizedResponses.get(), poolCleaned.get()));

        } catch (Exception e) {
            logging.logToError("[NettyManager] Error occurred during shutdown: " + e.getMessage());
        } finally {
            shutdownLatch.countDown();
        }
    }

    /**
     * 取消所有超时任务（新增）
     */
    private void cancelAllTimeoutTasks() {
        try {
            logging.logToOutput("[NettyManager] Cancelling all timeout tasks...");
            int cancelledCount = 0;
            for (Map.Entry<Long, ScheduledFuture<?>> entry : timeoutTasks.entrySet()) {
                if (entry.getValue().cancel(false)) {
                    cancelledCount++;
                }
            }
            timeoutTasks.clear();
            logging.logToOutput("[NettyManager] Cancelled " + cancelledCount + " timeout tasks");
        } catch (Exception e) {
            logging.logToError("[NettyManager] Error cancelling timeout tasks: " + e.getMessage());
        }
    }

    /**
     * 关闭超时监控线程池（新增）
     */
    private void shutdownTimeoutExecutor() {
        try {
            logging.logToOutput("[NettyManager] Shutting down timeout executor...");
            timeoutExecutor.shutdown();

            if (!timeoutExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                timeoutExecutor.shutdownNow();

                if (!timeoutExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                    logging.logToError("[NettyManager] Timeout executor forced shutdown failed");
                }
            }
            logging.logToOutput("[NettyManager] Timeout executor shutdown complete");
        } catch (InterruptedException e) {
            timeoutExecutor.shutdownNow();
            Thread.currentThread().interrupt();
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
     * 响应上下文 - 修改增加重试相关字段和总超时字段
     */
    private static class ResponseContext {
        final CompletableFuture<HttpResponse> future;
        final ResponseCallback callback;
        final long startTime;
        final long requestId;
        final boolean keepAlive;
        final HttpRequest originalRequest; // 新增：保存原始请求用于重试
        final int retryCount; // 新增：当前重试次数
        final long totalStartTime; // 新增：总开始时间（用于总超时控制）

        ResponseContext(CompletableFuture<HttpResponse> future, ResponseCallback callback,
                        long startTime, long requestId, boolean keepAlive,
                        HttpRequest originalRequest, int retryCount, long totalStartTime) {
            this.future = future;
            this.callback = callback;
            this.startTime = startTime;
            this.requestId = requestId;
            this.keepAlive = keepAlive;
            this.originalRequest = originalRequest;
            this.retryCount = retryCount;
            this.totalStartTime = totalStartTime;
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