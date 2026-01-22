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
 * NettyManager - 增强修复版
 *
 * 主要修复：
 * 1. ResourceGuard：统一管理信号量和计数器，防止泄漏
 * 2. 连接池污染：清理旧context
 * 3. 连接状态检查：更完整的验证
 * 4. 超时任务：确保清理
 * 5. 统一异常处理：所有路径都正确释放资源
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

    // 超时监控线程池
    private final ScheduledExecutorService timeoutExecutor;

    // 配置管理器
    private final PluginConfigManager configManager;

    // 配置
    private static final String PROXY_HOST = "127.0.0.1";
    private final int PROXY_PORT;
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_SEC = 120;
    private static final int WRITE_TIMEOUT_SEC = 60;
    private static final int MAX_RESPONSE_SIZE = 30 * 1024 * 1024;

    // 超时配置
    private static final long OVERALL_REQUEST_TIMEOUT_MS = 300000;
    private static final long SSL_HANDSHAKE_TIMEOUT_MS = 60000;
    private static final long TOTAL_RETRY_TIMEOUT_MS = 600000;
    private static final long SEMAPHORE_ACQUIRE_TIMEOUT_SEC = 30;

    // 重试配置
    private static final int MAX_RETRY_COUNT = 4;
    private static final long RETRY_DELAY_MS = 500;

    // 连接池清理配置
    private static final long POOL_CLEANUP_INTERVAL_SEC = 60;
    private static final long CHANNEL_IDLE_TIMEOUT_MS = 300000;

    // 统计
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong successRequests = new AtomicLong(0);
    private final AtomicLong failedRequests = new AtomicLong(0);
    private final AtomicLong retryRequests = new AtomicLong(0);
    private final AtomicLong oversizedResponses = new AtomicLong(0);
    private final AtomicLong timeoutRequests = new AtomicLong(0);
    private final AtomicLong connectionCreated = new AtomicLong(0);
    private final AtomicLong connectionReused = new AtomicLong(0);
    private final AtomicLong connectionClosed = new AtomicLong(0);
    private final AtomicLong poolCleaned = new AtomicLong(0);
    private final AtomicLong semaphoreTimeouts = new AtomicLong(0);

    // 调试开关
    private static final boolean DEBUG = false;

    // 关闭控制
    private final AtomicBoolean isShutdown = new AtomicBoolean(false);
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);
    private final AtomicBoolean shutdownStarted = new AtomicBoolean(false);

    // 超时任务跟踪
    private final ConcurrentHashMap<Long, ScheduledFuture<?>> timeoutTasks = new ConcurrentHashMap<>();

    // AttributeKey 缓存
    private static final AttributeKey<ResponseContext> CONTEXT_KEY = AttributeKey.valueOf("context");
    private static final AttributeKey<Long> LAST_USED_KEY = AttributeKey.valueOf("lastUsed");

    // StringBuilder 对象池
    private final ThreadLocal<StringBuilder> stringBuilderPool = ThreadLocal.withInitial(() -> new StringBuilder(512));

    /**
     * ResourceGuard - 资源保护类
     * 确保信号量和计数器同步释放，防止泄漏
     */
    private class ResourceGuard {
        private final long requestId;
        private final AtomicBoolean permitAcquired = new AtomicBoolean(false);
        private final AtomicBoolean released = new AtomicBoolean(false);

        ResourceGuard(long requestId) {
            this.requestId = requestId;
        }

        void acquirePermit() {
            if (permitAcquired.compareAndSet(false, true)) {
                acquiredPermits.incrementAndGet();
                activeRequests.incrementAndGet();
            }
        }

        void release() {
            if (released.compareAndSet(false, true)) {
                if (permitAcquired.get()) {
                    requestSemaphore.release();
                    acquiredPermits.decrementAndGet();
                    activeRequests.decrementAndGet();
                }
            }
        }

        boolean isAcquired() {
            return permitAcquired.get();
        }

        boolean isReleased() {
            return released.get();
        }
    }

    private NettyManager(Logging logging, CompressionUtils compressionUtils) {
        this.logging = logging;
        this.compressionUtils = compressionUtils;
        this.configManager = PluginConfigManager.getInstance();

        this.PROXY_PORT = configManager.getNettyPort();

        try {
            this.sslContext = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }

        this.eventLoopGroup = new NioEventLoopGroup(Math.min(Runtime.getRuntime().availableProcessors() * 2, 16));

        this.bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_REUSEADDR, true);

        this.businessExecutor = new ThreadPoolExecutor(
                10, 50,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                r -> {
                    Thread t = new Thread(r, "netty-business-" + BUSINESS_THREAD_COUNTER.getAndIncrement());
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        this.monitorExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "netty-monitor");
            t.setDaemon(true);
            return t;
        });

        this.timeoutExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "netty-timeout-monitor");
            t.setDaemon(true);
            return t;
        });

        startMonitorThread();
        startPoolCleanupThread();

        logging.logToOutput("[NettyManager] Initialization complete, EventLoop threads: " +
                ((NioEventLoopGroup)eventLoopGroup).executorCount() +
                ", Proxy: " + PROXY_HOST + ":" + PROXY_PORT +
                ", Max response size: " + (MAX_RESPONSE_SIZE / 1024 / 1024) + "MB" +
                ", Max retry count: " + MAX_RETRY_COUNT +
                ", Semaphore acquire timeout: " + SEMAPHORE_ACQUIRE_TIMEOUT_SEC + "s" +
                ", Plugin: " + configManager.getPluginName());
    }

    private void startMonitorThread() {
        monitorExecutor.scheduleAtFixedRate(() -> {
            if (isShutdown.get()) {
                return;
            }

            if (DEBUG) {
                logging.logToOutput(String.format(
                        "[NettyManager Monitor] Permits: %d/%d, Active: %d, Total: %d, Success: %d, Failed: %d, Retry: %d, Timeout: %d, Semaphore Timeouts: %d, Oversized: %d, " +
                                "Connections - Created: %d, Reused: %d, Closed: %d, Pools: %d, Cleaned: %d",
                        requestSemaphore.availablePermits(), 300,
                        activeRequests.get(),
                        totalRequests.get(),
                        successRequests.get(),
                        failedRequests.get(),
                        retryRequests.get(),
                        timeoutRequests.get(),
                        semaphoreTimeouts.get(),
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

    private void startPoolCleanupThread() {
        monitorExecutor.scheduleWithFixedDelay(() -> {
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

    private void cleanupConnectionPools() {
        long now = System.currentTimeMillis();
        int totalCleaned = 0;

        for (Map.Entry<String, Queue<Channel>> entry : channelPools.entrySet()) {
            Queue<Channel> pool = entry.getValue();
            List<Channel> toRemove = new ArrayList<>();

            for (Channel channel : pool) {
                if (!channel.isActive()) {
                    toRemove.add(channel);
                    continue;
                }

                Long lastUsed = channel.attr(LAST_USED_KEY).get();
                if (lastUsed != null && (now - lastUsed) > CHANNEL_IDLE_TIMEOUT_MS) {
                    toRemove.add(channel);
                }
            }

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

    private int getTotalPooledConnections() {
        return channelPools.values().stream()
                .mapToInt(Queue::size)
                .sum();
    }

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

    public CompletableFuture<HttpResponse> sendRequest(HttpRequest burpRequest, ResponseCallback callback) {
        long totalStartTime = System.currentTimeMillis();
        return sendRequestWithRetry(burpRequest, callback, 0, totalStartTime);
    }

    /**
     * 核心请求方法 - 使用ResourceGuard确保资源正确释放
     */
    private CompletableFuture<HttpResponse> sendRequestWithRetry(HttpRequest burpRequest, ResponseCallback callback,
                                                                 int retryCount, long totalStartTime) {
        CompletableFuture<HttpResponse> future = new CompletableFuture<>();

        if (isShutdown.get()) {
            future.completeExceptionally(new IllegalStateException("NettyManager is shutdown"));
            return future;
        }

        // 检查总超时
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

        if (DEBUG && retryCount == 0) {
            logging.logToOutput("[NettyManager] Request #" + requestId + " starting, URL: " + burpRequest.url());
        } else if (DEBUG && retryCount > 0) {
            logging.logToOutput("[NettyManager] Request #" + requestId + " retry " + retryCount + ", URL: " + burpRequest.url());
        }

        // 创建ResourceGuard统一管理资源
        ResourceGuard guard = new ResourceGuard(requestId);

        try {
            // 尝试获取信号量
            if (!requestSemaphore.tryAcquire(SEMAPHORE_ACQUIRE_TIMEOUT_SEC, TimeUnit.SECONDS)) {
                semaphoreTimeouts.incrementAndGet();
                failedRequests.incrementAndGet();

                String errorMsg = "Failed to acquire request permit within " + SEMAPHORE_ACQUIRE_TIMEOUT_SEC + " seconds (system overloaded)";

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + requestId + " " + errorMsg);
                }

                RejectedExecutionException exception = new RejectedExecutionException(errorMsg);
                future.completeExceptionally(exception);

                if (callback != null) {
                    safeExecuteCallback(() -> callback.onError(exception));
                }

                return future;
            }

            // 标记资源已获取
            guard.acquirePermit();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            failedRequests.incrementAndGet();

            future.completeExceptionally(e);
            if (callback != null) {
                safeExecuteCallback(() -> callback.onError(e));
            }

            return future;
        }

        // 提交到线程池处理
        CompletableFuture.runAsync(() -> {
            try {
                if (isShutdown.get()) {
                    throw new IllegalStateException("NettyManager is shutdown");
                }

                RequestInfo requestInfo = parseRequest(burpRequest);
                boolean shouldKeepAlive = shouldUseKeepAlive(burpRequest);

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + requestId +
                            " - Host: " + requestInfo.host + ", Keep-Alive: " + shouldKeepAlive);
                }

                CompletableFuture<Channel> channelFuture = shouldKeepAlive
                        ? acquirePooledChannel(requestInfo.host, requestInfo.port, requestInfo.isHttps)
                        : createNewChannel(requestInfo.host, requestInfo.port, requestInfo.isHttps);

                channelFuture.thenAccept(channel -> {
                    sendRequestOnChannel(channel, requestInfo, burpRequest, future, callback,
                            requestId, shouldKeepAlive, retryCount, totalStartTime, guard);
                }).exceptionally(ex -> {
                    handleRequestError(ex, future, callback, requestId, burpRequest, retryCount, totalStartTime, guard);
                    return null;
                });

            } catch (Exception e) {
                handleRequestError(e, future, callback, requestId, burpRequest, retryCount, totalStartTime, guard);
            }
        }, businessExecutor).exceptionally(ex -> {
            // 提交失败，使用guard释放资源
            guard.release();
            failedRequests.incrementAndGet();
            logging.logToError("[NettyManager] Request #" + requestId + " failed to submit: " + ex.getMessage());

            future.completeExceptionally(ex);
            if (callback != null) {
                safeExecuteCallback(() -> callback.onError(ex));
            }

            return null;
        });

        return future;
    }

    private boolean shouldUseKeepAlive(HttpRequest request) {
        String connectionHeader = request.headerValue("Connection");
        if (connectionHeader != null) {
            return !connectionHeader.equalsIgnoreCase("close");
        }
        return true;
    }

    private boolean isRetryableError(Throwable ex) {
        if (ex == null) return false;

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

        String className = ex.getClass().getName();
        if (className.contains("DecoderException") || className.contains("EncoderException")) {
            return false;
        }

        String message = ex.getMessage();
        if (message != null) {
            String lowerMessage = message.toLowerCase();

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

        if (DEBUG) {
            logging.logToOutput("[NettyManager] Unknown error type with null message: " + className);
        }

        return false;
    }

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
            return exceptionType + " (no message)";
        }
    }

    /**
     * 统一错误处理 - 使用ResourceGuard确保资源释放
     */
    private void handleRequestError(Throwable ex, CompletableFuture<HttpResponse> future,
                                    ResponseCallback callback, long requestId,
                                    HttpRequest burpRequest, int retryCount, long totalStartTime,
                                    ResourceGuard guard) {

        // 检查总超时
        long elapsedTime = System.currentTimeMillis() - totalStartTime;
        if (elapsedTime > TOTAL_RETRY_TIMEOUT_MS) {
            guard.release();
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
            guard.release();
            retryRequests.incrementAndGet();

            if (DEBUG) {
                logging.logToOutput("[NettyManager] Request #" + requestId + " will retry: " +
                        getErrorDescription(ex) + " (" + (retryCount + 1) + "/" + MAX_RETRY_COUNT + ")");
            }

            scheduleRetry(burpRequest, callback, future, requestId, retryCount, totalStartTime);
            return;
        }

        // 最终失败
        guard.release();
        failedRequests.incrementAndGet();

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

    private void scheduleRetry(HttpRequest burpRequest, ResponseCallback callback,
                               CompletableFuture<HttpResponse> future, long requestId,
                               int retryCount, long totalStartTime) {
        try {
            CompletableFuture.runAsync(() -> {
                try {
                    Thread.sleep(RETRY_DELAY_MS);
                    CompletableFuture<HttpResponse> retryFuture = sendRequestWithRetry(burpRequest, callback, retryCount + 1, totalStartTime);

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
            logging.logToError("[NettyManager] Request #" + requestId + " retry rejected: " + getErrorDescription(ree));
            failedRequests.incrementAndGet();
            future.completeExceptionally(ree);
            if (callback != null) {
                safeExecuteCallback(() -> callback.onError(ree));
            }
        }
    }

    private void safeExecuteCallback(Runnable callback) {
        try {
            businessExecutor.execute(callback);
        } catch (RejectedExecutionException e) {
            try {
                callback.run();
            } catch (Exception ex) {
                logging.logToError("[NettyManager] Callback execution error: " + ex.getMessage());
            }
        }
    }

    /**
     * 获取连接池连接 - 修复：清理旧context，改进状态检查
     */
    private CompletableFuture<Channel> acquirePooledChannel(String host, int port, boolean isHttps) {
        String key = host + ":" + port;
        Queue<Channel> pool = channelPools.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

        Channel channel;
        while ((channel = pool.poll()) != null) {
            // 更完整的状态检查
            // 注意：isInputShutdown/isOutputShutdown 只在 SocketChannel 中存在
            boolean isValid = channel.isActive() && channel.isOpen();

            // 如果是 SocketChannel，额外检查输入输出状态
            if (isValid && channel instanceof SocketChannel) {
                SocketChannel socketChannel = (SocketChannel) channel;
                isValid = !socketChannel.isInputShutdown() && !socketChannel.isOutputShutdown();
            }

            if (isValid) {
                // 修复：清理旧context
                channel.attr(CONTEXT_KEY).set(null);
                channel.attr(LAST_USED_KEY).set(System.currentTimeMillis());
                connectionReused.incrementAndGet();

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Reusing connection for " + key);
                }
                return CompletableFuture.completedFuture(channel);
            } else {
                channelInfoMap.remove(channel);
                safeCloseChannel(channel);
                connectionClosed.incrementAndGet();
            }
        }

        return createNewChannel(host, port, isHttps);
    }

    private CompletableFuture<Channel> createNewChannel(String host, int port, boolean isHttps) {
        CompletableFuture<Channel> future = new CompletableFuture<>();

        Bootstrap b = bootstrap.clone();
        b.handler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ChannelPipeline p = ch.pipeline();

                p.addLast("httpProxy", new HttpProxyHandler(
                        new InetSocketAddress(PROXY_HOST, PROXY_PORT)));

                if (isHttps) {
                    p.addLast("ssl", sslContext.newHandler(ch.alloc(), host, port));
                }

                p.addLast("readTimeout", new ReadTimeoutHandler(READ_TIMEOUT_SEC));
                p.addLast("writeTimeout", new WriteTimeoutHandler(WRITE_TIMEOUT_SEC));

                p.addLast("codec", new HttpClientCodec());
                p.addLast("aggregator", new HttpObjectAggregator(MAX_RESPONSE_SIZE));

                p.addLast("handler", new ResponseChannelHandler());
            }
        });

        ChannelFuture connectFuture = b.connect(host, port);

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
                sslTimeoutTask.cancel(false);

                if (f.isSuccess()) {
                    Channel channel = f.channel();
                    channelInfoMap.put(channel, new ChannelInfo(host, port, isHttps));
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
     * 发送请求到Channel - 修复：接收ResourceGuard参数
     */
    private void sendRequestOnChannel(Channel channel, RequestInfo requestInfo,
                                      HttpRequest burpRequest, CompletableFuture<HttpResponse> future,
                                      ResponseCallback callback, long requestId, boolean keepAlive,
                                      int retryCount, long totalStartTime, ResourceGuard guard) {
        FullHttpRequest nettyRequest = null;
        try {
            nettyRequest = convertToNettyRequest(burpRequest, requestInfo, keepAlive);

            long startTime = System.nanoTime();

            // 创建context并包含guard
            ResponseContext context = new ResponseContext(future, callback, startTime, requestId,
                    keepAlive, burpRequest, retryCount, totalStartTime, guard);
            channel.attr(CONTEXT_KEY).set(context);

            // 修复：注册超时任务
            ScheduledFuture<?> timeoutTask = timeoutExecutor.schedule(() -> {
                if (!future.isDone()) {
                    String errorMsg = "Overall request timeout after " + (OVERALL_REQUEST_TIMEOUT_MS / 1000) + "s";
                    if (DEBUG) {
                        logging.logToOutput("[NettyManager] Request #" + requestId + " " + errorMsg);
                    }
                    timeoutRequests.incrementAndGet();

                    safeCloseChannel(channel);
                    channelInfoMap.remove(channel);
                    connectionClosed.incrementAndGet();

                    TimeoutException timeoutEx = new TimeoutException(errorMsg);
                    handleChannelError(channel, timeoutEx, context);
                }
            }, OVERALL_REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);

            timeoutTasks.put(requestId, timeoutTask);

            final FullHttpRequest finalRequest = nettyRequest;

            channel.writeAndFlush(nettyRequest).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    cancelTimeoutTask(requestId);
                    handleChannelError(channel, f.cause(), context);
                } else if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + requestId + " sent successfully");
                }
            });

        } catch (Exception e) {
            ReferenceCountUtil.safeRelease(nettyRequest);
            ResponseContext context = new ResponseContext(future, callback, 0, requestId,
                    keepAlive, burpRequest, retryCount, totalStartTime, guard);
            handleChannelError(channel, e, context);
        }
    }

    /**
     * 修复：取消超时任务并从map中移除
     */
    private void cancelTimeoutTask(long requestId) {
        ScheduledFuture<?> task = timeoutTasks.remove(requestId);
        if (task != null) {
            task.cancel(false);
        }
    }

    /**
     * Channel错误处理 - 修复：使用guard释放资源
     */
    private void handleChannelError(Channel channel, Throwable cause, ResponseContext context) {
        cancelTimeoutTask(context.requestId);

        safeCloseChannel(channel);
        channelInfoMap.remove(channel);
        connectionClosed.incrementAndGet();

        if (DEBUG) {
            logging.logToOutput("[NettyManager] Request #" + context.requestId +
                    " channel error: " + getErrorDescription(cause));
        }

        long elapsedTime = System.currentTimeMillis() - context.totalStartTime;
        if (elapsedTime > TOTAL_RETRY_TIMEOUT_MS) {
            context.guard.release();
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

        if (context.retryCount < MAX_RETRY_COUNT && isRetryableError(cause) && !isShutdown.get()) {
            context.guard.release();
            retryRequests.incrementAndGet();

            if (DEBUG) {
                logging.logToOutput("[NettyManager] Request #" + context.requestId +
                        " will retry: " + getErrorDescription(cause));
            }

            scheduleRetry(context.originalRequest, context.callback, context.future,
                    context.requestId, context.retryCount, context.totalStartTime);
            return;
        }

        context.guard.release();
        failedRequests.incrementAndGet();

        if (cause instanceof TimeoutException || cause instanceof ReadTimeoutException ||
                cause instanceof WriteTimeoutException) {
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
     * Response处理器 - 修复：使用guard释放资源
     */
    private class ResponseChannelHandler extends SimpleChannelInboundHandler<FullHttpResponse> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
            ResponseContext context = ctx.channel().attr(CONTEXT_KEY).get();

            if (context == null) {
                logging.logToError("[NettyManager] No context found for response");
                return;
            }

            cancelTimeoutTask(context.requestId);

            msg.retain();

            try {
                long responseTime = (System.nanoTime() - context.startTime) / 1_000_000;

                ChannelInfo channelInfo = channelInfoMap.get(ctx.channel());
                boolean isHttps = channelInfo != null && channelInfo.isHttps;

                HttpResponse burpResponse = convertToBurpResponse(msg, isHttps);

                // 使用guard释放资源
                context.guard.release();
                successRequests.incrementAndGet();

                if (DEBUG) {
                    logging.logToOutput("[NettyManager] Request #" + context.requestId +
                            " completed in " + responseTime + "ms");
                }

                if (context.keepAlive && !isConnectionClose(msg)) {
                    // 修复：清理context后返回连接池
                    ctx.channel().attr(CONTEXT_KEY).set(null);
                    returnToPool(ctx.channel());
                } else {
                    ctx.close();
                    channelInfoMap.remove(ctx.channel());
                    connectionClosed.incrementAndGet();
                }

                context.future.complete(burpResponse);

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
     * 处理超大响应 - 修复：使用guard释放资源
     */
    private void handleOversizedResponse(Channel channel, ResponseContext context) {
        cancelTimeoutTask(context.requestId);

        try {
            long responseTime = (System.nanoTime() - context.startTime) / 1_000_000;

            oversizedResponses.incrementAndGet();

            logging.logToOutput("[NettyManager] Request #" + context.requestId +
                    " response exceeds size limit");

            ChannelInfo channelInfo = channelInfoMap.get(channel);
            boolean isHttps = channelInfo != null && channelInfo.isHttps;

            HttpResponse burpResponse = createOversizedResponse(isHttps);

            // 使用guard释放资源
            context.guard.release();
            successRequests.incrementAndGet();

            safeCloseChannel(channel);
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();

            context.future.complete(burpResponse);

            if (context.callback != null) {
                final long finalResponseTime = responseTime;
                safeExecuteCallback(() -> context.callback.onResponse(burpResponse, finalResponseTime));
            }

        } catch (Exception e) {
            logging.logToError("[NettyManager] Error handling oversized response: " + e.getMessage());
            handleChannelError(channel, e, context);
        }
    }

    private boolean isConnectionClose(FullHttpResponse response) {
        String connection = response.headers().get(HttpHeaderNames.CONNECTION);
        return connection != null && connection.equalsIgnoreCase("close");
    }

    private void returnToPool(Channel channel) {
        if (isShutdown.get()) {
            safeCloseChannel(channel);
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();
            return;
        }

        ChannelInfo info = channelInfoMap.get(channel);
        if (info != null && channel.isActive()) {
            String key = info.host + ":" + info.port;
            Queue<Channel> pool = channelPools.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

            channel.attr(LAST_USED_KEY).set(System.currentTimeMillis());

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
            safeCloseChannel(channel);
            channelInfoMap.remove(channel);
            connectionClosed.incrementAndGet();
        }
    }

    private RequestInfo parseRequest(HttpRequest request) {
        String url = request.url();
        RequestInfo info = new RequestInfo();

        if (url.startsWith("https://")) {
            info.isHttps = true;
            url = url.substring(8);
        } else if (url.startsWith("http://")) {
            info.isHttps = false;
            url = url.substring(7);
        }

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

    private FullHttpRequest convertToNettyRequest(HttpRequest burpRequest, RequestInfo info, boolean keepAlive) {
        ByteBuf content = burpRequest.body().length() > 0
                ? Unpooled.wrappedBuffer(burpRequest.body().getBytes())
                : Unpooled.EMPTY_BUFFER;

        FullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.valueOf(burpRequest.method()),
                info.path,
                content
        );

        for (HttpHeader header : burpRequest.headers()) {
            String name = header.name();
            if (!shouldSkipHeader(name)) {
                if (name.equalsIgnoreCase("Connection")) {
                    request.headers().set(HttpHeaderNames.CONNECTION,
                            keepAlive ? HttpHeaderValues.KEEP_ALIVE : HttpHeaderValues.CLOSE);
                } else {
                    request.headers().add(name, header.value());
                }
            }
        }

        request.headers().set(HttpHeaderNames.HOST, info.host);

        String method = burpRequest.method().toUpperCase();
        if (method.equals("POST") || method.equals("PUT") || method.equals("PATCH") ||
                method.equals("DELETE") || content.readableBytes() > 0) {
            request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        }

        if (!request.headers().contains(HttpHeaderNames.CONNECTION)) {
            request.headers().set(HttpHeaderNames.CONNECTION,
                    keepAlive ? HttpHeaderValues.KEEP_ALIVE : HttpHeaderValues.CLOSE);
        }

        return request;
    }

    private HttpResponse convertToBurpResponse(FullHttpResponse nettyResponse, boolean isHttps) {
        StringBuilder responseBuilder = stringBuilderPool.get();
        responseBuilder.setLength(0);

        responseBuilder.append("HTTP/1.1 ")
                .append(nettyResponse.status().code())
                .append(" ")
                .append(nettyResponse.status().reasonPhrase())
                .append("\r\n");

        for (Map.Entry<String, String> header : nettyResponse.headers()) {
            responseBuilder.append(header.getKey())
                    .append(": ")
                    .append(header.getValue())
                    .append("\r\n");
        }
        responseBuilder.append("\r\n");

        byte[] headerBytes = responseBuilder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = new byte[nettyResponse.content().readableBytes()];
        nettyResponse.content().readBytes(bodyBytes);

        byte[] fullResponse = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, fullResponse, headerBytes.length, bodyBytes.length);

        return HttpResponse.httpResponse(ByteArray.byteArray(fullResponse));
    }

    private boolean shouldSkipHeader(String headerName) {
        String lower = headerName.toLowerCase();
        return lower.equals("content-length") ||
                lower.equals("host");
    }

    public void shutdown() {
        if (!shutdownStarted.compareAndSet(false, true)) {
            try {
                shutdownLatch.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return;
        }

        logging.logToOutput("[NettyManager] Starting shutdown for " + configManager.getPluginName() + "...");

        isShutdown.set(true);

        CompletableFuture.runAsync(this::performShutdown);
    }

    private void performShutdown() {
        try {
            cancelAllTimeoutTasks();
            shutdownMonitorExecutor();
            shutdownTimeoutExecutor();
            waitForPendingRequests();
            closeAllPooledConnections();
            shutdownEventLoopGroup();
            shutdownBusinessExecutor();

            logging.logToOutput(String.format("[NettyManager] %s shutdown complete. Total: %d, Success: %d, Failed: %d, Retry: %d, Timeout: %d, Semaphore Timeouts: %d, Oversized: %d, Cleaned: %d",
                    configManager.getPluginName(), totalRequests.get(), successRequests.get(),
                    failedRequests.get(), retryRequests.get(), timeoutRequests.get(), semaphoreTimeouts.get(), oversizedResponses.get(), poolCleaned.get()));

        } catch (Exception e) {
            logging.logToError("[NettyManager] Error during shutdown: " + e.getMessage());
        } finally {
            shutdownLatch.countDown();
        }
    }

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
                logging.logToOutput("[NettyManager] Business executor timeout, forcing shutdown...");
                businessExecutor.shutdownNow();

                if (!businessExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                    logging.logToError("[NettyManager] Business executor forced shutdown failed");
                } else {
                    logging.logToOutput("[NettyManager] Business executor forced shutdown complete");
                }
            } else {
                logging.logToOutput("[NettyManager] Business executor graceful shutdown complete");
            }
        } catch (InterruptedException e) {
            businessExecutor.shutdownNow();
            Thread.currentThread().interrupt();
            logging.logToOutput("[NettyManager] Business executor shutdown interrupted");
        }
    }

    public boolean awaitShutdown(long timeout, TimeUnit unit) {
        try {
            return shutdownLatch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static class RequestInfo {
        String host;
        int port;
        String path;
        boolean isHttps;
    }

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
     * ResponseContext - 修复：包含ResourceGuard
     */
    private static class ResponseContext {
        final CompletableFuture<HttpResponse> future;
        final ResponseCallback callback;
        final long startTime;
        final long requestId;
        final boolean keepAlive;
        final HttpRequest originalRequest;
        final int retryCount;
        final long totalStartTime;
        final ResourceGuard guard;  // 新增

        ResponseContext(CompletableFuture<HttpResponse> future, ResponseCallback callback,
                        long startTime, long requestId, boolean keepAlive,
                        HttpRequest originalRequest, int retryCount, long totalStartTime,
                        ResourceGuard guard) {
            this.future = future;
            this.callback = callback;
            this.startTime = startTime;
            this.requestId = requestId;
            this.keepAlive = keepAlive;
            this.originalRequest = originalRequest;
            this.retryCount = retryCount;
            this.totalStartTime = totalStartTime;
            this.guard = guard;
        }
    }

    public interface ResponseCallback {
        void onResponse(HttpResponse response, long responseTimeMs);
        void onError(Throwable error);
    }
}