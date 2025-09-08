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
import pzfzr.model.ModifiedRequestResponse;

import javax.net.ssl.SSLException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NettyManager - 高性能HTTP客户端管理器
 * 使用Netty实现，支持高并发、SOCKS5代理、流控等特性
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
    private final ChannelPool channelPool;

    // 流控
    private final Semaphore requestSemaphore = new Semaphore(300);

    // 业务线程池
    private final ExecutorService businessExecutor;

    // 配置
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 20808;
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_SEC = 120;
    private static final int WRITE_TIMEOUT_SEC = 60;

    // 统计
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong successRequests = new AtomicLong(0);
    private final AtomicLong failedRequests = new AtomicLong(0);

    private volatile boolean isShutdown = false;

    private NettyManager(Logging logging, CompressionUtils compressionUtils) {
        this.logging = logging;
        this.compressionUtils = compressionUtils;

        try {
            // 创建SSL上下文
            this.sslContext = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }

        // 创建EventLoopGroup - 使用较少的线程，因为Netty是非阻塞的
        this.eventLoopGroup = new NioEventLoopGroup(Math.min(Runtime.getRuntime().availableProcessors() * 2, 16));

        // 创建Bootstrap
        this.bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_REUSEADDR, true);

        // 创建连接池
        this.channelPool = new ChannelPool(100);

        // 创建业务线程池
        this.businessExecutor = new ThreadPoolExecutor(
                10, 50,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                r -> {
                    Thread t = new Thread(r, "netty-business-" + Thread.currentThread().getId());
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        logging.logToOutput("[NettyManager] 初始化完成，EventLoop线程数: " +
                ((NioEventLoopGroup)eventLoopGroup).executorCount() +
                "，代理: " + PROXY_HOST + ":" + PROXY_PORT);
    }

    /**
     * 获取单例实例
     */
    public static NettyManager getInstance(Logging logging, CompressionUtils compressionUtils) {
        if (instance == null) {
            synchronized (NettyManager.class) {
                if (instance == null) {
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
     * 发送HTTP请求
     */
    public CompletableFuture<HttpResponse> sendRequest(HttpRequest burpRequest, ResponseCallback callback) {
        CompletableFuture<HttpResponse> future = new CompletableFuture<>();

        if (isShutdown) {
            future.completeExceptionally(new IllegalStateException("NettyManager is shutdown"));
            return future;
        }

        // 流控 - 异步获取许可
        CompletableFuture.runAsync(() -> {
            try {
                requestSemaphore.acquire();
                totalRequests.incrementAndGet();

                // 解析请求
                RequestInfo requestInfo = parseRequest(burpRequest);

                // 获取或创建Channel
                channelPool.acquire(requestInfo.host, requestInfo.port, requestInfo.isHttps)
                        .thenAccept(channel -> {
                            // 发送请求
                            sendRequestOnChannel(channel, requestInfo, burpRequest, future, callback);
                        })
                        .exceptionally(ex -> {
                            requestSemaphore.release();
                            failedRequests.incrementAndGet();
                            future.completeExceptionally(ex);
                            if (callback != null) {
                                businessExecutor.execute(() -> callback.onError(ex));
                            }
                            return null;
                        });

            } catch (Exception e) {
                requestSemaphore.release();
                failedRequests.incrementAndGet();
                future.completeExceptionally(e);
                if (callback != null) {
                    businessExecutor.execute(() -> callback.onError(e));
                }
            }
        }, businessExecutor);

        return future;
    }

    /**
     * 在Channel上发送请求
     */
    private void sendRequestOnChannel(Channel channel, RequestInfo requestInfo,
                                      HttpRequest burpRequest, CompletableFuture<HttpResponse> future,
                                      ResponseCallback callback) {
        try {
            // 转换为Netty请求
            FullHttpRequest nettyRequest = convertToNettyRequest(burpRequest, requestInfo);

            // 记录开始时间
            long startTime = System.nanoTime();

            // 设置响应处理器
            channel.attr(AttributeKey.<ResponseHandler>valueOf("handler")).set(new ResponseHandler() {
                @Override
                public void onResponse(FullHttpResponse response) {
                    try {
                        long responseTime = (System.nanoTime() - startTime) / 1_000_000;

                        // 转换响应
                        HttpResponse burpResponse = convertToBurpResponse(response, requestInfo.isHttps);

                        // 释放资源
                        requestSemaphore.release();
                        successRequests.incrementAndGet();

                        // 返回连接到池
                        channelPool.release(channel, requestInfo.host, requestInfo.port);

                        // 完成Future
                        future.complete(burpResponse);

                        // 调用回调
                        if (callback != null) {
                            businessExecutor.execute(() -> callback.onResponse(burpResponse, responseTime));
                        }
                    } finally {
                        ReferenceCountUtil.release(response);
                    }
                }

                @Override
                public void onError(Throwable cause) {
                    requestSemaphore.release();
                    failedRequests.incrementAndGet();
                    channelPool.invalidate(channel);
                    future.completeExceptionally(cause);
                    if (callback != null) {
                        businessExecutor.execute(() -> callback.onError(cause));
                    }
                }
            });

            // 发送请求
            channel.writeAndFlush(nettyRequest).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    channel.attr(AttributeKey.<ResponseHandler>valueOf("handler")).get()
                            .onError(f.cause());
                }
            });

        } catch (Exception e) {
            requestSemaphore.release();
            failedRequests.incrementAndGet();
            channelPool.invalidate(channel);
            future.completeExceptionally(e);
            if (callback != null) {
                businessExecutor.execute(() -> callback.onError(e));
            }
        }
    }

    /**
     * 解析请求信息
     */
    private RequestInfo parseRequest(HttpRequest request) {
        String url = request.url();
        RequestInfo info = new RequestInfo();

        // 手动解析URL，不使用Java URL类
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
    private FullHttpRequest convertToNettyRequest(HttpRequest burpRequest, RequestInfo info) {
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
            if (!shouldSkipHeader(header.name())) {
                request.headers().add(header.name(), header.value());
            }
        }

        // 设置必要的headers
        request.headers().set(HttpHeaderNames.HOST, info.host);
        if (content.readableBytes() > 0) {
            request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        }
        request.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);

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
                lower.equals("host") ||
                lower.equals("connection");
    }

    /**
     * 关闭管理器
     */
    public void shutdown() {
        if (isShutdown) {
            return;
        }

        isShutdown = true;
        logging.logToOutput("[NettyManager] 开始关闭...");

        // 关闭连接池
        channelPool.shutdown();

        // 关闭EventLoopGroup
        eventLoopGroup.shutdownGracefully(1, 5, TimeUnit.SECONDS);

        // 关闭业务线程池
        businessExecutor.shutdown();
        try {
            if (!businessExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                businessExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            businessExecutor.shutdownNow();
        }

        logging.logToOutput(String.format("[NettyManager] 关闭完成. 总请求: %d, 成功: %d, 失败: %d",
                totalRequests.get(), successRequests.get(), failedRequests.get()));
    }

    /**
     * 连接池实现
     */
    private class ChannelPool {
        private final Map<String, Queue<Channel>> poolMap = new ConcurrentHashMap<>();
        private final int maxPerHost;
        private final Map<String, AtomicInteger> connectionCounts = new ConcurrentHashMap<>();

        public ChannelPool(int maxPerHost) {
            this.maxPerHost = maxPerHost;
        }

        public CompletableFuture<Channel> acquire(String host, int port, boolean isHttps) {
            String key = host + ":" + port;
            Queue<Channel> queue = poolMap.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

            // 尝试从池中获取
            Channel channel = queue.poll();
            if (channel != null && channel.isActive()) {
                return CompletableFuture.completedFuture(channel);
            }

            // 创建新连接
            return createConnection(host, port, isHttps);
        }

        public void release(Channel channel, String host, int port) {
            if (!channel.isActive()) {
                return;
            }

            String key = host + ":" + port;
            Queue<Channel> queue = poolMap.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

            if (queue.size() < maxPerHost) {
                queue.offer(channel);
            } else {
                channel.close();
            }
        }

        public void invalidate(Channel channel) {
            if (channel != null) {
                channel.close();
            }
        }

        private CompletableFuture<Channel> createConnection(String host, int port, boolean isHttps) {
            CompletableFuture<Channel> future = new CompletableFuture<>();

            Bootstrap b = bootstrap.clone();
            b.handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ChannelPipeline p = ch.pipeline();

                    // SOCKS5代理
                    p.addLast(new Socks5ProxyHandler(
                            new InetSocketAddress(PROXY_HOST, PROXY_PORT)));

                    // SSL处理
                    if (isHttps) {
                        p.addLast(sslContext.newHandler(ch.alloc(), host, port));
                    }

                    // 超时处理
                    p.addLast(new ReadTimeoutHandler(READ_TIMEOUT_SEC));
                    p.addLast(new WriteTimeoutHandler(WRITE_TIMEOUT_SEC));

                    // HTTP编解码
                    p.addLast(new HttpClientCodec());
                    p.addLast(new HttpObjectAggregator(10 * 1024 * 1024));

                    // 响应处理
                    p.addLast(new SimpleChannelInboundHandler<FullHttpResponse>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
                            ResponseHandler handler = ctx.channel()
                                    .attr(AttributeKey.<ResponseHandler>valueOf("handler")).get();
                            if (handler != null) {
                                // 保留消息引用计数
                                msg.retain();
                                handler.onResponse(msg);
                            }
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                            ResponseHandler handler = ctx.channel()
                                    .attr(AttributeKey.<ResponseHandler>valueOf("handler")).get();
                            if (handler != null) {
                                handler.onError(cause);
                            }
                            ctx.close();
                        }
                    });
                }
            });

            // 连接
            b.connect(host, port).addListener((ChannelFutureListener) f -> {
                if (f.isSuccess()) {
                    future.complete(f.channel());
                } else {
                    future.completeExceptionally(f.cause());
                }
            });

            return future;
        }

        public void shutdown() {
            poolMap.values().forEach(queue -> {
                Channel ch;
                while ((ch = queue.poll()) != null) {
                    ch.close();
                }
            });
            poolMap.clear();
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
     * 响应处理器接口
     */
    private interface ResponseHandler {
        void onResponse(FullHttpResponse response);
        void onError(Throwable cause);
    }

    /**
     * 响应回调接口
     */
    public interface ResponseCallback {
        void onResponse(HttpResponse response, long responseTimeMs);
        void onError(Throwable error);
    }
}