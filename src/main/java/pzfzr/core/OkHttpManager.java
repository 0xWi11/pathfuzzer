package pzfzr.core;

import okhttp3.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CompressionUtils;
import burp.api.montoya.utilities.CompressionType;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * OkHttp客户端管理器 - 单例模式
 * 用于管理OkHttp客户端配置和请求转换
 */
public class OkHttpManager {
    private static volatile OkHttpManager instance;
    private final OkHttpClient http1Client;
    private final OkHttpClient http2Client;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CompressionUtils compressionUtils;

    // 简化的时间测量key
    private static final String TIMING_HEADER = "X-Response-Time-Ms";

    // 连接池配置等其他配置保持不变...
    private static final int MAX_IDLE_CONNECTIONS = 100;
    private static final long KEEP_ALIVE_DURATION = 5; // minutes

    // 超时配置
    private static final int CONNECT_TIMEOUT = 10; // seconds
    private static final int READ_TIMEOUT = 30; // seconds
    private static final int WRITE_TIMEOUT = 30; // seconds

    // 重试配置
    private static final int MAX_RETRIES = 2;

    // 代理配置
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 20808;

    private OkHttpManager(Logging logging, RateLimiter rateLimiter, CompressionUtils compressionUtils) {
        this.logging = logging;
        this.rateLimiter = rateLimiter;
        this.compressionUtils = compressionUtils;
        this.http1Client = createOkHttpClient(false); // HTTP/1.1 only
        this.http2Client = createOkHttpClient(true);  // HTTP/2 and HTTP/1.1

        logging.logToOutput("[OkHttpManager] 初始化完成，连接池大小: " + MAX_IDLE_CONNECTIONS +
                "，代理配置: " + PROXY_HOST + ":" + PROXY_PORT + "，支持Burp解压缩工具");
    }

    /**
     * 获取单例实例 - 带参数版本（用于首次初始化）
     */
    public static OkHttpManager getInstance(Logging logging, RateLimiter rateLimiter, CompressionUtils compressionUtils) {
        if (instance == null) {
            synchronized (OkHttpManager.class) {
                if (instance == null) {
                    if (logging == null || rateLimiter == null || compressionUtils == null) {
                        throw new IllegalArgumentException("OkHttpManager首次初始化时，所有参数都不能为null");
                    }
                    instance = new OkHttpManager(logging, rateLimiter, compressionUtils);
                }
            }
        }
        return instance;
    }

    /**
     * 获取单例实例 - 无参数版本（用于后续调用）
     */
    public static OkHttpManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException("OkHttpManager尚未初始化，请先调用getInstance(logging, rateLimiter, compressionUtils)进行初始化");
        }
        return instance;
    }

    /**
     * 检查实例是否已初始化
     */
    public static boolean isInitialized() {
        return instance != null;
    }

    /**
     * 创建配置好的OkHttpClient实例
     */
    private OkHttpClient createOkHttpClient(boolean supportHttp2) {
        // 创建信任所有证书的TrustManager
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[]{};
                    }
                }
        };

        try {
            // 创建SSL上下文
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // 创建连接池
            ConnectionPool connectionPool = new ConnectionPool(
                    MAX_IDLE_CONNECTIONS,
                    KEEP_ALIVE_DURATION,
                    TimeUnit.MINUTES
            );

            // 创建Dispatcher用于并发控制
            Dispatcher dispatcher = new Dispatcher();
            dispatcher.setMaxRequests(100); // 最大并发请求数
            dispatcher.setMaxRequestsPerHost(20); // 每个主机的最大并发请求数

            // 配置代理 - 所有请求都走20808端口代理
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_HOST, PROXY_PORT));

            // 构建OkHttpClient - 禁用自动解压缩以便手动处理
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                    .proxy(proxy) // 设置代理
                    .connectionPool(connectionPool)
                    .dispatcher(dispatcher)
                    .connectTimeout(CONNECT_TIMEOUT, TimeUnit.SECONDS)
                    .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS)
                    .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
                    .retryOnConnectionFailure(true)
                    .followRedirects(false) // 不自动跟随重定向
                    .followSslRedirects(false)
                    .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .addNetworkInterceptor(new SimpleTimingInterceptor()) // 简化的时间测量拦截器
                    .addInterceptor(new RetryInterceptor(MAX_RETRIES))
                    .addInterceptor(new LoggingInterceptor(logging))
                    .addNetworkInterceptor(new DecompressionInterceptor());

            // 配置协议支持
            List<Protocol> protocols;
            if (supportHttp2) {
                protocols = Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1);
            } else {
                protocols = Arrays.asList(Protocol.HTTP_1_1);
            }
            builder.protocols(protocols);

            logging.logToOutput("[OkHttpManager] 代理配置完成: " + PROXY_HOST + ":" + PROXY_PORT +
                    ", HTTP2支持: " + supportHttp2);

            return builder.build();

        } catch (Exception e) {
            logging.logToError("[OkHttpManager] 创建OkHttpClient失败: " + e.getMessage());
            throw new RuntimeException("Failed to create OkHttpClient", e);
        }
    }

    /**
     * 简化的时间测量拦截器 - 只需几行代码就能获取精确时间
     */
    private static class SimpleTimingInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();

            // 记录网络请求开始时间（纳秒精度）
            long startTime = System.nanoTime();

            // 执行网络请求
            Response response = chain.proceed(request);

            // 计算网络响应时间（毫秒）
            long responseTimeMs = (System.nanoTime() - startTime) / 1_000_000;

            // 将时间信息添加到响应头中
            return response.newBuilder()
                    .addHeader(TIMING_HEADER, String.valueOf(responseTimeMs))
                    .build();
        }
    }

    /**
     * 从响应中提取精确的响应时间
     */
    public long extractResponseTime(Response response) {
        String timingHeader = response.header(TIMING_HEADER);
        if (timingHeader != null) {
            try {
                return Long.parseLong(timingHeader);
            } catch (NumberFormatException e) {
                logging.logToError("[OkHttpManager] 解析响应时间失败: " + timingHeader);
            }
        }
        return -1; // 表示无法获取精确时间
    }

    public Call newCall(Request request) {
        RequestMetadata metadata = request.tag(RequestMetadata.class);
        String httpVersion = metadata != null ? metadata.httpVersion : "HTTP/1.1";

        OkHttpClient clientToUse;
        if ("HTTP/2".equals(httpVersion)) {
            clientToUse = http2Client;
        } else {
            clientToUse = http1Client;
        }

        return clientToUse.newCall(request);
    }

    public Request convertToOkHttpRequest(HttpRequest burpRequest) {
        String url = burpRequest.url();
        String httpVersion = burpRequest.httpVersion();

        // 构建请求体
        RequestBody body = null;
        if (burpRequest.body() != null && burpRequest.body().length() > 0) {
            String contentType = burpRequest.headerValue("Content-Type");
            MediaType mediaType = contentType != null ? MediaType.parse(contentType) : MediaType.parse("application/octet-stream");
            body = RequestBody.create(burpRequest.body().getBytes(), mediaType);
        }

        // 构建请求
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .method(burpRequest.method(), body);

        // 添加headers
        for (HttpHeader header : burpRequest.headers()) {
            // 跳过一些由OkHttp自动处理的header
            String headerName = header.name();
            if (!shouldSkipHeader(headerName)) {
                requestBuilder.addHeader(headerName, header.value());
            }
        }

        // 添加Accept-Encoding header以支持压缩
        requestBuilder.addHeader("Accept-Encoding", "gzip, deflate, br");

        // 添加自定义tag用于跟踪，包含HTTP版本信息
        requestBuilder.tag(RequestMetadata.class, new RequestMetadata(System.currentTimeMillis(), httpVersion));

        return requestBuilder.build();
    }

    /**
     * 将OkHttp的Response转换为Burp的HttpResponse，并移除时间测量头
     */
    public HttpResponse convertToBurpResponse(Response okHttpResponse) throws IOException {
        // 构建响应行
        StringBuilder responseBuilder = new StringBuilder();
        responseBuilder.append("HTTP/").append(okHttpResponse.protocol() == Protocol.HTTP_2 ? "2" : "1.1");
        responseBuilder.append(" ").append(okHttpResponse.code());
        if (okHttpResponse.message() != null && !okHttpResponse.message().isEmpty()) {
            responseBuilder.append(" ").append(okHttpResponse.message());
        }
        responseBuilder.append("\r\n");

        // 获取原始headers
        Headers originalHeaders = okHttpResponse.headers();
        String contentEncoding = originalHeaders.get("Content-Encoding");

        // 处理响应体
        ResponseBody responseBody = okHttpResponse.body();
        byte[] decompressedBody = null;
        boolean wasDecompressed = false;

        if (responseBody != null) {
            byte[] originalBodyBytes = responseBody.bytes();

            // 检查是否需要解压缩
            if (contentEncoding != null && !contentEncoding.isEmpty() && originalBodyBytes.length > 0) {
                try {
                    decompressedBody = decompressResponseBody(originalBodyBytes, contentEncoding);
                    wasDecompressed = true;
//                    logging.logToOutput(String.format("[OkHttpManager] 使用Burp工具解压缩响应: %s, 原始大小: %d, 解压后大小: %d",
//                            contentEncoding, originalBodyBytes.length, decompressedBody.length));
                } catch (Exception e) {
                    logging.logToError("[OkHttpManager] Burp解压缩失败: " + e.getMessage());
                    // 解压缩失败时使用原始数据
                    decompressedBody = originalBodyBytes;
                    wasDecompressed = false;
                }
            } else {
                decompressedBody = originalBodyBytes;
            }
        }

        // 构建修改后的headers
        Headers.Builder modifiedHeadersBuilder = new Headers.Builder();
        for (int i = 0; i < originalHeaders.size(); i++) {
            String headerName = originalHeaders.name(i);
            String headerValue = originalHeaders.value(i);

            // 跳过我们添加的时间测量头，不要泄露到最终响应中
            if (headerName.equals(TIMING_HEADER)) {
                continue;
            }

            if (headerName.equalsIgnoreCase("Transfer-Encoding")) {
                continue; // 跳过Transfer-Encoding header
            }

            // 如果解压缩成功，移除Content-Encoding相关的headers
            if (wasDecompressed) {
                if (headerName.equalsIgnoreCase("Content-Encoding")) {
                    continue; // 跳过Content-Encoding header
                }
                if (headerName.equalsIgnoreCase("Content-Length")) {
                    // 更新Content-Length为解压后的大小
                    headerValue = String.valueOf(decompressedBody != null ? decompressedBody.length : 0);
                }
            }

            modifiedHeadersBuilder.add(headerName, headerValue);
        }

        // 要求2: 确保响应包含Content-Length头
        Headers currentHeaders = modifiedHeadersBuilder.build();
        if (currentHeaders.get("Content-Length") == null) {
            int contentLength = decompressedBody != null ? decompressedBody.length : 0;
            modifiedHeadersBuilder.add("Content-Length", String.valueOf(contentLength));
        }

        Headers modifiedHeaders = modifiedHeadersBuilder.build();



        // 添加修改后的headers到响应
        for (int i = 0; i < modifiedHeaders.size(); i++) {
            responseBuilder.append(modifiedHeaders.name(i)).append(": ").append(modifiedHeaders.value(i)).append("\r\n");
        }
        responseBuilder.append("\r\n");

        // 构建完整响应
        if (decompressedBody != null && decompressedBody.length > 0) {
            byte[] headerBytes = responseBuilder.toString().getBytes();
            byte[] fullResponse = new byte[headerBytes.length + decompressedBody.length];
            System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
            System.arraycopy(decompressedBody, 0, fullResponse, headerBytes.length, decompressedBody.length);

            return HttpResponse.httpResponse(ByteArray.byteArray(fullResponse));
        } else {
            return HttpResponse.httpResponse(responseBuilder.toString());
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

            // 根据Content-Encoding确定压缩类型
            if ("gzip".equalsIgnoreCase(contentEncoding)) {
                compressionType = CompressionType.GZIP;
            } else if ("deflate".equalsIgnoreCase(contentEncoding)) {
                compressionType = CompressionType.DEFLATE;
            } else if ("br".equalsIgnoreCase(contentEncoding)) {
                compressionType = CompressionType.BROTLI;
            } else {
                return compressedData;
            }

            // 使用Burp的CompressionUtils进行解压缩
            ByteArray compressedByteArray = ByteArray.byteArray(compressedData);
            ByteArray decompressedByteArray = compressionUtils.decompress(compressedByteArray, compressionType);

            return decompressedByteArray.getBytes();

        } catch (Exception e) {
            logging.logToError("[OkHttpManager] 使用Burp解压缩工具失败: " + e.getMessage());
            // 解压缩失败时返回原始数据
            return compressedData;
        }
    }

    /**
     * 判断是否应该跳过某个header
     */
    private boolean shouldSkipHeader(String headerName) {
        String lowerName = headerName.toLowerCase();
        return lowerName.equals("content-length") || lowerName.equals("transfer-encoding");
    }

    /**
     * 获取OkHttpClient实例（保持向后兼容）
     */
    public OkHttpClient getClient() {
        return http2Client; // 默认返回支持HTTP/2的客户端
    }

    /**
     * 关闭客户端
     */
    public void shutdown() {
        try {
            // 关闭HTTP/1.1客户端
            http1Client.dispatcher().executorService().shutdown();
            http1Client.connectionPool().evictAll();
            if (http1Client.cache() != null) {
                http1Client.cache().close();
            }

            // 关闭HTTP/2客户端
            http2Client.dispatcher().executorService().shutdown();
            http2Client.connectionPool().evictAll();
            if (http2Client.cache() != null) {
                http2Client.cache().close();
            }

            logging.logToOutput("[OkHttpManager] 客户端已关闭");
        } catch (Exception e) {
            logging.logToError("[OkHttpManager] 关闭客户端时出错: " + e.getMessage());
        }
    }

    /**
     * 解压缩拦截器 - 确保响应被正确解压缩
     */
    private class DecompressionInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            return chain.proceed(chain.request());
        }
    }

    /**
     * 重试拦截器
     */
    private static class RetryInterceptor implements Interceptor {
        private final int maxRetries;

        public RetryInterceptor(int maxRetries) {
            this.maxRetries = maxRetries;
        }

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            Response response = null;
            IOException lastException = null;

            for (int i = 0; i <= maxRetries; i++) {
                try {
                    if (response != null) {
                        response.close();
                    }
                    response = chain.proceed(request);

                    // 如果响应成功或不需要重试的状态码，直接返回
                    if (response.isSuccessful() || !shouldRetry(response.code())) {
                        return response;
                    }
                } catch (IOException e) {
                    lastException = e;
                    if (i == maxRetries) {
                        throw e;
                    }
                    // 等待一段时间后重试
                    try {
                        Thread.sleep((long) Math.pow(2, i) * 100);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Retry interrupted", ie);
                    }
                }
            }

            if (response != null) {
                return response;
            } else {
                throw lastException != null ? lastException : new IOException("Failed after " + maxRetries + " retries");
            }
        }

        private boolean shouldRetry(int code) {
            return code == 408 || code == 429 || code >= 500;
        }
    }

    /**
     * 日志拦截器
     */
    private static class LoggingInterceptor implements Interceptor {
        private final Logging logging;

        public LoggingInterceptor(Logging logging) {
            this.logging = logging;
        }

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            Response response = chain.proceed(request);
            return response;
        }
    }

    /**
     * 请求元数据
     */
    private static class RequestMetadata {
        final long timestamp;
        final String httpVersion;

        RequestMetadata(long timestamp, String httpVersion) {
            this.timestamp = timestamp;
            this.httpVersion = httpVersion;
        }
    }
}