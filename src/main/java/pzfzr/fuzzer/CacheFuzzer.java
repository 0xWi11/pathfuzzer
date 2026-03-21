package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.core.CookieChanger;
import pzfzr.core.NettyManager;
import pzfzr.core.NettyHelper;
import pzfzr.core.RateLimiter;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

/**
 * CacheFuzzer - 缓存模糊测试器
 * 主要用于测试缓存中毒等缓存相关的安全问题
 * 通过添加特定的headers来进行测试
 */
public class CacheFuzzer {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private volatile boolean isShuttingDown = false;
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;

    // 使用NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    // 随机字符串生成器
    private static final Random RANDOM = new Random();
    private static final String HASH_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final int HASH_LENGTH = 8;

    /**
     * 内部类：Header批次定义
     */
    private static class HeaderBatch {
        final String alias;
        final Map<String, String> headers;

        HeaderBatch(String alias, Map<String, String> headers) {
            this.alias = alias;
            this.headers = headers;
        }
    }

    // 定义所有的header批次
    private static final List<HeaderBatch> HEADER_BATCHES = new ArrayList<>();

    static {
        // 第一批：Cache XFF
        Map<String, String> batch1 = new LinkedHashMap<>();
        batch1.put("X-Forwarded-Host", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-Server", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-For", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-By", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Real-IP", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Remote-IP", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Remote-Addr", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Host", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-HTTP-Host-Override", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Original-Host", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Originating-IP", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Client-IP", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Cluster-Client-IP", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("Client-IP", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-Uri", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-URL", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-Path", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-Prefix", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Forwarded-Context", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Rewrite-URL", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Rewrite-URI", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Rewrite-Path", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Rewritten-URL", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Real-URI", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("X-Original-Url", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch1.put("Replaced-Path", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        HEADER_BATCHES.add(new HeaderBatch("Cache XFF", batch1));

        // 第二批：Cache Baocuo1
        Map<String, String> batch2 = new LinkedHashMap<>();
        batch2.put("X-Forwarded-SSL", "wat");
        batch2.put("X-Forwarded-Port", "9993");
        batch2.put("x-forwarded-proto", "wat");
        batch2.put("x-amz-website-redirect-location", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch2.put("x-forwarded-scheme", "http");
        batch2.put("x-http-method-override", "HEAD");
        batch2.put("fastly-ssl", "wat");
        batch2.put("fastly-host", "wat");
        batch2.put("fastly-ff", "wat");
        batch2.put("fastly-client-ip", "wat");
        HEADER_BATCHES.add(new HeaderBatch("Cache Baocuo1", batch2));

        // 第三批：Cache Baocuo2
        Map<String, String> batch3 = new LinkedHashMap<>();
        batch3.put("Transfer-Encoding", "hwmen");
        batch3.put("Range", "bytes=cow");
        batch3.put("Upgrade", "wat");
        batch3.put("Max-Forwards", "wat");
        batch3.put("content-type", "wat");
        HEADER_BATCHES.add(new HeaderBatch("Cache Baocuo2", batch3));

        // 第四批：Cache Baocuo3
        Map<String, String> batch4 = new LinkedHashMap<>();
        batch4.put("Host", "zcydyyyya.{hash}.tejq8.zcyy.fun");
        batch4.put("api-version", "wat");
        batch4.put("Server-Name", "wat");
        batch4.put("Path-Info", "wat");
        batch4.put("Rsc", "wat");
        batch4.put("Next-Router-State-Tree", "wat");
        batch4.put("Content-Encoding", "wat");
        batch4.put("X-Vercel-Id", "wat");
        batch4.put("X-Part", "wat");
        batch4.put("User-Agent", "扫描器特征");
        HEADER_BATCHES.add(new HeaderBatch("Cache Baocuo3", batch4));

        // 第五批：Cache Baocuo4
//        Map<String, String> batch5 = new LinkedHashMap<>();
//        batch5.put("\\", "wat");
//        HEADER_BATCHES.add(new HeaderBatch("Cache Baocuo4", batch5));
    }

    public CacheFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();

        this.nextModifiedId = nextModifiedId;

        // 使用NettyManager
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[CacheFuzzer] Initialization completed using NettyManager client");
    }

    /**
     * 生成指定长度的随机字母数字字符串，用于替换 {hash} 占位符
     */
    private static String generateRandomHash() {
        StringBuilder sb = new StringBuilder(HASH_LENGTH);
        for (int i = 0; i < HASH_LENGTH; i++) {
            sb.append(HASH_CHARS.charAt(RANDOM.nextInt(HASH_CHARS.length())));
        }
        return sb.toString();
    }

    /**
     * 主要的测试方法
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            fuzzRequestWithCacheHeaders(originalRequest, messageId, host);
        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 对请求进行缓存相关的模糊测试
     * 为每个批次添加headers并发送请求
     */
    private void fuzzRequestWithCacheHeaders(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        // 遍历每个header批次
        for (HeaderBatch batch : HEADER_BATCHES) {
            if (isShuttingDown) {
                return;
            }

            try {
                // 为当前批次发送测试请求
                sendBatchTestRequest(originalRequest, messageId, host, batch);
            } catch (Exception e) {
                logging.logToError("[CacheFuzzer] Error testing batch '" + batch.alias + "': " + e.getMessage());
            }
        }
    }

    /**
     * 发送批次测试请求
     * 每个批次生成一个唯一的随机 hash，批次内所有 {hash} 占位符使用同一个值，
     * 便于通过 DNS 回调将请求与具体批次关联。
     */
    private void sendBatchTestRequest(HttpRequest originalRequest, int messageId, String host, HeaderBatch batch) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 首先添加dontpoisonallpeople参数到GET请求的URI
            HttpRequest modifiedRequest = addDontPoisonParameter(originalRequest);

            // 每个批次生成一个随机 hash，批次内所有 header 共用同一个值
            String batchHash = generateRandomHash();

            // 添加批次中的所有headers，并处理{hash}占位符
            for (Map.Entry<String, String> entry : batch.headers.entrySet()) {
                // 处理header值中的{hash}占位符，传入本批次的随机hash
                String processedValue = processPayload(entry.getValue(), "", batchHash);
                HttpHeader header = HttpHeader.httpHeader(entry.getKey(), processedValue);
                modifiedRequest = modifiedRequest.withAddedHeader(header);
            }

            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
            }

            // 获取令牌（阻塞直到获得令牌）
            rateLimiter.acquire(originalRequest.url() + modifiedRequest.method());

            // 生成请求ID
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);

            // 创建ModifiedRequestResponse条目
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "CacheFuzz",      // testType为CacheFuzz
                    "",               // expression置空
                    batch.alias,      // payloadAlias为批次别名
                    "",               // parameterName置空
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(modifiedRequest, tempID, modifiedPair);

        } catch (Exception e) {
            logging.logToError("[CacheFuzzer] sendBatchTestRequest error: " + e.getMessage());
        }
    }

    /**
     * 使用统一的PayloadConstants处理payload，并额外替换 {hash} 占位符。
     *
     * @param payload    原始 payload 字符串
     * @param paramValue 当前参数值（传给 PayloadConstants 使用）
     * @param hash       本批次随机生成的 hash，用于替换 {hash} 占位符
     */
    private String processPayload(String payload, String paramValue, String hash) {
        // 先用统一的 PayloadConstants 进行通用替换
        String processed = PayloadConstants.PayloadProcessor.processCommonReplacements(payload, paramValue);
        // 再替换 {hash} 占位符为本批次随机字符串
        return processed.replace("{hash}", hash);
    }

    /**
     * 兼容原有无 hash 参数的调用入口（内部不再使用，保留以防其他地方引用）
     */
    private String processPayload(String payload, String paramValue) {
        return processPayload(payload, paramValue, generateRandomHash());
    }

    /**
     * 为GET请求添加dontpoisonallpeople=1参数
     */
    private HttpRequest addDontPoisonParameter(HttpRequest request) {
        // 只对GET请求添加参数
        if (!"GET".equalsIgnoreCase(request.method())) {
            return request;
        }

        try {
            String currentUrl = request.url();
            String newUrl;

            // 检查URL是否已经包含查询参数
            if (currentUrl.contains("?")) {
                newUrl = currentUrl + "&dontpoisonallpeople=1";
            } else {
                newUrl = currentUrl + "?dontpoisonallpeople=1";
            }

            // 获取原始请求的所有部分
            String originalRequestString = request.toString();

            // 找到第一行（请求行）
            int firstLineEnd = originalRequestString.indexOf("\r\n");
            if (firstLineEnd == -1) {
                firstLineEnd = originalRequestString.indexOf("\n");
            }

            if (firstLineEnd != -1) {
                String requestLine = originalRequestString.substring(0, firstLineEnd);
                String restOfRequest = originalRequestString.substring(firstLineEnd);

                // 解析请求行：GET /path HTTP/1.1
                String[] parts = requestLine.split(" ", 3);
                if (parts.length >= 3) {
                    String method = parts[0];
                    String path = parts[1];
                    String httpVersion = parts[2];

                    // 修改path部分
                    String newPath;
                    if (path.contains("?")) {
                        newPath = path + "&dontpoisonallpeople=1";
                    } else {
                        newPath = path + "?dontpoisonallpeople=1";
                    }

                    // 重建请求
                    String newRequestString = method + " " + newPath + " " + httpVersion + restOfRequest;
                    return HttpRequest.httpRequest(request.httpService(), newRequestString);
                }
            }

            // 如果解析失败，返回原始请求
            return request;

        } catch (Exception e) {
            logging.logToError("[CacheFuzzer] Error adding dontpoisonallpeople parameter: " + e.getMessage());
            return request;
        }
    }

    /**
     * 实际发送请求的方法
     */
    private void sendTestRequestAsync(HttpRequest modifiedRequest, int tempID, ModifiedRequestResponse modifiedPair) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 使用NettyManager发送请求
            nettyManager.sendRequest(modifiedRequest, new NettyManager.ResponseCallback() {
                @Override
                public void onResponse(HttpResponse response, long responseTimeMs) {
                    try {
                        // 处理响应（解压等）
                        HttpResponse processedResponse = nettyHelper.processResponse(response);

                        // 调用RequestResponseSaver处理响应
                        requestResponseSaver.handleNettyResponse(processedResponse, tempID, responseTimeMs, modifiedPair);

                    } catch (Exception e) {
                        logging.logToError("[CacheFuzzer] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[CacheFuzzer] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });

        } catch (Exception e) {
            logging.logToError("[CacheFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 设置关闭标志
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[CacheFuzzer] Starting shutdown...");

            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作

            logging.logToOutput("[CacheFuzzer] Shutdown completed");
        }
    }
}