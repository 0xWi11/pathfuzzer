package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.IOException;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;

import okhttp3.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.core.ByteArray;
import pzfzr.core.CookieChanger;
import pzfzr.core.RateLimiter;
import pzfzr.core.RequestDeduplicator;
import pzfzr.core.OkHttpManager;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

public class RouteFuzzer {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private volatile boolean isShuttingDown = false;
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final RequestDeduplicator requestDeduplicator;
    private final PayloadManager payloadManager;
    private final OkHttpManager okHttpManager;

    // 用于跟踪正在进行的请求
    private final Set<Call> activeRequests = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);

    // 定义ROUTE1类型的payload alias数组
    private static final Set<String> ROUTE1_ALIASES = new HashSet<>(Arrays.asList(
            "{param}&chaxx=cha",
            "{param}%26chaxx=cha",
            "{path}@host",
            "{path1}{path2}",
            "{path}..",
            "ng crlf",
            "ng crlf2",
            "ng crlf3",
            "{path}CRLF"
    ));

    // 定义ROUTE12类型的payload alias数组
    private static final Set<String> ROUTE12_ALIASES = new HashSet<>(Arrays.asList(
            "chaxx",
            "{path}/chaxx"
    ));

    public RouteFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.requestDeduplicator = RequestDeduplicator.getInstance(this.logging);
        this.nextModifiedId = nextModifiedId;
        this.payloadManager = PayloadManager.getInstance();

        // **修改: 使用无参数的getInstance方法获取已初始化的OkHttpManager实例**
        this.okHttpManager = OkHttpManager.getInstance();

        logging.logToOutput("[RouteFuzzer] 初始化完成，使用OkHttp客户端和Burp解压缩工具");
    }

    /**
     * 主要的测试方法，使用requestDeduplicator
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            String path = originalRequest.pathWithoutQuery();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return;
            }
            boolean hasTrailingSlash = path.endsWith("/");
            String normalizedPath = hasTrailingSlash ? path.substring(0, path.length() - 1) : path;
            List<String> pathSegments = parsePathSegments(normalizedPath);
            if (pathSegments.isEmpty()) {
                return;
            }
            for (int level = pathSegments.size(); level >= 1; level--) {
                if (isShuttingDown) {
                    return;
                }
                List<String> currentSegments = pathSegments.subList(0, level);
                boolean shouldTestTrailingSlash = hasTrailingSlash && level == pathSegments.size();
                testPathLevelWithDeduplication(originalRequest, messageId, host, currentSegments, shouldTestTrailingSlash);
            }
        } catch (Exception e) {
            logging.logToError("[RouteFuzzer] processRequest error: " + e.getMessage());
        }
    }

    /**
     * 不经过requestDeduplicator的测试方法
     */
    public void processRequestWithoutDeduplication(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            String path = originalRequest.pathWithoutQuery();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return;
            }
            boolean hasTrailingSlash = path.endsWith("/");
            String normalizedPath = hasTrailingSlash ? path.substring(0, path.length() - 1) : path;
            List<String> pathSegments = parsePathSegments(normalizedPath);
            if (pathSegments.isEmpty()) {
                return;
            }
            for (int level = pathSegments.size(); level >= 1; level--) {
                if (isShuttingDown) {
                    return;
                }
                List<String> currentSegments = pathSegments.subList(0, level);
                boolean shouldTestTrailingSlash = hasTrailingSlash && level == pathSegments.size();
                testPathLevelWithoutDeduplication(originalRequest, messageId, host, currentSegments, shouldTestTrailingSlash);
            }
        } catch (Exception e) {
            logging.logToError("[RouteFuzzer] processRequestWithoutDeduplication error: " + e.getMessage());
        }
    }

    /**
     * 解析路径段
     */
    private List<String> parsePathSegments(String path) {
        String[] segments = path.split("/");
        List<String> pathSegments = new ArrayList<>();
        for (String segment : segments) {
            if (!segment.isEmpty()) {
                pathSegments.add(segment);
            }
        }
        return pathSegments;
    }

    /**
     * 测试指定路径级别（使用去重）
     */
    private void testPathLevelWithDeduplication(HttpRequest originalRequest, int messageId, String host,
                                                List<String> pathSegments, boolean testTrailingSlash) {
        for (int segmentIndex = pathSegments.size() - 1; segmentIndex >= 0; segmentIndex--) {
            if (isShuttingDown) {
                return;
            }
            for (PayloadInfo payloadInfo : payloadManager.getEnabledRoutePayloads()) {
                if (isShuttingDown) {
                    return;
                }
                try {
                    String currentTestParam = pathSegments.get(segmentIndex);
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                            payloadInfo.alias, currentTestParam, false, true);
                    if (testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
                        testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                                payloadInfo.alias, currentTestParam, true, true);
                    }
                } catch (Exception e) {
                    logging.logToError("[RouteFuzzer] testPathLevelWithDeduplication error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 测试指定路径级别（不使用去重）
     */
    private void testPathLevelWithoutDeduplication(HttpRequest originalRequest, int messageId, String host,
                                                   List<String> pathSegments, boolean testTrailingSlash) {
        for (int segmentIndex = pathSegments.size() - 1; segmentIndex >= 0; segmentIndex--) {
            if (isShuttingDown) {
                return;
            }
            for (PayloadInfo payloadInfo : payloadManager.getEnabledRoutePayloads()) {
                if (isShuttingDown) {
                    return;
                }
                try {
                    String currentTestParam = pathSegments.get(segmentIndex);
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                            payloadInfo.alias, currentTestParam, false, false);
                    if (testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
                        testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                                payloadInfo.alias, currentTestParam, true, false);
                    }
                } catch (Exception e) {
                    logging.logToError("[RouteFuzzer] testPathLevelWithoutDeduplication error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 测试单个payload
     */
    private void testSinglePayload(HttpRequest originalRequest, int messageId, String host,
                                   List<String> pathSegments, int targetIndex, String payload,
                                   String payloadAlias, String currentTestParam,
                                   boolean addTrailingSlash, boolean useDeduplication) {
        String modifiedPath = generateModifiedPath(pathSegments, targetIndex, payload, addTrailingSlash);
        if (modifiedPath != null) {
            if (useDeduplication) {
                String fullUrl = host + modifiedPath;
                if (!requestDeduplicator.shouldSkipRequest(originalRequest.method(), fullUrl, "RouteFuzzer")) {
                    sendTestRequestAsync(originalRequest, messageId, host, modifiedPath, payloadAlias, currentTestParam);
                }
            } else {
                sendTestRequestAsync(originalRequest, messageId, host, modifiedPath, payloadAlias, currentTestParam);
            }
        }
    }

    /**
     * 异步发送测试请求 - 使用OkHttp
     */
    private void sendTestRequestAsync(HttpRequest originalRequest, int messageId, String host, String modifiedPath,
                                      String payloadAlias, String currentTestParam) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 构建完整的路径
            String fullModifiedPath = buildFullPath(originalRequest, modifiedPath, payloadAlias);

            // 创建修改后的请求
            HttpRequest modifiedRequest = originalRequest.withPath(fullModifiedPath);

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

            // 根据payloadAlias判断testType
            String testType = determineTestType(payloadAlias);

            // 创建ModifiedRequestResponse条目
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    testType,
                    "",
                    payloadAlias,
                    currentTestParam,
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 转换为OkHttp请求并异步发送
            Request okHttpRequest = okHttpManager.convertToOkHttpRequest(modifiedRequest);
            Call call = okHttpManager.newCall(okHttpRequest);

            // 跟踪活动请求
            activeRequests.add(call);

            // 异步执行请求
            call.enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    activeRequests.remove(call);
                    logging.logToError("[RouteFuzzer] Request failed for ID " + tempID + ": " + e.getMessage());

                    // 更新表格模型中的错误状态
                    ModifiedRequestResponse entry = tableModel.getModifiedEntryById(tempID);
                    if (entry != null) {
//                        entry.setError("Request failed: " + e.getMessage());
                    }
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    activeRequests.remove(call);

                    try {
                        // **修改点：使用OkHttpManager的extractResponseTime方法获取精确的响应时间**
                        long responseTime = okHttpManager.extractResponseTime(response);

                        // 转换响应为Burp格式
                        HttpResponse burpResponse = okHttpManager.convertToBurpResponse(response);

                        // 处理响应，使用从OkHttpManager获取的精确响应时间
                        requestResponseSaver.handleOkHttpResponse(burpResponse, tempID, responseTime, modifiedPair);

                    } catch (Exception e) {
                        logging.logToError("[RouteFuzzer] Error processing response for ID " + tempID + ": " + e.getMessage());
                    } finally {
                        response.close();
                    }
                }
            });

        } catch (Exception e) {
            logging.logToError("[RouteFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 生成修改后的路径
     */
    private String generateModifiedPath(List<String> pathSegments, int targetIndex, String payload, boolean addTrailingSlash) {
        List<String> modifiedSegments = new ArrayList<>(pathSegments);
        String modifiedPayload = payload;

        // 使用统一的PayloadConstants.PayloadProcessor处理{fuzz}替换
        if (modifiedPayload.contains("{fuzz}")) {
            modifiedPayload = modifiedPayload.replace("{fuzz}", PayloadConstants.PayloadProcessor.generateRandomHash());
        }

        // 处理特殊情况 {path_del}
        if (modifiedPayload.equals("{path_del}")) {
            return handlePathDelPayload(modifiedSegments, targetIndex, addTrailingSlash);
        }

        // 处理特殊情况 {path1}{path2}
        if (modifiedPayload.contains("{path1}{path2}")) {
            return handlePath1Path2Payload(modifiedSegments, targetIndex, addTrailingSlash);
        }

        // 处理URL编码的特殊情况
        if (modifiedPayload.equals("{path_url_encoded}")) {
            String targetSegment = modifiedSegments.get(targetIndex);
            String urlEncoded = PayloadConstants.PayloadProcessor.urlEncodeFullly(targetSegment);
            modifiedSegments.set(targetIndex, urlEncoded);
        } else if (modifiedPayload.equals("{path_double_url_encoded}")) {
            String targetSegment = modifiedSegments.get(targetIndex);
            String doubleUrlEncoded = PayloadConstants.PayloadProcessor.urlEncodeFullly(
                    PayloadConstants.PayloadProcessor.urlEncodeFullly(targetSegment));
            modifiedSegments.set(targetIndex, doubleUrlEncoded);
        } else {
            // 处理普通的替换
            String targetSegment = modifiedSegments.get(targetIndex);
            modifiedPayload = PayloadConstants.PayloadProcessor.processCommonReplacements(modifiedPayload, targetSegment);
            modifiedSegments.set(targetIndex, modifiedPayload);
        }

        return buildPath(modifiedSegments, addTrailingSlash);
    }

    /**
     * 处理 {path_del} 特殊情况
     */
    private String handlePathDelPayload(List<String> pathSegments, int targetIndex, boolean addTrailingSlash) {
        List<String> modifiedSegments = new ArrayList<>(pathSegments);

        if (modifiedSegments.size() == 1) {
            return addTrailingSlash ? "/" : "/";
        }

        if (targetIndex >= 0 && targetIndex < modifiedSegments.size()) {
            modifiedSegments.remove(targetIndex);
        } else {
            return null;
        }

        return buildPath(modifiedSegments, addTrailingSlash);
    }

    /**
     * 处理 {path1}{path2} 特殊情况
     */
    private String handlePath1Path2Payload(List<String> pathSegments, int targetIndex, boolean addTrailingSlash) {
        List<String> modifiedSegments = new ArrayList<>(pathSegments);

        if (targetIndex < modifiedSegments.size() - 1) {
            String path1 = modifiedSegments.get(targetIndex);
            String path2 = modifiedSegments.get(targetIndex + 1);
            modifiedSegments.set(targetIndex, path1 + path2);
            modifiedSegments.remove(targetIndex + 1);
        } else if (targetIndex > 0) {
            String path1 = modifiedSegments.get(targetIndex - 1);
            String path2 = modifiedSegments.get(targetIndex);
            modifiedSegments.set(targetIndex - 1, path1 + path2);
            modifiedSegments.remove(targetIndex);
        } else {
            return null;
        }

        return buildPath(modifiedSegments, addTrailingSlash);
    }

    /**
     * 构建路径字符串
     */
    private String buildPath(List<String> segments, boolean addTrailingSlash) {
        StringBuilder pathBuilder = new StringBuilder();
        for (String segment : segments) {
            pathBuilder.append("/").append(segment);
        }
        if (addTrailingSlash) {
            pathBuilder.append("/");
        }
        return pathBuilder.toString();
    }

    /**
     * 根据payload alias判断TestType
     */
    private String determineTestType(String payloadAlias) {
        if (ROUTE12_ALIASES.contains(payloadAlias)) {
            return "ROUTE3";
        } else if (ROUTE1_ALIASES.contains(payloadAlias)) {
            return "ROUTE1";
        } else {
            return "ROUTE2";
        }
    }

    /**
     * 构建包含原始查询参数的完整路径
     */
    private String buildFullPath(HttpRequest originalRequest, String modifiedPath, String payloadAlias) {
        try {
            if (shouldSkipQueryParameters(payloadAlias)) {
                return modifiedPath;
            }

            String originalQuery = originalRequest.query();

            if (originalQuery != null && !originalQuery.isEmpty()) {
                return modifiedPath + "?" + originalQuery;
            } else {
                return modifiedPath;
            }
        } catch (Exception e) {
            logging.logToError("[RouteFuzzer] Error building full path with query parameters: " + e.getMessage());
            return modifiedPath;
        }
    }

    /**
     * 判断是否应该跳过添加查询参数
     */
    private boolean shouldSkipQueryParameters(String payloadAlias) {
        return "ng crlf".equals(payloadAlias) ||
                "ng crlf2".equals(payloadAlias) ||
                "ng crlf3".equals(payloadAlias) ||
                "{path}CRLF".equals(payloadAlias);
    }

    /**
     * 设置关闭标志并等待所有请求完成
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[RouteFuzzer] 开始关闭，取消所有活动请求...");

            // 取消所有活动的请求
            for (Call call : activeRequests) {
                call.cancel();
            }

            // 等待所有请求完成（最多等待10秒）
            long startTime = System.currentTimeMillis();
            while (!activeRequests.isEmpty() && (System.currentTimeMillis() - startTime) < 10000) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            if (!activeRequests.isEmpty()) {
                logging.logToOutput("[RouteFuzzer] 强制关闭 " + activeRequests.size() + " 个未完成的请求");
                activeRequests.clear();
            }

            // **修改: 不再在这里关闭OkHttpManager，因为它现在由PathFuzzer统一管理**
            // okHttpManager.shutdown(); // 移除这行

            logging.logToOutput("[RouteFuzzer] 关闭完成");
        }
    }
}