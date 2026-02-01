package pzfzr.fuzzer;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.core.CookieChanger;
import pzfzr.core.NettyManager;
import pzfzr.core.NettyHelper;
import pzfzr.core.RateLimiter;
import pzfzr.core.RequestDeduplicator;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

/**
 * RouteFuzzer - 使用新NettyManager的版本
 * 路径模糊测试器，支持高并发请求
 */
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
    // 使用新的NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    // 定义ROUTE1类型的payload alias数组
    private static final Set<String> ROUTE1_ALIASES = new HashSet<>(Arrays.asList(
            "null",
            ".%2f{path}",
            "{param}&chaxx=cha",
            "{param}%26chaxx=cha",
            "{path}@host",
            "{path1}{path2}",
            "{path}..",
            "ng crlf",
            "ng crlf2",
            "ng crlf3",
            "{path}CRLF",
            ".",
            "#",
            "\\",
            "?"
            ,"{path}/;{fuzz}.css"
    ));
    // 定义ROUTE12类型的payload alias数组
    private static final Set<String> ROUTE12_ALIASES = new HashSet<>(Arrays.asList(
            "chaxx",
            "{path}/chaxx"
            ,"{path}/{fuzz}.css"
            ,"{path}.css"
    ));

    // 定义需要特殊处理的 Spring 类 Payload Alias 集合
    private static final Set<String> SPRING_ALIASES = new HashSet<>(Arrays.asList(
            "swagger", "swagger2", "api_docs", "v2docs", "v3docs",
            "actuator", "env", "health", "mappings", "gateway", "metrics", "jolokia",
            ";/swagger;.js", ";/swagger2;.js", ";/api_docs;.js",
            ";/v2/api-docs;.js", ";/v3/api-docs;.js", ";/actuator;.js",
            ";/env;.js", ";/health;.js", ";/mappings;.js", ";/gateway;.js",
            ";/metrics;.js", ";/jolokia;.js",
            ";/..;/swagger", ";/..;/swagger2", ";/..;/api_docs",
            ";/..;/v2/api-docs", ";/..;/v3/api-docs", ";/..;/actuator",
            ";/..;/env", ";/..;/health", ";/..;/mappings", ";/..;/gateway",
            ";/..;/metrics", ";/..;/jolokia",
            ";/..;/X2-swagger", ";/..;/X2-swagger2", ";/..;/..;/api_docs",
            ";/..;/..;/v2/api-docs", ";/..;/..;/v3/api-docs", ";/..;/..;/actuator",
            ";/..;/..;/env", ";/..;/..;/health", ";/..;/..;/mappings",
            ";/..;/..;/gateway", ";/..;/..;/metrics", ";/..;/..;/jolokia",
            ";/..;/X3-swagger", ";/..;/X3-swagger2", ";/..;/..;/..;/api_docs",
            ";/..;/..;/..;/v2/api-docs", ";/..;/..;/..;/v3/api-docs", ";/..;/..;/..;/actuator",
            ";/..;/..;/..;/env", ";/..;/..;/..;/health", ";/..;/..;/..;/mappings",
            ";/..;/..;/..;/gateway", ";/..;/..;/..;/metrics", ";/..;/..;/..;/jolokia"
    ));

    // 定义通用框架信息泄露探测的 Payload Alias 集合
    private static final Set<String> GENERAL_INFO_LEAK_ALIASES = new HashSet<>(Arrays.asList(
            ".env", ".env.local", ".env.prod", "appsettings.json",
            ".git/", ".git/config", ".DS_Store", ".svn/entries", ".svn/",
            "wc.db", "manager//..;/", "settings.py", "admin_dev.php",
            "index_dev.php", "app_dev.php", "_fragment", "_profiler",
            "{sub../}.env", "{sub../}.env.local", "{sub../}.env.prod", "{sub../}appsettings.json",
            "{sub../}.git/", "{sub../}.git/config", "{sub../}.DS_Store", "{sub../}.svn/entries",
            "{sub../}.svn/", "{sub../}wc.db", "{sub../}manager//..;/", "{sub../}settings.py",
            "{sub../}admin_dev.php", "{sub../}index_dev.php", "{sub../}app_dev.php",
            "{sub../}_fragment", "{sub../}_profiler"
    ));


    /**
     * 内部类用于保存路径生成结果和表达式
     */
    private static class PathGenerationResult {
        final String modifiedPath;
        final String expression;

        PathGenerationResult(String modifiedPath, String expression) {
            this.modifiedPath = modifiedPath;
            this.expression = expression;
        }
    }

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

        // 使用新的NettyManager
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[RouteFuzzer] Initialization completed using new NettyManager client");
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
            // 注意：如果需要测试根路径的边界情况（如 {sub../}），这里的判断可能需要根据实际情况调整
            // 当前逻辑如果path为null或空或/则直接返回，可能会跳过根路径测试
            if (path == null || path.isEmpty() || path.equals("/")) {
                // 如果需要支持根路径Payload (如 / -> /../_fragment)，需注释掉下行或做特殊处理
                // return;
                // 为了安全起见暂保持原逻辑，如需开启根路径测试请注释 return
                // return;
                // *修正*: 为了响应 {sub../} 在根路径的需求，这里不再直接 return，而是让 pathSegments 解析去处理
                if (path == null) return;
            }

            boolean hasTrailingSlash = path.endsWith("/");
            String normalizedPath = hasTrailingSlash && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
            List<String> pathSegments = parsePathSegments(normalizedPath);

            if (pathSegments.isEmpty()) {
                // 针对根路径 "/" 的特殊处理，允许其进入测试循环以匹配 {sub../} 等边界Payload
                if (path != null && path.equals("/")) {
                    List<String> rootSegments = new ArrayList<>(); // 空列表
                    testPathLevelWithDeduplication(originalRequest, messageId, host, rootSegments, true, rootSegments, 1);
                    return;
                }
                return;
            }
            for (int level = pathSegments.size(); level >= 1; level--) {
                if (isShuttingDown) {
                    return;
                }
                List<String> currentSegments = pathSegments.subList(0, level);
                boolean shouldTestTrailingSlash = hasTrailingSlash && level == pathSegments.size();
                // 传递完整的pathSegments和level用于计算批次号
                testPathLevelWithDeduplication(originalRequest, messageId, host, currentSegments, shouldTestTrailingSlash, pathSegments, level);
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
            if (path == null) {
                return;
            }

            boolean hasTrailingSlash = path.endsWith("/");
            String normalizedPath = hasTrailingSlash && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
            List<String> pathSegments = parsePathSegments(normalizedPath);

            if (pathSegments.isEmpty()) {
                if (path.equals("/")) {
                    List<String> rootSegments = new ArrayList<>();
                    testPathLevelWithoutDeduplication(originalRequest, messageId, host, rootSegments, true, rootSegments, 1);
                    return;
                }
                return;
            }
            for (int level = pathSegments.size(); level >= 1; level--) {
                if (isShuttingDown) {
                    return;
                }
                List<String> currentSegments = pathSegments.subList(0, level);
                boolean shouldTestTrailingSlash = hasTrailingSlash && level == pathSegments.size();
                // 传递完整的pathSegments和level用于计算批次号
                testPathLevelWithoutDeduplication(originalRequest, messageId, host, currentSegments, shouldTestTrailingSlash, pathSegments, level);
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
                                                List<String> pathSegments, boolean testTrailingSlash,
                                                List<String> originalPathSegments, int level) {
        // 计算批次号：原始路径段数 - 当前level + 1
        int batchNumber = originalPathSegments.size() - level + 1;

        // 兼容根路径空列表情况
        int startIndex = pathSegments.isEmpty() ? 0 : pathSegments.size() - 1;
        int endIndex = 0;

        for (int segmentIndex = startIndex; segmentIndex >= endIndex; segmentIndex--) {
            if (isShuttingDown) {
                return;
            }
            for (PayloadInfo payloadInfo : payloadManager.getEnabledRoutePayloads()) {
                if (isShuttingDown) {
                    return;
                }
                try {
                    String originalTestParam = pathSegments.isEmpty() ? "" : pathSegments.get(segmentIndex);
                    String currentTestParam = originalTestParam + "-" + batchNumber; // 添加批次后缀
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                            payloadInfo.alias, currentTestParam, false, true);

                    if (!pathSegments.isEmpty() && testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
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
                                                   List<String> pathSegments, boolean testTrailingSlash,
                                                   List<String> originalPathSegments, int level) {
        // 计算批次号：原始路径段数 - 当前level + 1
        int batchNumber = originalPathSegments.size() - level + 1;

        int startIndex = pathSegments.isEmpty() ? 0 : pathSegments.size() - 1;
        int endIndex = 0;

        for (int segmentIndex = startIndex; segmentIndex >= endIndex; segmentIndex--) {
            if (isShuttingDown) {
                return;
            }
            for (PayloadInfo payloadInfo : payloadManager.getEnabledRoutePayloads()) {
                if (isShuttingDown) {
                    return;
                }
                try {
                    String originalTestParam = pathSegments.isEmpty() ? "" : pathSegments.get(segmentIndex);
                    String currentTestParam = originalTestParam + "-" + batchNumber; // 添加批次后缀
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                            payloadInfo.alias, currentTestParam, false, false);

                    if (!pathSegments.isEmpty() && testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
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
        PathGenerationResult result = generateModifiedPath(pathSegments, targetIndex, payload, addTrailingSlash);
        if (result != null && result.modifiedPath != null) {
            if (useDeduplication) {
                String fullUrl = host + result.modifiedPath;
                if (!requestDeduplicator.shouldSkipRequest(originalRequest.method(), fullUrl, "RouteFuzzer")) {
                    sendTestRequestAsync(originalRequest, messageId, host, result.modifiedPath, payloadAlias, currentTestParam, result.expression);
                }
            } else {
                sendTestRequestAsync(originalRequest, messageId, host, result.modifiedPath, payloadAlias, currentTestParam, result.expression);
            }
        }
    }

    /**
     * 异步发送测试请求 - 使用新NettyManager
     */
    private void sendTestRequestAsync(HttpRequest originalRequest, int messageId, String host, String modifiedPath,
                                      String payloadAlias, String currentTestParam, String expression) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 构建完整的路径 (Query String handling)
            String fullModifiedPath = buildFullPath(originalRequest, modifiedPath, payloadAlias);

            // 默认情况下，请求路径就是修改后的路径
            // 创建修改后的请求
            HttpRequest modifiedRequest = originalRequest.withPath(fullModifiedPath);

            // -------------------------------------------------------------------------
            // 新增逻辑：Header 注入与 Rewrite 模式处理
            // 注意：使用 withHeader() 替代 withUpdatedHeader() 以确保 Header 不存在时会被添加
            // -------------------------------------------------------------------------
            boolean isRewrite = payloadAlias.endsWith("-rewrite");
            boolean isSpring = SPRING_ALIASES.contains(payloadAlias);
            boolean isInfoLeak = GENERAL_INFO_LEAK_ALIASES.contains(payloadAlias);

            // 1. 如果是 Rewrite 模式，Request Line 必须保持原始路径 (不含 Payload)
            // Header Value ({replace_route}) 必须是变体后的完整路径
            if (isRewrite) {
                // 回退请求路径到原始请求路径
                modifiedRequest = modifiedRequest.withPath(originalRequest.path());

                // 添加 URL 改写类 Header
//                [cite_start]// 关键修正：使用 withHeader [cite: 313] 确保添加Header
                modifiedRequest = modifiedRequest
                        .withHeader("X-Forwarded-Uri", fullModifiedPath)
                        .withHeader("X-Forwarded-URL", fullModifiedPath)
                        .withHeader("X-Forwarded-Path", fullModifiedPath)
                        .withHeader("X-Forwarded-Prefix", fullModifiedPath)
                        .withHeader("X-Forwarded-Context", fullModifiedPath)
                        .withHeader("X-Rewrite-URL", fullModifiedPath)
                        .withHeader("X-Rewrite-URI", fullModifiedPath)
                        .withHeader("X-Rewrite-Path", fullModifiedPath)
                        .withHeader("X-Rewritten-URL", fullModifiedPath)
                        .withHeader("X-Real-URI", fullModifiedPath)
                        .withHeader("X-Original-Url", fullModifiedPath)
                        .withHeader("Replaced-Path", fullModifiedPath);
            }

            // 2. 如果是 Spring类 或 InfoLeak类 或 Rewrite类
            // 都要注入 XFF 类 Header
            if (isSpring || isInfoLeak || isRewrite) {
//                [cite_start]// 关键修正：使用 withHeader [cite: 313] 确保添加Header
                modifiedRequest = modifiedRequest
                        .withHeader("X-Forwarded-Host", "127.0.0.1")
                        .withHeader("X-Forwarded-Server", "127.0.0.1")
                        .withHeader("X-Forwarded-For", "127.0.0.1")
                        .withHeader("X-Forwarded-By", "127.0.0.1")
                        .withHeader("X-Real-IP", "127.0.0.1")
                        .withHeader("X-Remote-IP", "127.0.0.1")
                        .withHeader("X-Remote-Addr", "127.0.0.1")
                        .withHeader("X-Host", "127.0.0.1")
                        .withHeader("X-HTTP-Host-Override", "127.0.0.1")
                        .withHeader("X-Original-Host", "127.0.0.1")
                        .withHeader("X-Originating-IP", "127.0.0.1")
                        .withHeader("X-Client-IP", "127.0.0.1")
                        .withHeader("X-Cluster-Client-IP", "127.0.0.1")
                        .withHeader("Client-IP", "127.0.0.1");
            }
            // -------------------------------------------------------------------------

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
            // 创建ModifiedRequestResponse条目，使用传入的expression
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    testType,
                    expression,  // 使用生成路径时记录的expression
                    payloadAlias,
                    currentTestParam,
                    requestResponseSaver,
                    logging
            );
            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);
            // 使用新NettyManager发送请求
            nettyManager.sendRequest(modifiedRequest, new NettyManager.ResponseCallback() {
                @Override
                public void onResponse(HttpResponse response, long responseTimeMs) {
                    try {
                        // 处理响应（解压等）
                        HttpResponse processedResponse = nettyHelper.processResponse(response);

                        // 调用RequestResponseSaver处理响应
                        requestResponseSaver.handleNettyResponse(processedResponse, tempID, responseTimeMs, modifiedPair);

                    } catch (Exception e) {
                        logging.logToError("[RouteFuzzer] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[RouteFuzzer] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });
        } catch (Exception e) {
            logging.logToError("[RouteFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 生成修改后的路径，并返回路径和被替换的表达式
     */
    private PathGenerationResult generateModifiedPath(List<String> pathSegments, int targetIndex, String payload, boolean addTrailingSlash) {
        List<String> modifiedSegments = new ArrayList<>(pathSegments);
        String modifiedPayload = payload;
        String expression = ""; // 记录实际替换后的内容

        // 使用统一的PayloadConstants.PayloadProcessor处理{fuzz}替换
        if (modifiedPayload.contains("{fuzz}")) {
            modifiedPayload = modifiedPayload.replace("{fuzz}", PayloadConstants.PayloadProcessor.generateRandomHash());
        }

        // -------------------------------------------------------------------------
        // 新增逻辑：处理 {sub../} 前缀
        // -------------------------------------------------------------------------
        if (modifiedPayload.startsWith("{sub../}")) {
            String actualPayload = modifiedPayload.substring(8); // 去掉 {sub../} 前缀

            // 边界情况：根路径 (segments 为空)
            if (modifiedSegments.isEmpty()) {
                // 原请求: / -> /../_fragment
                return new PathGenerationResult("/../" + actualPayload, actualPayload);
            }

            // 如果有前一级路径 (targetIndex > 0)
            if (targetIndex > 0) {
                // 修改前一级: segment -> segment..
                String prevSegment = modifiedSegments.get(targetIndex - 1);
                modifiedSegments.set(targetIndex - 1, prevSegment + "..");

                // 移除当前级 (targetIndex)
                modifiedSegments.remove(targetIndex);

                String basePath = buildPath(modifiedSegments, false);
                String finalPath = basePath + "/" + actualPayload;

                expression = actualPayload;
                return new PathGenerationResult(finalPath, expression);
            } else {
                // 边界情况：当前是第一级路径 /api，没有前一级
                // 修改成 /../_fragment
                modifiedSegments.remove(targetIndex);
                String finalPath = "/../" + actualPayload;
                expression = actualPayload;
                return new PathGenerationResult(finalPath, expression);
            }
        }
        // -------------------------------------------------------------------------

        // 处理特殊情况 {path_del}
        if (modifiedPayload.equals("{path_del}")) {
            String path = handlePathDelPayload(modifiedSegments, targetIndex, addTrailingSlash);
            expression = ""; // path_del 情况下expression为空
            return new PathGenerationResult(path, expression);
        }

        // 处理特殊情况 {path1}{path2}
        if (modifiedPayload.contains("{path1}{path2}")) {
            if (targetIndex < modifiedSegments.size() - 1) {
                String path1 = modifiedSegments.get(targetIndex);
                String path2 = modifiedSegments.get(targetIndex + 1);
                expression = path1 + path2;
                modifiedSegments.set(targetIndex, expression);
                modifiedSegments.remove(targetIndex + 1);
            } else if (targetIndex > 0) {
                String path1 = modifiedSegments.get(targetIndex - 1);
                String path2 = modifiedSegments.get(targetIndex);
                expression = path1 + path2;
                modifiedSegments.set(targetIndex - 1, expression);
                modifiedSegments.remove(targetIndex);
            } else {
                return null;
            }
            return new PathGenerationResult(buildPath(modifiedSegments, addTrailingSlash), expression);
        }

        // 处理URL编码的特殊情况
        String targetSegment = modifiedSegments.isEmpty() ? "" : modifiedSegments.get(targetIndex);
        if (modifiedPayload.equals("{path_url_encoded}")) {
            expression = PayloadConstants.PayloadProcessor.urlEncodeFullly(targetSegment);
            modifiedSegments.set(targetIndex, expression);
        } else if (modifiedPayload.equals("{path_double_url_encoded}")) {
            expression = PayloadConstants.PayloadProcessor.urlEncodeFullly(
                    PayloadConstants.PayloadProcessor.urlEncodeFullly(targetSegment));
            modifiedSegments.set(targetIndex, expression);
        } else {
            // 处理普通的替换
            expression = PayloadConstants.PayloadProcessor.processCommonReplacements(modifiedPayload, targetSegment);
            if (modifiedSegments.isEmpty()) {
                return new PathGenerationResult("/" + expression, expression);
            }
            modifiedSegments.set(targetIndex, expression);
        }

        return new PathGenerationResult(buildPath(modifiedSegments, addTrailingSlash), expression);
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
        if (payloadAlias == null) return "ROUTE2";

        // 新增的Payload类型判断
        if (SPRING_ALIASES.contains(payloadAlias) ||
                GENERAL_INFO_LEAK_ALIASES.contains(payloadAlias) ||
                payloadAlias.endsWith("-rewrite") ||
                payloadAlias.contains("{sub../}")) {
            return "OOB-GENERALFUZZ";
        }

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
     * 设置关闭标志
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
        if (shuttingDown) {
            logging.logToOutput("[RouteFuzzer] Starting shutdown...");
            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作

            logging.logToOutput("[RouteFuzzer] Shutdown completed");
        }
    }
}