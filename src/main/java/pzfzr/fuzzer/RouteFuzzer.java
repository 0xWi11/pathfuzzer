// Updated RouteFuzzer.java - Modified to use PayloadManager
package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.core.CookieChanger;
import pzfzr.core.RateLimiter;
import pzfzr.core.RequestDeduplicator;
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
    private final PayloadManager payloadManager; // Add PayloadManager

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
        this.payloadManager = PayloadManager.getInstance(); // Initialize PayloadManager
    }

    /**
     * 主要的测试方法，使用requestDeduplicator
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            String path = originalRequest.pathWithoutQuery();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return; // 跳过根路径或空路径
            }
            // 处理结尾斜杠的情况
            boolean hasTrailingSlash = path.endsWith("/");
            String normalizedPath = hasTrailingSlash ? path.substring(0, path.length() - 1) : path;
            // 分割路径段
            List<String> pathSegments = parsePathSegments(normalizedPath);
            if (pathSegments.isEmpty()) {
                return;
            }
            // 从完整路径开始，逐级减少测试
            for (int level = pathSegments.size(); level >= 1; level--) {
                if (isShuttingDown) {
                    return;
                }
                List<String> currentSegments = pathSegments.subList(0, level);
                boolean shouldTestTrailingSlash = hasTrailingSlash && level == pathSegments.size();
                testPathLevelWithDeduplication(originalRequest, messageId, host, currentSegments, shouldTestTrailingSlash);
            }
        } catch (Exception e) {
            // 错误处理
        }
    }

    /**
     * 不经过requestDeduplicator的测试方法
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
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
            // 错误处理
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
        // 从最后一个路径段开始，依次向前测试每个段
        for (int segmentIndex = pathSegments.size() - 1; segmentIndex >= 0; segmentIndex--) {
            if (isShuttingDown) {
                return;
            }
            // 对当前段测试每个启用的payload - 使用PayloadManager获取启用的payloads
            for (PayloadInfo payloadInfo : payloadManager.getEnabledRoutePayloads()) {
                if (isShuttingDown) {
                    return;
                }
                try {
                    String currentTestParam = pathSegments.get(segmentIndex);

                    // 测试不带尾部斜杠的版本
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                            payloadInfo.alias, currentTestParam, false, true);
                    // 如果原始路径有尾部斜杠，且当前是最后一个段，也测试带斜杠的版本
                    if (testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
                        testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payloadInfo.payload,
                                payloadInfo.alias, currentTestParam, true, true);
                    }
                } catch (Exception e) {
                    // 错误处理
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
            // 使用PayloadManager获取启用的payloads
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
                    // 错误处理
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
                    sendTestRequest(originalRequest, messageId, host, modifiedPath, payloadAlias, currentTestParam);
                }
            } else {
                sendTestRequest(originalRequest, messageId, host, modifiedPath, payloadAlias, currentTestParam);
            }
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

        // 处理特殊情况 {path1}{path2}
        if (modifiedPayload.contains("{path1}{path2}")) {
            return handlePath1Path2Payload(modifiedSegments, targetIndex, addTrailingSlash);
        }

        // 处理URL编码的特殊情况 - 使用统一的PayloadConstants.PayloadProcessor
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
            // 处理普通的替换，使用统一的处理方法
            String targetSegment = modifiedSegments.get(targetIndex);
            modifiedPayload = PayloadConstants.PayloadProcessor.processCommonReplacements(modifiedPayload, targetSegment);
            modifiedSegments.set(targetIndex, modifiedPayload);
        }

        // 构建最终路径
        return buildPath(modifiedSegments, addTrailingSlash);
    }

    /**
     * 处理 {path1}{path2} 特殊情况
     */
    private String handlePath1Path2Payload(List<String> pathSegments, int targetIndex, boolean addTrailingSlash) {
        List<String> modifiedSegments = new ArrayList<>(pathSegments);
        // 根据需求，{path1}{path2} 有几种变体：
        // 1. 当前段 + 下一段 (如果存在下一段)
        // 2. 上一段 + 当前段 (如果存在上一段)
        // 3. 其他组合
        if (targetIndex < modifiedSegments.size() - 1) {
            // 变体1：当前段与下一段组合
            String path1 = modifiedSegments.get(targetIndex);
            String path2 = modifiedSegments.get(targetIndex + 1);
            modifiedSegments.set(targetIndex, path1 + path2);
            modifiedSegments.remove(targetIndex + 1);
        } else if (targetIndex > 0) {
            // 变体2：上一段与当前段组合
            String path1 = modifiedSegments.get(targetIndex - 1);
            String path2 = modifiedSegments.get(targetIndex);
            modifiedSegments.set(targetIndex - 1, path1 + path2);
            modifiedSegments.remove(targetIndex);
        } else {
            // 只有一个段，无法应用 {path1}{path2}
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
     * 发送测试请求
     */
    private void sendTestRequest(HttpRequest originalRequest, int messageId, String host, String modifiedPath,
                                 String payloadAlias, String currentTestParam) {
        try {
            // 创建修改后的请求
            HttpRequest modifiedRequest = originalRequest.withPath(modifiedPath);
            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
            }
            rateLimiter.acquire(modifiedRequest.url() + modifiedRequest.method());
            // 发送修改后的请求
            HttpRequestResponse modifiedResponse = api.http().sendRequest(modifiedRequest);
            int tempID = nextModifiedId.getAndIncrement();
            // 保存修改后的请求和响应，传入新的参数
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "ROUTE",
                    "",
                    payloadAlias,       // payload别名
                    currentTestParam,    // 当前测试参数的名称（被替换的path片段）
                    requestResponseSaver,
                    logging
            );
            tableModel.addModifiedEntry(modifiedPair);
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);
            requestResponseSaver.handleDelayedModifiedResponse(modifiedResponse, tempID);
            // 清理引用
            modifiedRequest = null;
            modifiedResponse = null;
        } catch (Exception e) {
            // 错误处理
        }
    }

    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
    }
}