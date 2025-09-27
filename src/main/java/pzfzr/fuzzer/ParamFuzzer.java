package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.core.RateLimiter;
import pzfzr.core.CookieChanger;
import pzfzr.core.NettyManager;
import pzfzr.core.NettyHelper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;

/**
 * ParamFuzzer - 使用NettyManager的版本
 * 支持高并发参数模糊测试
 */
public class ParamFuzzer {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final Logging logging;
    private final CookieChanger cookieChanger;
    private volatile boolean isShuttingDown = false;
    private final PayloadManager payloadManager;

    // 使用NettyManager替代OkHttpManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    // 可动态修改的参数数量限制
    private volatile int maxParameterCount = 30;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ParamFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.rateLimiter = rateLimiter;
        this.logging = api.logging();
        this.nextModifiedId = nextModifiedId;
        this.cookieChanger = CookieChanger.getInstance();
        this.payloadManager = PayloadManager.getInstance();

        // 获取NettyManager实例
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[ParamFuzzer] Initialization completed using NettyManager client");
    }

    /**
     * 设置最大参数数量限制
     */
    public void setMaxParameterCount(int maxParameterCount) {
        this.maxParameterCount = maxParameterCount;
    }

    /**
     * 获取当前的最大参数数量限制
     */
    public int getMaxParameterCount() {
        return this.maxParameterCount;
    }

    /**
     * 主方法，供其他类调用
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 计算总参数数量
            int totalParamCount = getTotalParameterCount(originalRequest);

            // 如果参数数量超过限制，只发送一个原请求
            if (totalParamCount > maxParameterCount) {
                sendParameterTooManyRequest(originalRequest, messageId, host);
                return;
            }

            // 首先测试URL参数
            fuzzUrlParameters(originalRequest, messageId, host);

            // 然后测试POST body参数
            fuzzPostBodyParameters(originalRequest, messageId, host);

            // 最后测试JSON参数
            fuzzJsonParameters(originalRequest, messageId, host);

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 计算请求中的总参数数量
     */
    private int getTotalParameterCount(HttpRequest request) {
        int count = 0;

        // URL参数
        count += request.parameters(HttpParameterType.URL).size();

        // POST body参数（仅当是表单数据时）
        if (isFormDataRequest(request)) {
            count += request.parameters(HttpParameterType.BODY).size();
        }

        // JSON参数
        count += getJsonParameterCount(request);

        return count;
    }

    /**
     * 获取JSON参数数量
     */
    private int getJsonParameterCount(HttpRequest request) {
        String bodyString = request.bodyToString();
        if (bodyString == null || bodyString.trim().isEmpty()) {
            return 0;
        }

        if (!isJsonFormat(bodyString)) {
            return 0;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(bodyString);
            List<JsonPath> jsonPaths = extractJsonPaths(rootNode, "");
            return jsonPaths.size();
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * 发送参数数量过多的请求 - 使用NettyManager
     */
    private void sendParameterTooManyRequest(HttpRequest originalRequest, int messageId, String host) {
        try {
            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                originalRequest = originalRequest.withUpdatedHeaders(authHeaders);
            }

            rateLimiter.acquire(originalRequest.url() + originalRequest.method());

            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(originalRequest, tempID);

            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "PARAM",
                    "", // expression置空
                    "PARAMTOOMANY", // payloadAlias设置为PARAMTOOMANY
                    "", // parameterName置空
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(originalRequest, tempID, modifiedPair);

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 检查是否为表单数据请求
     */
    private boolean isFormDataRequest(HttpRequest request) {
        String contentType = request.headerValue("Content-Type");
        if (contentType == null) {
            return false;
        }

        String type = contentType.toLowerCase();
        // 只测试URL编码的表单数据，不测试文件上传
        return type.contains("application/x-www-form-urlencoded");
    }

    /**
     * 对URL参数进行模糊测试
     */
    private void fuzzUrlParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        List<ParsedHttpParameter> urlParams = originalRequest.parameters(HttpParameterType.URL);

        for (ParsedHttpParameter param : urlParams) {
            if (isShuttingDown) return;

            String paramName = param.name();
            String paramValue = param.value();

            // 使用PayloadManager获取启用的param payloads
            for (PayloadInfo payloadInfo : payloadManager.getEnabledParamPayloads()) {
                if (isShuttingDown) return;

                // URL参数跳过random_8000，参数污染，URL编码，以及"\"null\""
                if ("{random_8000}".equals(payloadInfo.alias)||"{param}&norandom=xx".equals(payloadInfo.alias)||"{url_encoded}".equals(payloadInfo.alias)||"\"null\"".equals(payloadInfo.alias)) {
                    continue;
                }

                String processedPayload = processPayload(payloadInfo.payload, paramValue);
                String expression = paramName + "=" + processedPayload;

                try {
                    HttpParameter newParam = HttpParameter.urlParameter(paramName, processedPayload);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(newParam);

                    sendTestRequest(modifiedRequest, messageId, host, expression, "URL_PARAM",
                            payloadInfo.alias, paramName);

                } catch (Exception e) {
                    // 静默错误处理
                }
            }
        }
    }

    /**
     * 对POST body参数进行模糊测试（表单数据）
     */
    private void fuzzPostBodyParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        // 只有当请求是表单数据时才进行测试
        if (!isFormDataRequest(originalRequest)) {
            return;
        }

        List<ParsedHttpParameter> bodyParams = originalRequest.parameters(HttpParameterType.BODY);

        for (ParsedHttpParameter param : bodyParams) {
            if (isShuttingDown) return;

            String paramName = param.name();
            String paramValue = param.value();

            // 使用PayloadManager获取启用的param payloads
            for (PayloadInfo payloadInfo : payloadManager.getEnabledParamPayloads()) {
                if (isShuttingDown) return;

                // PostBody参数跳过参数污染，URL编码，以及"\"null\""
                if ("{param}&norandom=xx".equals(payloadInfo.alias)||"{url_encoded}".equals(payloadInfo.alias)||"\"null\"".equals(payloadInfo.alias)) {
                    continue;
                }
                String processedPayload = processPayload(payloadInfo.payload, paramValue);
                String expression = paramName + "=" + processedPayload;

                try {
                    HttpParameter newParam = HttpParameter.bodyParameter(paramName, processedPayload);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(newParam);

                    sendTestRequest(modifiedRequest, messageId, host, expression, "BODY_PARAM",
                            payloadInfo.alias, paramName);

                } catch (Exception e) {
                    // 静默错误处理
                }
            }
        }
    }

    /**
     * 对JSON参数进行模糊测试
     */
    private void fuzzJsonParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        String bodyString = originalRequest.bodyToString();
        if (bodyString == null || bodyString.trim().isEmpty()) {
            return;
        }

        // 检查body是否为JSON格式
        if (!isJsonFormat(bodyString)) {
            return;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(bodyString);
            List<JsonPath> jsonPaths = extractJsonPaths(rootNode, "");

            for (JsonPath jsonPath : jsonPaths) {
                if (isShuttingDown) return;

                // 使用PayloadManager获取启用的param payloads
                for (PayloadInfo payloadInfo : payloadManager.getEnabledParamPayloads()) {
                    if (isShuttingDown) return;

                    // 从JsonNode获取实际文本值
                    String originalValue = getJsonNodeValue(jsonPath.value);
                    String processedPayload = processPayload(payloadInfo.payload, originalValue);

                    try {
                        JsonNode modifiedJson = modifyJsonNode(rootNode, jsonPath.path, processedPayload, payloadInfo.alias);
                        String modifiedJsonString = objectMapper.writeValueAsString(modifiedJson);

                        // 从修改后的JSON中提取实际表达式
                        String expression = extractExpressionFromJson(modifiedJson, jsonPath.path, jsonPath.lastKey);

                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedJsonString);

                        sendTestRequest(modifiedRequest, messageId, host, expression, "JSON_PARAM",
                                payloadInfo.alias, jsonPath.lastKey);

                    } catch (Exception e) {
                        // 静默错误处理
                    }
                }
            }

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 发送测试请求 - 使用NettyManager
     */
    private void sendTestRequest(HttpRequest modifiedRequest, int messageId, String host,
                                 String expression, String testType, String payloadAlias, String parameterName) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
            }

            // 获取令牌（阻塞直到获得令牌）
            rateLimiter.acquire(modifiedRequest.url().split("\\?")[0] + modifiedRequest.method());

            // 生成请求ID
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);

            // 创建ModifiedRequestResponse条目
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "PARAM",
                    expression,
                    payloadAlias,      // payload别名
                    parameterName,      // 当前测试参数的名称
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(modifiedRequest, tempID, modifiedPair);

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 异步发送测试请求 - 使用NettyManager
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
                        logging.logToError("[ParamFuzzer] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[ParamFuzzer] Request failed for ID " + tempID + ": " + error.getMessage());
                    // 可以在这里更新表格状态为错误状态
                }
            });

        } catch (Exception e) {
            logging.logToError("[ParamFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 设置关闭状态
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ParamFuzzer] Starting shutdown...");

            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作，因为NettyManager内部管理了所有连接

            logging.logToOutput("[ParamFuzzer] Shutdown completed");
        }
    }

    // ===== 以下是辅助方法，与原版保持一致 =====

    /**
     * 从修改后的JSON中提取表达式以确保准确性
     */
    private String extractExpressionFromJson(JsonNode modifiedJson, String path, String lastKey) {
        try {
            String[] pathParts = path.split("\\.");
            JsonNode currentNode = modifiedJson;

            // 导航到父节点
            for (int i = 0; i < pathParts.length - 1; i++) {
                String part = pathParts[i];
                if (part.contains("[")) {
                    String arrayField = part.substring(0, part.indexOf("["));
                    int arrayIndex = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));
                    currentNode = currentNode.get(arrayField).get(arrayIndex);
                } else {
                    currentNode = currentNode.get(part);
                }
            }

            // 获取最后一部分并提取键值对
            String lastPart = pathParts[pathParts.length - 1];
            JsonNode valueNode;

            if (lastPart.contains("[")) {
                String arrayField = lastPart.substring(0, lastPart.indexOf("["));
                int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
                valueNode = currentNode.get(arrayField).get(arrayIndex);
            } else {
                valueNode = currentNode.get(lastPart);
            }

            // 将值转换为正确的JSON表示
            String jsonValue = objectMapper.writeValueAsString(valueNode);

            return "\"" + lastKey + "\":" + jsonValue;

        } catch (Exception e) {
            // 如果提取失败，回退到简单格式
            return "\"" + lastKey + "\":\"[error]\"";
        }
    }

    /**
     * 从JsonNode获取实际值，不带JSON格式化
     */
    private String getJsonNodeValue(JsonNode node) {
        if (node.isTextual()) {
            return node.asText();
        } else if (node.isNumber()) {
            return node.asText();
        } else if (node.isBoolean()) {
            return node.asText();
        } else if (node.isNull()) {
            return "null";
        } else {
            // 回退到字符串表示
            return node.asText();
        }
    }

    /**
     * 检查字符串是否为JSON格式
     */
    private boolean isJsonFormat(String text) {
        try {
            objectMapper.readTree(text);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 提取JSON路径用于模糊测试
     */
    private List<JsonPath> extractJsonPaths(JsonNode node, String currentPath) {
        List<JsonPath> paths = new ArrayList<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String newPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                if (fieldValue.isObject()) {
                    // 不对对象值进行模糊测试，但递归进入其中
                    paths.addAll(extractJsonPaths(fieldValue, newPath));
                } else if (fieldValue.isArray()) {
                    // 根据需求只测试数组中的第一个项目
                    if (fieldValue.size() > 0) {
                        JsonNode firstItem = fieldValue.get(0);
                        String arrayPath = newPath + "[0]";
                        if (!firstItem.isObject()) {
                            paths.add(new JsonPath(arrayPath, firstItem, fieldName));
                        } else {
                            paths.addAll(extractJsonPaths(firstItem, arrayPath));
                        }
                    }
                } else {
                    // 对字符串、数字、布尔值、null值进行模糊测试
                    paths.add(new JsonPath(newPath, fieldValue, fieldName));
                }
            }
        }

        return paths;
    }

    /**
     * 在指定路径修改JSON节点
     * 针对null payload的特殊处理
     */
    private JsonNode modifyJsonNode(JsonNode rootNode, String path, String newValue, String payloadAlias) throws Exception {
        ObjectNode rootCopy = rootNode.deepCopy();

        String[] pathParts = path.split("\\.");
        JsonNode currentNode = rootCopy;

        for (int i = 0; i < pathParts.length - 1; i++) {
            String part = pathParts[i];
            if (part.contains("[")) {
                String arrayField = part.substring(0, part.indexOf("["));
                int arrayIndex = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));
                currentNode = currentNode.get(arrayField).get(arrayIndex);
            } else {
                currentNode = currentNode.get(part);
            }
        }

        String lastPart = pathParts[pathParts.length - 1];

        // 根据payloadAlias来区分两种null的处理方式：
        // 1. alias为"null" -> JSON null值（不带引号）
        // 2. alias为"\"null\"" -> 字符串"null"（带引号）
        JsonNode valueToSet;
        if ("null".equals(payloadAlias)) {
            // new PayloadInfo("null", "null") 的情况，设置为JSON null
            valueToSet = NullNode.getInstance();
        } else if ("\"null\"".equals(payloadAlias)) {
            // new PayloadInfo("null", "\"null\"") 的情况，设置为字符串"null"
            valueToSet = new TextNode("null");
        } else {
            // 其他情况设置为字符串值
            valueToSet = new TextNode(newValue);
        }

        if (lastPart.contains("[")) {
            String arrayField = lastPart.substring(0, lastPart.indexOf("["));
            int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
            ((ArrayNode) currentNode.get(arrayField)).set(arrayIndex, valueToSet);
        } else {
            ((ObjectNode) currentNode).set(lastPart, valueToSet);
        }

        return rootCopy;
    }

    /**
     * 使用统一的PayloadConstants处理payload
     */
    private String processPayload(String payload, String paramValue) {
        // 使用统一的PayloadConstants.PayloadProcessor进行通用处理
        return PayloadConstants.PayloadProcessor.processCommonReplacements(payload, paramValue);
    }

    /**
     * 用于跟踪JSON路径的辅助类
     */
    private static class JsonPath {
        final String path;
        final JsonNode value;
        final String lastKey;

        JsonPath(String path, JsonNode value, String lastKey) {
            this.path = path;
            this.value = value;
            this.lastKey = lastKey;
        }
    }
}