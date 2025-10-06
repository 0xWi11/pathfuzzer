package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.core.CookieChanger;
import pzfzr.core.NettyManager;
import pzfzr.core.NettyHelper;
import pzfzr.core.RateLimiter;
import pzfzr.core.ParamCollector;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * ParamAdder - 参数添加器
 * 从ParamCollector读取参数，分批次添加到GET/POST/JSON位置
 */
public class ParamAdder {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private volatile boolean isShuttingDown = false;
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final ParamCollector paramCollector;

    // 使用NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // 批次大小配置 - 改为可配置字段
    private int getBatchSize = 100;
    private int postBatchSize = 250;
    private int jsonBatchSize = 250;
    private static final int MAX_JSON_DEPTH = 4;

    public ParamAdder(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                      RateLimiter rateLimiter, AtomicInteger nextModifiedId, ParamCollector paramCollector) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.nextModifiedId = nextModifiedId;
        this.paramCollector = paramCollector;

        // 使用NettyManager
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[ParamAdder] Initialization completed using NettyManager client");
    }

    /**
     * 获取GET批次大小
     */
    public int getGetBatchSize() {
        return getBatchSize;
    }

    /**
     * 设置GET批次大小
     */
    public void setGetBatchSize(int batchSize) {
        if (batchSize > 0) {
            this.getBatchSize = batchSize;
            logging.logToOutput("[ParamAdder] GET batch size updated to: " + batchSize);
        }
    }

    /**
     * 获取POST批次大小
     */
    public int getPostBatchSize() {
        return postBatchSize;
    }

    /**
     * 设置POST批次大小
     */
    public void setPostBatchSize(int batchSize) {
        if (batchSize > 0) {
            this.postBatchSize = batchSize;
            logging.logToOutput("[ParamAdder] POST batch size updated to: " + batchSize);
        }
    }

    /**
     * 获取JSON批次大小
     */
    public int getJsonBatchSize() {
        return jsonBatchSize;
    }

    /**
     * 设置JSON批次大小
     */
    public void setJsonBatchSize(int batchSize) {
        if (batchSize > 0) {
            this.jsonBatchSize = batchSize;
            logging.logToOutput("[ParamAdder] JSON batch size updated to: " + batchSize);
        }
    }

    /**
     * URL编码：仅编码会破坏URL/HTTP格式的特殊字符
     * 保留安全字符：字母、数字、-_.~
     * 编码特殊字符：空格、&、=、?、#、%、+、/等
     */
    private String urlEncodeValue(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        try {
            // 使用URLEncoder进行完整编码
            String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());

            // URLEncoder会把空格编码成+，但在URL中我们更希望用%20
            // 同时保留一些URL中的安全字符
            encoded = encoded.replace("+", "%20");

            return encoded;
        } catch (Exception e) {
            logging.logToError("[ParamAdder] URL encoding error: " + e.getMessage());
            return value;
        }
    }

    /**
     * 主要的处理方法
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 从ParamCollector获取所有参数
            Map<String, ParamCollector.ParamEntry> allParams = paramCollector.getAllParams();

            // 如果没有参数，直接返回
            if (allParams == null || allParams.isEmpty()) {
                logging.logToOutput("[ParamAdder] No parameters found in ParamCollector, skipping");
                return;
            }

            // 转换为List方便分批处理
            List<ParamCollector.ParamEntry> paramList = new ArrayList<>(allParams.values());

//            logging.logToOutput(String.format("[ParamAdder] Starting to add %d parameters", paramList.size()));

            String method = originalRequest.method().toUpperCase();
            String contentType = originalRequest.headerValue("Content-Type");

            // 添加GET参数（所有请求类型都尝试）
            addGetParametersBatch(originalRequest, paramList, messageId, host);

            // 根据请求类型添加POST参数
            if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                    // JSON格式：添加JSON参数
                    addJsonParametersBatch(originalRequest, paramList, messageId, host);
                } else if (contentType != null && contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
                    // 表单格式：添加POST参数
                    addPostParametersBatch(originalRequest, paramList, messageId, host);
                }
            }

        } catch (Exception e) {
            logging.logToError("[ParamAdder] processRequest error: " + e.getMessage());
        }
    }

    /**
     * 分批添加GET参数
     */
    private void addGetParametersBatch(HttpRequest originalRequest, List<ParamCollector.ParamEntry> paramList,
                                       int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            int totalParams = paramList.size();
            int batchCount = (int) Math.ceil((double) totalParams / getBatchSize);

            for (int batchIndex = 0; batchIndex < batchCount; batchIndex++) {
                if (isShuttingDown) {
                    break;
                }

                int startIndex = batchIndex * getBatchSize;
                int endIndex = Math.min(startIndex + getBatchSize, totalParams);
                List<ParamCollector.ParamEntry> batchParams = paramList.subList(startIndex, endIndex);

                // 创建请求副本并添加参数
                HttpRequest modifiedRequest = originalRequest;
                List<HttpParameter> parametersToAdd = new ArrayList<>();

                for (ParamCollector.ParamEntry entry : batchParams) {
                    // URL编码参数值
                    String encodedValue = urlEncodeValue(entry.getValue());
                    HttpParameter param = HttpParameter.urlParameter(entry.getKey(), encodedValue);
                    parametersToAdd.add(param);
                }

                modifiedRequest = modifiedRequest.withAddedParameters(parametersToAdd);

                // 发送请求
                String payloadAlias = String.format("GET-batch-%d", batchIndex + 1);
                sendTestRequest(modifiedRequest, messageId, host, "", payloadAlias);

//                logging.logToOutput(String.format("[ParamAdder] Sent GET batch %d/%d with %d parameters",
//                        batchIndex + 1, batchCount, batchParams.size()));
            }

        } catch (Exception e) {
            logging.logToError("[ParamAdder] addGetParametersBatch error: " + e.getMessage());
        }
    }

    /**
     * 分批添加POST表单参数
     */
    private void addPostParametersBatch(HttpRequest originalRequest, List<ParamCollector.ParamEntry> paramList,
                                        int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            int totalParams = paramList.size();
            int batchCount = (int) Math.ceil((double) totalParams / postBatchSize);

            for (int batchIndex = 0; batchIndex < batchCount; batchIndex++) {
                if (isShuttingDown) {
                    break;
                }

                int startIndex = batchIndex * postBatchSize;
                int endIndex = Math.min(startIndex + postBatchSize, totalParams);
                List<ParamCollector.ParamEntry> batchParams = paramList.subList(startIndex, endIndex);

                // 创建请求副本并添加参数
                HttpRequest modifiedRequest = originalRequest;
                List<HttpParameter> parametersToAdd = new ArrayList<>();

                for (ParamCollector.ParamEntry entry : batchParams) {
                    // URL编码参数值（POST表单也需要URL编码）
                    String encodedValue = urlEncodeValue(entry.getValue());
                    HttpParameter param = HttpParameter.bodyParameter(entry.getKey(), encodedValue);
                    parametersToAdd.add(param);
                }

                modifiedRequest = modifiedRequest.withAddedParameters(parametersToAdd);

                // 发送请求
                String payloadAlias = String.format("POST-batch-%d", batchIndex + 1);
                sendTestRequest(modifiedRequest, messageId, host, "", payloadAlias);

//                logging.logToOutput(String.format("[ParamAdder] Sent POST batch %d/%d with %d parameters",
//                        batchIndex + 1, batchCount, batchParams.size()));
            }

        } catch (Exception e) {
            logging.logToError("[ParamAdder] addPostParametersBatch error: " + e.getMessage());
        }
    }

    /**
     * 分批添加JSON参数
     */
    private void addJsonParametersBatch(HttpRequest originalRequest, List<ParamCollector.ParamEntry> paramList,
                                        int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            String bodyString = originalRequest.bodyToString();
            if (bodyString == null || bodyString.trim().isEmpty()) {
                bodyString = "{}"; // 如果body为空,创建空对象
            }

            // 解析JSON
            JsonNode rootNode = objectMapper.readTree(bodyString);

            // 如果根节点是数组,不处理
            if (rootNode.isArray()) {
//                logging.logToOutput("[ParamAdder] Root node is array, skipping JSON parameter addition");
                return;
            }

            // 如果根节点不是对象,不处理
            if (!rootNode.isObject()) {
//                logging.logToOutput("[ParamAdder] Root node is not object, skipping JSON parameter addition");
                return;
            }

            // 找到所有符合条件的对象位置
            List<JsonObjectLocation> objectLocations = findAllObjectLocations(rootNode);

            if (objectLocations.isEmpty()) {
//                logging.logToOutput("[ParamAdder] No valid object locations found in JSON");
                return;
            }

//            logging.logToOutput(String.format("[ParamAdder] Found %d object locations in JSON", objectLocations.size()));

            // 计算批次数
            int totalParams = paramList.size();
            int batchCount = (int) Math.ceil((double) totalParams / jsonBatchSize);

            // 对每个Object位置和每个批次组合生成请求
            for (JsonObjectLocation location : objectLocations) {
                if (isShuttingDown) {
                    break;
                }

                for (int batchIndex = 0; batchIndex < batchCount; batchIndex++) {
                    if (isShuttingDown) {
                        break;
                    }

                    int startIndex = batchIndex * jsonBatchSize;
                    int endIndex = Math.min(startIndex + jsonBatchSize, totalParams);
                    List<ParamCollector.ParamEntry> batchParams = paramList.subList(startIndex, endIndex);

                    // 创建JSON副本并插入参数
                    JsonNode modifiedJson = rootNode.deepCopy();
                    ObjectNode targetObject = locateAndGetObject(modifiedJson, location);

                    if (targetObject != null) {
                        // 添加参数到目标对象
                        for (ParamCollector.ParamEntry entry : batchParams) {
                            addParamToJsonObject(targetObject, entry);
                        }

                        // 转换回字符串
                        String modifiedJsonString = objectMapper.writeValueAsString(modifiedJson);

                        // 创建修改后的请求
                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedJsonString);

                        // 发送请求
                        String payloadAlias = String.format("JSON-batch-%d", batchIndex + 1);
                        sendTestRequest(modifiedRequest, messageId, host, "", payloadAlias);

//                        logging.logToOutput(String.format("[ParamAdder] Sent JSON batch %d/%d to location %s with %d parameters",
//                                batchIndex + 1, batchCount, location.getPathString(), batchParams.size()));
                    }
                }
            }

        } catch (Exception e) {
            logging.logToError("[ParamAdder] addJsonParametersBatch error: " + e.getMessage());
        }
    }

    /**
     * JSON对象位置类
     */
    private static class JsonObjectLocation {
        private final List<PathSegment> path;
        private final int depth;

        public JsonObjectLocation(List<PathSegment> path, int depth) {
            this.path = new ArrayList<>(path);
            this.depth = depth;
        }

        public List<PathSegment> getPath() {
            return path;
        }

        public int getDepth() {
            return depth;
        }

        public String getPathString() {
            StringBuilder sb = new StringBuilder();
            for (PathSegment segment : path) {
                if (segment.isArrayElement) {
                    sb.append("[0]");
                } else {
                    if (sb.length() > 0) {
                        sb.append(".");
                    }
                    sb.append(segment.key);
                }
            }
            return sb.toString();
        }
    }

    /**
     * 路径片段
     */
    private static class PathSegment {
        final String key;
        final boolean isArrayElement;

        public PathSegment(String key, boolean isArrayElement) {
            this.key = key;
            this.isArrayElement = isArrayElement;
        }
    }

    /**
     * 找到所有符合条件的对象位置
     */
    private List<JsonObjectLocation> findAllObjectLocations(JsonNode rootNode) {
        List<JsonObjectLocation> locations = new ArrayList<>();
        findObjectLocationsRecursive(rootNode, new ArrayList<>(), 1, locations);
        return locations;
    }

    /**
     * 递归查找对象位置
     */
    private void findObjectLocationsRecursive(JsonNode node, List<PathSegment> currentPath, int currentDepth,
                                              List<JsonObjectLocation> locations) {
        // 超过最大深度，停止
        if (currentDepth > MAX_JSON_DEPTH) {
            return;
        }

        if (node.isObject()) {
            // 记录当前对象位置（包括空对象）
            locations.add(new JsonObjectLocation(currentPath, currentDepth));

            // 继续遍历对象的字段
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String key = field.getKey();
                JsonNode value = field.getValue();

                List<PathSegment> newPath = new ArrayList<>(currentPath);
                newPath.add(new PathSegment(key, false));

                if (value.isArray()) {
                    // 数组本身不算层级，处理数组第一个元素
                    processArrayForObjectLocations(value, newPath, currentDepth + 1, locations);
                } else if (value.isObject()) {
                    // 递归处理对象，层级+1
                    findObjectLocationsRecursive(value, newPath, currentDepth + 1, locations);
                }
                // 其他类型（基本类型）不处理
            }
        }
    }

    /**
     * 处理数组寻找对象位置
     */
    private void processArrayForObjectLocations(JsonNode arrayNode, List<PathSegment> currentPath, int currentDepth,
                                                List<JsonObjectLocation> locations) {
        if (arrayNode.size() == 0) {
            // 空数组，跳过
            return;
        }

        JsonNode firstElement = arrayNode.get(0);

        // 如果第一个元素还是数组，直接跳过（嵌套数组）
        if (firstElement.isArray()) {
            return;
        }

        // 如果第一个元素不是对象，跳过
        if (!firstElement.isObject()) {
            return;
        }

        // 第一个元素是对象，继续处理
        List<PathSegment> newPath = new ArrayList<>(currentPath);
        newPath.add(new PathSegment("", true)); // 标记为数组元素
        findObjectLocationsRecursive(firstElement, newPath, currentDepth, locations);
    }

    /**
     * 根据路径定位并获取对象节点
     */
    private ObjectNode locateAndGetObject(JsonNode rootNode, JsonObjectLocation location) {
        JsonNode current = rootNode;

        for (PathSegment segment : location.getPath()) {
            if (segment.isArrayElement) {
                // 数组元素
                if (current.isArray() && current.size() > 0) {
                    current = current.get(0);
                } else {
                    return null;
                }
            } else {
                // 对象字段
                if (current.isObject() && current.has(segment.key)) {
                    current = current.get(segment.key);
                } else {
                    return null;
                }
            }
        }

        return current.isObject() ? (ObjectNode) current : null;
    }

    /**
     * 添加参数到JSON对象，根据type进行类型转换
     * JSON中不需要URL编码，因为JSON格式本身会自动转义特殊字符
     */
    private void addParamToJsonObject(ObjectNode targetObject, ParamCollector.ParamEntry entry) {
        String key = entry.getKey();
        String value = entry.getValue();
        String type = entry.getType();

        // 根据type进行类型转换
        switch (type.toLowerCase()) {
            case "number":
                try {
                    // 尝试解析为数字
                    if (value.contains(".")) {
                        targetObject.put(key, Double.parseDouble(value));
                    } else {
                        targetObject.put(key, Long.parseLong(value));
                    }
                } catch (NumberFormatException e) {
                    // 解析失败，作为字符串
                    targetObject.put(key, value);
                }
                break;
            case "boolean":
                targetObject.put(key, Boolean.parseBoolean(value));
                break;
            case "null":
                targetObject.putNull(key);
                break;
            case "string":
            default:
                // JSON字符串不需要URL编码，Jackson会自动处理转义
                targetObject.put(key, value);
                break;
        }
    }

    /**
     * 发送测试请求
     */
    private void sendTestRequest(HttpRequest modifiedRequest, int messageId, String host,
                                 String expression, String payloadAlias) {
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
                    "PARAM-ADD",           // testType
                    expression,            // expression: 暂不设置
                    payloadAlias,          // payloadAlias: GET-batch-1, POST-batch-2, JSON-batch-3等
                    "",                    // parameterName: 留空
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(modifiedRequest, tempID, modifiedPair);

        } catch (Exception e) {
            logging.logToError("[ParamAdder] sendTestRequest error: " + e.getMessage());
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
                        logging.logToError("[ParamAdder] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[ParamAdder] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });

        } catch (Exception e) {
            logging.logToError("[ParamAdder] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 设置关闭标志
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ParamAdder] Starting shutdown...");
            logging.logToOutput("[ParamAdder] Shutdown completed");
        }
    }
}