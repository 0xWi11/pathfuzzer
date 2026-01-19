package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
 * ParamDeleter - 使用新NettyManager的版本
 * 参数删除测试器，测试删除参数后的应用行为
 */
public class ParamDeleter {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final Logging logging;
    private final CookieChanger cookieChanger;
    private volatile boolean isShuttingDown = false;

    // 使用新的NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    // 可动态修改的参数数量限制
    private volatile int maxParameterCount = 80;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ParamDeleter(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                        RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.rateLimiter = rateLimiter;
        this.logging = api.logging();
        this.nextModifiedId = nextModifiedId;
        this.cookieChanger = CookieChanger.getInstance();

        // 获取已初始化的NettyManager实例
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[ParamDeleter] Initialization complete, using new NettyManager client");    }

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

            // 如果参数数量超过限制，跳过不测试
            if (totalParamCount > maxParameterCount) {
                return;
            }

            // 首先测试URL参数删除
            deleteUrlParameters(originalRequest, messageId, host);

            // 然后测试POST body参数删除
            deletePostBodyParameters(originalRequest, messageId, host);

            // 最后测试JSON参数删除
            deleteJsonParameters(originalRequest, messageId, host);

        } catch (Exception e) {
            // 按照ParamFuzzer模式进行静默错误处理
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
            List<JsonPath> jsonPaths = extractJsonPaths(rootNode, "", 0);
            return jsonPaths.size();
        } catch (Exception e) {
            return 0;
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
     * 对URL参数进行删除测试
     */
    private void deleteUrlParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        List<ParsedHttpParameter> urlParams = originalRequest.parameters(HttpParameterType.URL);

        // 如果没有URL参数，跳过
        if (urlParams.isEmpty()) {
            return;
        }

        int paramCount = urlParams.size();

        // 根据参数数量决定执行哪些测试
        boolean shouldDoDeleteOne = paramCount >= 2;  // 至少2个参数才做DELETE_ONE
        boolean shouldDoKeepOnly = paramCount >= 3;   // 至少3个参数才做KEEP_ONLY
        boolean shouldDoDeleteAll = true;             // 总是做DELETE_ALL

        // 1. 单独轮流删除每个参数（保留其他参数）
        if (shouldDoDeleteOne) {
            for (ParsedHttpParameter paramToDelete : urlParams) {
                if (isShuttingDown) return;

                try {
                    // 创建删除指定参数后的请求
                    List<ParsedHttpParameter> remainingParams = new ArrayList<>();
                    for (ParsedHttpParameter param : urlParams) {
                        if (!param.name().equals(paramToDelete.name())) {
                            remainingParams.add(param);
                        }
                    }

                    HttpRequest modifiedRequest = createRequestWithUrlParams(originalRequest, remainingParams);
                    String expression = "DELETE_URL_PARAM: " + paramToDelete.name();

                    sendTestRequest(modifiedRequest, messageId, host, expression, "URL_PARAM_DELETE",
                            "DELETE_ONE", paramToDelete.name());

                } catch (Exception e) {
                    // 静默错误处理
                }
            }
        }

        // 2. 保留单个参数的形式
        if (shouldDoKeepOnly) {
            for (ParsedHttpParameter paramToKeep : urlParams) {
                if (isShuttingDown) return;

                try {
                    // 创建只保留指定参数的请求
                    List<ParsedHttpParameter> singleParam = Arrays.asList(paramToKeep);
                    HttpRequest modifiedRequest = createRequestWithUrlParams(originalRequest, singleParam);
                    String expression = "KEEP_ONLY_URL_PARAM: " + paramToKeep.name();

                    sendTestRequest(modifiedRequest, messageId, host, expression, "URL_PARAM_DELETE",
                            "KEEP_ONLY", paramToKeep.name());

                } catch (Exception e) {
                    // 静默错误处理
                }
            }
        }

        // 3. 发送无参数的请求
        if (shouldDoDeleteAll) {
            try {
                HttpRequest modifiedRequest = createRequestWithUrlParams(originalRequest, new ArrayList<>());
                String expression = "DELETE_ALL_URL_PARAMS";

                sendTestRequest(modifiedRequest, messageId, host, expression, "URL_PARAM_DELETE",
                        "DELETE_ALL", "");

            } catch (Exception e) {
                // 静默错误处理
            }
        }
    }

    /**
     * 创建具有指定URL参数的请求
     */
    private HttpRequest createRequestWithUrlParams(HttpRequest originalRequest, List<ParsedHttpParameter> params) {
        // 先移除所有URL参数
        HttpRequest cleanRequest = originalRequest;
        List<ParsedHttpParameter> originalParams = originalRequest.parameters(HttpParameterType.URL);
        for (ParsedHttpParameter param : originalParams) {
            cleanRequest = cleanRequest.withRemovedParameters(param);
        }

        // 添加指定的参数
        for (ParsedHttpParameter param : params) {
            HttpParameter newParam = HttpParameter.urlParameter(param.name(), param.value());
            cleanRequest = cleanRequest.withAddedParameters(newParam);
        }

        return cleanRequest;
    }

    /**
     * 对POST body参数进行删除测试
     */
    private void deletePostBodyParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        // 只有当请求是表单数据时才进行测试
        if (!isFormDataRequest(originalRequest)) {
            return;
        }

        List<ParsedHttpParameter> bodyParams = originalRequest.parameters(HttpParameterType.BODY);

        // 如果没有POST参数，跳过
        if (bodyParams.isEmpty()) {
            return;
        }

        int paramCount = bodyParams.size();

        // 根据参数数量决定执行哪些测试
        boolean shouldDoDeleteOne = paramCount >= 2;  // 至少2个参数才做DELETE_ONE
        boolean shouldDoKeepOnly = paramCount >= 3;   // 至少3个参数才做KEEP_ONLY
        boolean shouldDoDeleteAll = true;             // 总是做DELETE_ALL

        // 1. 单独轮流删除每个参数（保留其他参数）
        if (shouldDoDeleteOne) {
            for (ParsedHttpParameter paramToDelete : bodyParams) {
                if (isShuttingDown) return;

                try {
                    // 创建删除指定参数后的请求
                    List<ParsedHttpParameter> remainingParams = new ArrayList<>();
                    for (ParsedHttpParameter param : bodyParams) {
                        if (!param.name().equals(paramToDelete.name())) {
                            remainingParams.add(param);
                        }
                    }

                    HttpRequest modifiedRequest = createRequestWithBodyParams(originalRequest, remainingParams);
                    String expression = "DELETE_BODY_PARAM: " + paramToDelete.name();

                    sendTestRequest(modifiedRequest, messageId, host, expression, "BODY_PARAM_DELETE",
                            "DELETE_ONE", paramToDelete.name());

                } catch (Exception e) {
                    // 静默错误处理
                }
            }
        }

        // 2. 保留单个参数的形式
        if (shouldDoKeepOnly) {
            for (ParsedHttpParameter paramToKeep : bodyParams) {
                if (isShuttingDown) return;

                try {
                    // 创建只保留指定参数的请求
                    List<ParsedHttpParameter> singleParam = Arrays.asList(paramToKeep);
                    HttpRequest modifiedRequest = createRequestWithBodyParams(originalRequest, singleParam);
                    String expression = "KEEP_ONLY_BODY_PARAM: " + paramToKeep.name();

                    sendTestRequest(modifiedRequest, messageId, host, expression, "BODY_PARAM_DELETE",
                            "KEEP_ONLY", paramToKeep.name());

                } catch (Exception e) {
                    // 静默错误处理
                }
            }
        }

        // 3. 发送无参数的请求
        if (shouldDoDeleteAll) {
            try {
                HttpRequest modifiedRequest = createRequestWithBodyParams(originalRequest, new ArrayList<>());
                String expression = "DELETE_ALL_BODY_PARAMS";

                sendTestRequest(modifiedRequest, messageId, host, expression, "BODY_PARAM_DELETE",
                        "DELETE_ALL", "");

            } catch (Exception e) {
                // 静默错误处理
            }
        }
    }

    /**
     * 创建具有指定Body参数的请求
     */
    private HttpRequest createRequestWithBodyParams(HttpRequest originalRequest, List<ParsedHttpParameter> params) {
        // 先移除所有Body参数
        HttpRequest cleanRequest = originalRequest;
        List<ParsedHttpParameter> originalParams = originalRequest.parameters(HttpParameterType.BODY);
        for (ParsedHttpParameter param : originalParams) {
            cleanRequest = cleanRequest.withRemovedParameters(param);
        }

        // 添加指定的参数
        for (ParsedHttpParameter param : params) {
            HttpParameter newParam = HttpParameter.bodyParameter(param.name(), param.value());
            cleanRequest = cleanRequest.withAddedParameters(newParam);
        }

        return cleanRequest;
    }

    /**
     * 对JSON参数进行删除测试
     */
    private void deleteJsonParameters(HttpRequest originalRequest, int messageId, String host) {
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
            List<JsonPath> jsonPaths = extractJsonPaths(rootNode, "", 0);

            // 如果没有JSON参数，跳过
            if (jsonPaths.isEmpty()) {
                return;
            }

            int paramCount = jsonPaths.size();

            // 根据参数数量决定执行哪些测试
            boolean shouldDoDeleteOne = paramCount >= 2;  // 至少2个参数才做DELETE_ONE
            boolean shouldDoKeepOnly = paramCount >= 3;   // 至少3个参数才做KEEP_ONLY
            boolean shouldDoDeleteAll = true;             // 总是做DELETE_ALL

            // 1. 单独轮流删除每个参数（保留其他参数）
            if (shouldDoDeleteOne) {
                for (JsonPath pathToDelete : jsonPaths) {
                    if (isShuttingDown) return;

                    try {
                        JsonNode modifiedJson = deleteJsonPath(rootNode, pathToDelete.path);
                        String modifiedJsonString = objectMapper.writeValueAsString(modifiedJson);

                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedJsonString);
                        String expression = "DELETE_JSON_PARAM: " + pathToDelete.lastKey;

                        sendTestRequest(modifiedRequest, messageId, host, expression, "JSON_PARAM_DELETE",
                                "DELETE_ONE", pathToDelete.lastKey);

                    } catch (Exception e) {
                        // 静默错误处理
                    }
                }
            }

            // 2. 保留单个参数的形式
            if (shouldDoKeepOnly) {
                for (JsonPath pathToKeep : jsonPaths) {
                    if (isShuttingDown) return;

                    try {
                        JsonNode modifiedJson = keepOnlyJsonPath(rootNode, pathToKeep.path);
                        String modifiedJsonString = objectMapper.writeValueAsString(modifiedJson);

                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedJsonString);
                        String expression = "KEEP_ONLY_JSON_PARAM: " + pathToKeep.lastKey;

                        sendTestRequest(modifiedRequest, messageId, host, expression, "JSON_PARAM_DELETE",
                                "KEEP_ONLY", pathToKeep.lastKey);

                    } catch (Exception e) {
                        // 静默错误处理
                    }
                }
            }

            // 3. 发送空JSON对象的请求
            if (shouldDoDeleteAll) {
                try {
                    String emptyJson = "{}";
                    HttpRequest modifiedRequest = originalRequest.withBody(emptyJson);
                    String expression = "DELETE_ALL_JSON_PARAMS";

                    sendTestRequest(modifiedRequest, messageId, host, expression, "JSON_PARAM_DELETE",
                            "DELETE_ALL", "");

                } catch (Exception e) {
                    // 静默错误处理
                }
            }

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 删除指定JSON路径
     */
    private JsonNode deleteJsonPath(JsonNode rootNode, String pathToDelete) throws Exception {
        ObjectNode rootCopy = rootNode.deepCopy();

        String[] pathParts = pathToDelete.split("\\.");
        JsonNode currentNode = rootCopy;

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

        // 删除最后一部分
        String lastPart = pathParts[pathParts.length - 1];
        if (lastPart.contains("[")) {
            String arrayField = lastPart.substring(0, lastPart.indexOf("["));
            int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
            ((ArrayNode) currentNode.get(arrayField)).remove(arrayIndex);
        } else {
            ((ObjectNode) currentNode).remove(lastPart);
        }

        return rootCopy;
    }

    /**
     * 只保留指定JSON路径
     */
    private JsonNode keepOnlyJsonPath(JsonNode rootNode, String pathToKeep) throws Exception {
        JsonNode valueToKeep = getJsonValueByPath(rootNode, pathToKeep);
        String[] pathParts = pathToKeep.split("\\.");

        // 创建新的JSON结构，只包含要保留的路径
        ObjectNode newRoot = objectMapper.createObjectNode();
        JsonNode currentNew = newRoot;

        for (int i = 0; i < pathParts.length - 1; i++) {
            String part = pathParts[i];
            if (part.contains("[")) {
                String arrayField = part.substring(0, part.indexOf("["));
                int arrayIndex = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));

                ArrayNode arrayNode = objectMapper.createArrayNode();
                ObjectNode objectInArray = objectMapper.createObjectNode();

                // 填充数组到指定索引
                for (int j = 0; j <= arrayIndex; j++) {
                    if (j == arrayIndex) {
                        arrayNode.add(objectInArray);
                    } else {
                        arrayNode.add(objectMapper.createObjectNode());
                    }
                }

                ((ObjectNode) currentNew).set(arrayField, arrayNode);
                currentNew = objectInArray;
            } else {
                ObjectNode nextLevel = objectMapper.createObjectNode();
                ((ObjectNode) currentNew).set(part, nextLevel);
                currentNew = nextLevel;
            }
        }

        // 设置最终值
        String lastPart = pathParts[pathParts.length - 1];
        if (lastPart.contains("[")) {
            String arrayField = lastPart.substring(0, lastPart.indexOf("["));
            int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));

            ArrayNode arrayNode = objectMapper.createArrayNode();
            // 填充数组到指定索引
            for (int j = 0; j <= arrayIndex; j++) {
                if (j == arrayIndex) {
                    arrayNode.add(valueToKeep);
                } else {
                    arrayNode.addNull();
                }
            }
            ((ObjectNode) currentNew).set(arrayField, arrayNode);
        } else {
            ((ObjectNode) currentNew).set(lastPart, valueToKeep);
        }

        return newRoot;
    }

    /**
     * 根据路径获取JSON值
     */
    private JsonNode getJsonValueByPath(JsonNode rootNode, String path) {
        String[] pathParts = path.split("\\.");
        JsonNode currentNode = rootNode;

        for (String part : pathParts) {
            if (part.contains("[")) {
                String arrayField = part.substring(0, part.indexOf("["));
                int arrayIndex = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));
                currentNode = currentNode.get(arrayField).get(arrayIndex);
            } else {
                currentNode = currentNode.get(part);
            }
        }

        return currentNode;
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
     * 提取JSON路径用于删除测试（只处理二层对象）
     */
    private List<JsonPath> extractJsonPaths(JsonNode node, String currentPath) {
        return extractJsonPaths(node, currentPath, 0);
    }

    /**
     * 提取JSON路径用于删除测试（只处理二层对象）
     * @param node 当前JSON节点
     * @param currentPath 当前路径
     * @param depth 当前深度，0表示根级别
     */
    private List<JsonPath> extractJsonPaths(JsonNode node, String currentPath, int depth) {
        List<JsonPath> paths = new ArrayList<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String newPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                if (fieldValue.isObject()) {
                    // 首先添加整个对象的删除路径（这样可以删除整个对象）
                    paths.add(new JsonPath(newPath, fieldValue, fieldName));

                    // 只有在深度小于2时才递归进入对象内部（最多深入2层）
                    if (depth < 2) {
                        paths.addAll(extractJsonPaths(fieldValue, newPath, depth + 1));
                    }
                } else if (fieldValue.isArray()) {
                    // 首先添加整个数组的删除路径
                    paths.add(new JsonPath(newPath, fieldValue, fieldName));

                    // 只有在深度小于2时才处理数组内容
                    if (depth < 2 && fieldValue.size() > 0) {
                        JsonNode firstItem = fieldValue.get(0);
                        String arrayPath = newPath + "[0]";
                        if (!firstItem.isObject()) {
                            paths.add(new JsonPath(arrayPath, firstItem, fieldName + "[0]"));
                        } else {
                            // 添加数组中对象的删除路径
                            paths.add(new JsonPath(arrayPath, firstItem, fieldName + "[0]"));
                            // 递归处理数组中的对象
                            paths.addAll(extractJsonPaths(firstItem, arrayPath, depth + 1));
                        }
                    }
                } else {
                    // 对字符串、数字、布尔值、null值进行删除测试
                    paths.add(new JsonPath(newPath, fieldValue, fieldName));
                }
            }
        }

        return paths;
    }

    /**
     * 发送测试请求 - 使用新NettyManager
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
                    "PARAM_DELETE",
                    expression,
                    payloadAlias,      // payload别名
                    parameterName,      // 当前测试参数的名称
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
                        logging.logToError("[ParamDeleter] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[ParamDeleter] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 设置关闭状态
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ParamDeleter] Starting shutdown...");
            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作

            logging.logToOutput("[ParamDeleter] Shutdown complete");        }
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