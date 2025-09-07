package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.IOException;

import burp.api.montoya.http.message.responses.HttpResponse;
import okhttp3.*;
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
import pzfzr.core.OkHttpManager;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;

public class ParamDeleter {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final Logging logging;
    private final CookieChanger cookieChanger;
    private volatile boolean isShuttingDown = false;
    private final OkHttpManager okHttpManager;

    // 用于跟踪正在进行的请求
    private final Set<Call> activeRequests = Collections.newSetFromMap(new ConcurrentHashMap<>());

    // 可动态修改的参数数量限制
    private volatile int maxParameterCount = 30;

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

        // 获取已初始化的OkHttpManager实例
        this.okHttpManager = OkHttpManager.getInstance();

        logging.logToOutput("[ParamDeleter] 初始化完成，使用OkHttp客户端");
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
     * 发送测试请求 - 使用OkHttp
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

            // 使用OkHttp发送请求
            sendTestRequestAsync(modifiedRequest, tempID, modifiedPair);

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 异步发送测试请求 - 使用OkHttp
     */
    private void sendTestRequestAsync(HttpRequest modifiedRequest, int tempID, ModifiedRequestResponse modifiedPair) {
        if (isShuttingDown) {
            return;
        }

        try {
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
                    logging.logToError("[ParamDeleter] Request failed for ID " + tempID + ": " + e.getMessage());
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    activeRequests.remove(call);

                    try {
                        // 使用OkHttpManager的extractResponseTime方法获取精确的响应时间
                        long responseTime = okHttpManager.extractResponseTime(response);

                        // 如果无法获取精确时间（返回-1），使用备用计算方法
                        if (responseTime == -1) {
                            responseTime = 0; // 或者设置为一个默认值
                            logging.logToOutput("[ParamDeleter] 无法获取精确响应时间，使用默认值: " + responseTime + "ms");
                        }

                        // 转换响应为Burp格式
                        HttpResponse burpResponse = okHttpManager.convertToBurpResponse(response);

                        // 处理响应，使用从OkHttpManager获取的精确响应时间
                        requestResponseSaver.handleOkHttpResponse(burpResponse, tempID, responseTime, modifiedPair);

                    } catch (Exception e) {
                        logging.logToError("[ParamDeleter] Error processing response for ID " + tempID + ": " + e.getMessage());
                    } finally {
                        response.close();
                    }
                }
            });

        } catch (Exception e) {
            logging.logToError("[ParamDeleter] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 设置关闭状态
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ParamDeleter] 开始关闭，取消所有活动请求...");

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
                logging.logToOutput("[ParamDeleter] 强制关闭 " + activeRequests.size() + " 个未完成的请求");
                activeRequests.clear();
            }

            logging.logToOutput("[ParamDeleter] 关闭完成");
        }
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