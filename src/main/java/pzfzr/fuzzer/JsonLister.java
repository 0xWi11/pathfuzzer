package pzfzr.fuzzer;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import pzfzr.core.CookieChanger;
import pzfzr.core.RateLimiter;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * JsonLister类用于对HTTP请求中的参数进行替换和污染测试
 * 主要处理邮箱和ID类型的参数替换
 */
public class JsonLister {

    private final MontoyaApi api;
    private final ObjectMapper objectMapper;
    private final Pattern emailPattern;
    private final Pattern idPattern;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final AtomicInteger nextModifiedId;
    private volatile boolean isShuttingDown = false;

    // 常量定义
    private static final String TARGET_EMAIL = "victim@gmail.com";
    private static final String ATTACKER_EMAIL = "attacker@gmail.com";
    private static final Pattern EMAIL_REGEX = Pattern.compile("victim@gmail\\.com");
    private static final Pattern ID_REGEX = Pattern.compile(".*id[s]?[=:]");

    public JsonLister(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                      RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
        this.emailPattern = Pattern.compile("victim@gmail\\.com");
        this.idPattern = Pattern.compile(".*id[s]?[=:]");
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.nextModifiedId = nextModifiedId;
    }

    /**
     * 主要处理方法，接收HttpRequest并进行参数替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            String requestString = originalRequest.toString();

            // 检查是否包含邮箱模式
            boolean hasEmail = emailPattern.matcher(requestString).find();

            // 检查是否包含ID模式
            boolean hasId = idPattern.matcher(requestString).find();

            if (hasEmail) {
                processEmailReplacements(originalRequest, messageId, host);
            }

            if (hasId) {
                processIdReplacements(originalRequest, messageId, host);
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理邮箱参数替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processEmailReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 处理Query参数中的邮箱
            processQueryEmailReplacements(originalRequest, messageId, host);

            // 处理JSON参数中的邮箱
            if (originalRequest.contentType() == ContentType.JSON) {
                processJsonEmailReplacements(originalRequest, messageId, host);
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理Query参数中的邮箱替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processQueryEmailReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            List<ParsedHttpParameter> queryParams = originalRequest.parameters(HttpParameterType.URL);

            for (ParsedHttpParameter param : queryParams) {
                if (isShuttingDown) {
                    return;
                }

                if (TARGET_EMAIL.equals(param.value())) {
                    // 创建污染参数: email=victim@gmail.com&email=attacker@gmail.com
                    HttpParameter newParam = HttpParameter.parameter(param.name(), ATTACKER_EMAIL, HttpParameterType.URL);
                    HttpRequest modifiedRequest = originalRequest.withAddedParameters(newParam);
                    sendModifiedRequest(modifiedRequest, messageId, host, "EMAIL_QUERY");
                }
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理JSON参数中的邮箱替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processJsonEmailReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            String body = originalRequest.bodyToString();
            if (body.isEmpty()) return;

            JsonNode rootNode = objectMapper.readTree(body);
            Map<String, JsonNode> emailFields = findEmailFields(rootNode);

            for (Map.Entry<String, JsonNode> entry : emailFields.entrySet()) {
                if (isShuttingDown) {
                    return;
                }

                String fieldPath = entry.getKey();

                // 创建新的JSON with email array
                ObjectNode newRoot = rootNode.deepCopy();

                // 创建邮箱数组
                ArrayNode emailArray = JsonNodeFactory.instance.arrayNode();
                emailArray.add(TARGET_EMAIL);
                emailArray.add(ATTACKER_EMAIL);

                // 替换字段值
                setFieldValue(newRoot, fieldPath, emailArray);

                // 发送修改后的请求
                String modifiedBody = objectMapper.writeValueAsString(newRoot);
                HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                sendModifiedRequest(modifiedRequest, messageId, host, "EMAIL_JSON");
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理ID参数替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processIdReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 处理Query参数中的ID
            processQueryIdReplacements(originalRequest, messageId, host);

            // 处理JSON参数中的ID
            if (originalRequest.contentType() == ContentType.JSON) {
                processJsonIdReplacements(originalRequest, messageId, host);
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理Query参数中的ID替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processQueryIdReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            List<ParsedHttpParameter> queryParams = originalRequest.parameters(HttpParameterType.URL);

            for (ParsedHttpParameter param : queryParams) {
                if (isShuttingDown) {
                    return;
                }

                if (isIdParameter(param.name()) && isNumericId(param.value())) {
                    int originalId = Integer.parseInt(param.value());

                    // 生成各种ID替换变体
                    List<String> variants = generateIdVariants(originalId);

                    for (String variant : variants) {
                        if (isShuttingDown) {
                            return;
                        }

                        HttpRequest modifiedRequest;
                        if (variant.equals("[]") || variant.equals("null")) {
                            // 直接替换参数值
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant, HttpParameterType.URL);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                        } else if (variant.contains("&")) {
                            // 参数污染情况
                            String[] parts = variant.split("&");
                            List<HttpParameter> newParams = new ArrayList<>();
                            for (String part : parts) {
                                String[] keyValue = part.split("=");
                                if (keyValue.length == 2) {
                                    newParams.add(HttpParameter.parameter(keyValue[0], keyValue[1], HttpParameterType.URL));
                                }
                            }
                            modifiedRequest = originalRequest.withUpdatedParameters(newParams);
                        } else {
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant, HttpParameterType.URL);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                        }

                        sendModifiedRequest(modifiedRequest, messageId, host, "ID_QUERY");
                    }
                }
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理JSON参数中的ID替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processJsonIdReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            String body = originalRequest.bodyToString();
            if (body.isEmpty()) return;

            JsonNode rootNode = objectMapper.readTree(body);
            Map<String, JsonNode> idFields = findIdFields(rootNode);

            for (Map.Entry<String, JsonNode> entry : idFields.entrySet()) {
                if (isShuttingDown) {
                    return;
                }

                String fieldPath = entry.getKey();
                JsonNode originalValue = entry.getValue();

                List<JsonNode> variants = generateJsonIdVariants(originalValue);

                for (JsonNode variant : variants) {
                    if (isShuttingDown) {
                        return;
                    }

                    ObjectNode newRoot = rootNode.deepCopy();
                    setFieldValue(newRoot, fieldPath, variant);

                    String modifiedBody = objectMapper.writeValueAsString(newRoot);
                    HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                    sendModifiedRequest(modifiedRequest, messageId, host, "ID_JSON");
                }
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 发送修改后的请求并保存响应
     * @param modifiedRequest 修改后的请求
     * @param messageId 消息ID
     * @param host 主机名
     * @param testType 测试类型
     */
    private void sendModifiedRequest(HttpRequest modifiedRequest, int messageId, String host, String testType) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
            }

            // 应用速率限制
            rateLimiter.acquire(modifiedRequest.url() + modifiedRequest.method());

            // 发送修改后的请求
            HttpRequestResponse modifiedResponse = api.http().sendRequest(modifiedRequest);
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求和响应
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    testType,
                    requestResponseSaver,
                    logging
            );

            tableModel.addModifiedEntry(modifiedPair);
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);
            requestResponseSaver.handleDelayedModifiedResponse(modifiedResponse, tempID);

            // 清理内存
            modifiedRequest = null;
            modifiedResponse = null;

        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 查找JSON中的邮箱字段
     * @param node JSON节点
     * @return 邮箱字段路径和值的映射
     */
    private Map<String, JsonNode> findEmailFields(JsonNode node) {
        Map<String, JsonNode> emailFields = new HashMap<>();
        findEmailFieldsRecursive(node, "", emailFields);
        return emailFields;
    }

    /**
     * 递归查找邮箱字段
     * @param node 当前JSON节点
     * @param currentPath 当前路径
     * @param emailFields 结果映射
     */
    private void findEmailFieldsRecursive(JsonNode node, String currentPath, Map<String, JsonNode> emailFields) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                if (fieldValue.isTextual() && TARGET_EMAIL.equals(fieldValue.asText())) {
                    emailFields.put(fieldPath, fieldValue);
                } else if (fieldValue.isArray()) {
                    for (JsonNode arrayItem : fieldValue) {
                        if (arrayItem.isTextual() && TARGET_EMAIL.equals(arrayItem.asText())) {
                            emailFields.put(fieldPath, fieldValue);
                            break;
                        }
                    }
                } else if (fieldValue.isObject()) {
                    findEmailFieldsRecursive(fieldValue, fieldPath, emailFields);
                }
            }
        }
    }

    /**
     * 查找JSON中的ID字段
     * @param node JSON节点
     * @return ID字段路径和值的映射
     */
    private Map<String, JsonNode> findIdFields(JsonNode node) {
        Map<String, JsonNode> idFields = new HashMap<>();
        findIdFieldsRecursive(node, "", idFields);
        return idFields;
    }

    /**
     * 递归查找ID字段
     * @param node 当前JSON节点
     * @param currentPath 当前路径
     * @param idFields 结果映射
     */
    private void findIdFieldsRecursive(JsonNode node, String currentPath, Map<String, JsonNode> idFields) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                if (isIdParameter(fieldName)) {
                    if (fieldValue.isInt() ||
                            (fieldValue.isTextual() && isNumericId(fieldValue.asText())) ||
                            (fieldValue.isArray() && containsNumericIds(fieldValue))) {
                        idFields.put(fieldPath, fieldValue);
                    }
                } else if (fieldValue.isObject()) {
                    findIdFieldsRecursive(fieldValue, fieldPath, idFields);
                }
            }
        }
    }

    /**
     * 检查是否为ID参数
     * @param paramName 参数名
     * @return 是否为ID参数
     */
    private boolean isIdParameter(String paramName) {
        return paramName.toLowerCase().contains("id");
    }

    /**
     * 检查是否为数字ID
     * @param value 值
     * @return 是否为数字ID
     */
    private boolean isNumericId(String value) {
        try {
            Integer.parseInt(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 检查数组是否包含数字ID
     * @param arrayNode 数组节点
     * @return 是否包含数字ID
     */
    private boolean containsNumericIds(JsonNode arrayNode) {
        for (JsonNode item : arrayNode) {
            if (item.isInt() || (item.isTextual() && isNumericId(item.asText()))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 生成ID变体
     * @param originalId 原始ID
     * @return ID变体列表
     */
    private List<String> generateIdVariants(int originalId) {
        List<String> variants = new ArrayList<>();

        // 基本变体
        variants.add("[]");
        variants.add("null");

        // 参数污染变体
        variants.add("id=" + originalId + "&id=" + (originalId - 4));
        variants.add("id=" + originalId + "&id=" + (originalId - 10));
        variants.add("id=" + originalId + "&id=" + (originalId - 100));

        // 路径遍历变体
        variants.add(originalId + "/../" + (originalId - 4));
        variants.add(originalId + "/../" + (originalId - 10));
        variants.add(originalId + "/../" + (originalId - 100));

        return variants;
    }

    /**
     * 生成JSON ID变体
     * @param originalValue 原始值
     * @return JSON变体列表
     */
    private List<JsonNode> generateJsonIdVariants(JsonNode originalValue) {
        List<JsonNode> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            int id = originalValue.asInt();

            // 空数组和null
            variants.add(JsonNodeFactory.instance.arrayNode());
            variants.add(JsonNodeFactory.instance.nullNode());
            // 整型的递减变体
            variants.add(JsonNodeFactory.instance.numberNode(id - 4));
            variants.add(JsonNodeFactory.instance.numberNode(id - 10));
            variants.add(JsonNodeFactory.instance.numberNode(id - 100));
            // 数组变体
            ArrayNode arrayVariant1 = JsonNodeFactory.instance.arrayNode();
            arrayVariant1.add(id);
            arrayVariant1.add(id - 4);
            variants.add(arrayVariant1);

            ArrayNode arrayVariant2 = JsonNodeFactory.instance.arrayNode();
            arrayVariant2.add(id);
            arrayVariant2.add(id - 10);
            variants.add(arrayVariant2);

            ArrayNode arrayVariant3 = JsonNodeFactory.instance.arrayNode();
            arrayVariant3.add(id);
            arrayVariant3.add(id - 100);
            variants.add(arrayVariant3);

            // 路径遍历变体
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)));
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)));
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)));

        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            int id = Integer.parseInt(idStr);

            // 空数组和null
            variants.add(JsonNodeFactory.instance.arrayNode());
            variants.add(JsonNodeFactory.instance.nullNode());
            // 字符串型但是数值递减的变体
            variants.add(JsonNodeFactory.instance.textNode(String.valueOf(id - 4)));
            variants.add(JsonNodeFactory.instance.textNode(String.valueOf(id - 10)));
            variants.add(JsonNodeFactory.instance.textNode(String.valueOf(id - 100)));
            // 字符串数组变体
            ArrayNode arrayVariant1 = JsonNodeFactory.instance.arrayNode();
            arrayVariant1.add(idStr);
            arrayVariant1.add(String.valueOf(id - 4));
            variants.add(arrayVariant1);

            ArrayNode arrayVariant2 = JsonNodeFactory.instance.arrayNode();
            arrayVariant2.add(idStr);
            arrayVariant2.add(String.valueOf(id - 10));
            variants.add(arrayVariant2);

            ArrayNode arrayVariant3 = JsonNodeFactory.instance.arrayNode();
            arrayVariant3.add(idStr);
            arrayVariant3.add(String.valueOf(id - 100));
            variants.add(arrayVariant3);

            // 路径遍历变体
            variants.add(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 4)));
            variants.add(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 10)));
            variants.add(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 100)));

        } else if (originalValue.isArray()) {
            // 数组情况
            variants.add(JsonNodeFactory.instance.arrayNode());
            variants.add(JsonNodeFactory.instance.nullNode());

            // 提取第一个ID值来生成变体
            JsonNode firstItem = originalValue.get(0);
            if (firstItem != null) {
                if (firstItem.isInt()) {
                    int id = firstItem.asInt();
                    ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                    arrayVariant.add(id);
                    arrayVariant.add(id - 4);
                    arrayVariant.add(id - 10);
                    arrayVariant.add(id - 100);
                    variants.add(arrayVariant);
                } else if (firstItem.isTextual() && isNumericId(firstItem.asText())) {
                    String idStr = firstItem.asText();
                    int id = Integer.parseInt(idStr);
                    ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                    arrayVariant.add(idStr);
                    arrayVariant.add(String.valueOf(id - 4));
                    arrayVariant.add(String.valueOf(id - 10));
                    arrayVariant.add(String.valueOf(id - 100));
                    variants.add(arrayVariant);
                }
            }
        }

        return variants;
    }

    /**
     * 设置字段值
     * @param node 根节点
     * @param path 字段路径
     * @param value 新值
     */
    private void setFieldValue(ObjectNode node, String path, JsonNode value) {
        String[] pathParts = path.split("\\.");
        JsonNode current = node;

        for (int i = 0; i < pathParts.length - 1; i++) {
            current = current.get(pathParts[i]);
            if (current == null) {
                return;
            }
        }

        if (current instanceof ObjectNode) {
            ((ObjectNode) current).set(pathParts[pathParts.length - 1], value);
        }
    }

    /**
     * 设置停止状态
     * @param shuttingDown 是否停止
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
    }
}