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
    private static final Pattern ID_REGEX = Pattern.compile("(\"[^\"]*ids?\":|[?&][^=&]*ids?=)", Pattern.CASE_INSENSITIVE);

    public JsonLister(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                      RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
        this.emailPattern = Pattern.compile("victim@gmail\\.com");
        this.idPattern = Pattern.compile("(\"[^\"]*ids?\":|[?&][^=&]*ids?=)", Pattern.CASE_INSENSITIVE);
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
            logging.logToOutput("Exception in processRequest: " + e.getMessage());
            e.printStackTrace();
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

                    // 生成 expression
                    String expression = param.name() + "=" + TARGET_EMAIL + "&" + param.name() + "=" + ATTACKER_EMAIL;

                    sendModifiedRequest(modifiedRequest, messageId, host, "EMAIL_QUERY", expression);
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

                JsonNode originalValue = entry.getValue(); // 添加这一行来获取原始值

                // 生成 expression
                String expression = generateJsonExpression(fieldPath, originalValue, emailArray);

                // 发送修改后的请求
                String modifiedBody = objectMapper.writeValueAsString(newRoot);
                HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                sendModifiedRequest(modifiedRequest, messageId, host, "EMAIL_JSON", expression);
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
                    // 直接使用字符串值，支持长整数
                    String originalIdStr = param.value();

                    // 生成各种ID替换变体
                    List<String> variants = generateIdVariants(originalIdStr);

                    for (String variant : variants) {
                        if (isShuttingDown) {
                            return;
                        }

                        HttpRequest modifiedRequest;
                        String expression;

                        if (variant.equals("[]") || variant.equals("null")) {
                            // 直接替换参数值
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant, HttpParameterType.URL);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            expression = param.name() + "=" + variant;
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
                            expression = variant;
                        } else {
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant, HttpParameterType.URL);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            expression = param.name() + "=" + variant;
                        }

                        sendModifiedRequest(modifiedRequest, messageId, host, "ID_QUERY", expression);
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processQueryIdReplacements: " + e.getMessage());
            e.printStackTrace();
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
            if (body.isEmpty()) {
                return;
            }
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

                    // 生成 expression
                    String expression = generateJsonExpression(fieldPath, originalValue, variant);

                    String modifiedBody = objectMapper.writeValueAsString(newRoot);

                    HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                    sendModifiedRequest(modifiedRequest, messageId, host, "ID_JSON", expression);
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processJsonIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 生成 JSON 变体的 expression 字符串 - 简化版本
     * @param fieldPath 字段路径
     * @param originalValue 原始值
     * @param variant 变体值
     * @return expression 字符串
     */
    private String generateJsonExpression(String fieldPath, JsonNode originalValue, JsonNode variant) {
        // 取字段路径的最后一段
        String[] pathParts = fieldPath.split("\\.");
        String lastFieldName = pathParts[pathParts.length - 1];

        // 处理数组索引的情况 (如 "field[0]")
        if (lastFieldName.contains("[") && lastFieldName.contains("]")) {
            lastFieldName = lastFieldName.substring(0, lastFieldName.indexOf("["));
        }

        // 生成变体值的字符串表示
        String variantStr;
        if (variant.isNull()) {
            variantStr = "null";
        } else if (variant.isArray() || variant.isObject()) {
            try {
                variantStr = objectMapper.writeValueAsString(variant);
            } catch (Exception e) {
                variantStr = variant.toString();
            }
        } else if (variant.isTextual()) {
            variantStr = "\"" + variant.asText() + "\"";
        } else {
            variantStr = variant.toString();
        }

        return "\"" + lastFieldName + "\":" + variantStr;
    }

    /**
     * 发送修改后的请求并保存响应
     * @param modifiedRequest 修改后的请求
     * @param messageId 消息ID
     * @param host 主机名
     * @param testType 测试类型
     * @param expression 变体修改的参数表达式
     */
    private void sendModifiedRequest(HttpRequest modifiedRequest, int messageId, String host, String testType, String expression) {
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

            // 保存修改后的请求和响应，传递 expression 参数
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    testType,
                    expression, // 传递 expression 参数
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
     * 递归查找邮箱字段 - 修改版本，支持数组中对象的email字段
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
                    // 检查数组是否直接包含目标email
                    for (JsonNode arrayItem : fieldValue) {
                        if (arrayItem.isTextual() && TARGET_EMAIL.equals(arrayItem.asText())) {
                            emailFields.put(fieldPath, fieldValue);
                            break;
                        }
                    }
                }

                // 不管是否已经找到email，都要继续递归处理嵌套结构
                if (fieldValue.isArray()) {
                    // 检查数组第一个元素是否为对象，如果是，递归查找其中的email字段
                    if (fieldValue.size() > 0) {
                        JsonNode firstElement = fieldValue.get(0);
                        if (firstElement.isObject()) {
                            String arrayFirstPath = fieldPath + "[0]";
                            findEmailFieldsRecursive(firstElement, arrayFirstPath, emailFields);
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
     * 递归查找ID字段 - 修改版本，支持数组中对象的ID字段
     * @param node 当前JSON节点
     * @param currentPath 当前路径
     * @param idFields 结果映射
     */
    private void findIdFieldsRecursive(JsonNode node, String currentPath, Map<String, JsonNode> idFields) {
        logging.logToOutput("Searching for ID fields at path: '" + currentPath + "', node type: " + node.getNodeType());

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                logging.logToOutput("  Examining field: " + fieldName + " at path: " + fieldPath + ", value type: " + fieldValue.getNodeType() + ", value: " + fieldValue);

                // 检查是否为ID参数
                boolean isIdParam = isIdParameter(fieldName);
                logging.logToOutput("    -> isIdParameter('" + fieldName + "'): " + isIdParam);

                if (isIdParam) {
                    logging.logToOutput("    -> Field '" + fieldName + "' is ID parameter");

                    boolean isValidId = false;
                    if (fieldValue.isInt()) {
                        logging.logToOutput("    -> Value is integer (32-bit): " + fieldValue.asInt());
                        isValidId = true;
                    } else if (fieldValue.isLong()) {
                        logging.logToOutput("    -> Value is long integer (64-bit): " + fieldValue.asLong());
                        isValidId = true;
                    } else if (fieldValue.isTextual() && isNumericId(fieldValue.asText())) {
                        logging.logToOutput("    -> Value is numeric string: " + fieldValue.asText());
                        isValidId = true;
                    } else if (fieldValue.isArray() && containsNumericIds(fieldValue)) {
                        logging.logToOutput("    -> Value is array with numeric IDs");
                        isValidId = true;
                    } else {
                        logging.logToOutput("    -> Value is not valid ID format: " + fieldValue + " (type: " + fieldValue.getNodeType() + ")");
                    }

                    if (isValidId) {
                        logging.logToOutput("    -> Adding ID field: " + fieldPath);
                        idFields.put(fieldPath, fieldValue);
                    }
                } else {
                    logging.logToOutput("    -> Field '" + fieldName + "' is NOT an ID parameter");
                }

                // 不管是否是ID字段，都要继续递归处理嵌套结构
                if (fieldValue.isArray()) {
                    logging.logToOutput("    -> Processing array field: " + fieldPath);
                    // 检查数组第一个元素是否为对象，如果是，递归查找其中的ID字段
                    if (fieldValue.size() > 0) {
                        JsonNode firstElement = fieldValue.get(0);
                        logging.logToOutput("    -> Array first element type: " + firstElement.getNodeType());
                        if (firstElement.isObject()) {
                            String arrayFirstPath = fieldPath + "[0]";
                            logging.logToOutput("    -> Recursing into array element: " + arrayFirstPath);
                            findIdFieldsRecursive(firstElement, arrayFirstPath, idFields);
                        }
                    }
                } else if (fieldValue.isObject()) {
                    logging.logToOutput("    -> Recursing into object field: " + fieldPath);
                    findIdFieldsRecursive(fieldValue, fieldPath, idFields);
                }
            }
        }
    }

    /**
     * 检查是否为ID参数 - 修复版本，只匹配以id/ids结尾的字段名
     * @param paramName 参数名
     * @return 是否为ID参数
     */
    private boolean isIdParameter(String paramName) {
        String lowerName = paramName.toLowerCase();
        return lowerName.endsWith("id") || lowerName.endsWith("ids");
    }

    /**
     * 检查是否为数字ID - 修复版本，支持长整数
     * @param value 值
     * @return 是否为数字ID
     */
    private boolean isNumericId(String value) {
        try {
            // 使用Long.parseLong()支持长整数，而不是Integer.parseInt()
            Long.parseLong(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 检查数组是否包含数字ID - 修复版本，支持长整数
     * @param arrayNode 数组节点
     * @return 是否包含数字ID
     */
    private boolean containsNumericIds(JsonNode arrayNode) {
        for (JsonNode item : arrayNode) {
            if (item.isInt() || item.isLong() || (item.isTextual() && isNumericId(item.asText()))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 生成ID变体 - 修复版本，支持长整数
     * @param originalIdStr 原始ID字符串
     * @return ID变体列表
     */
    private List<String> generateIdVariants(String originalIdStr) {
        List<String> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(originalIdStr);

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
        } catch (NumberFormatException e) {
            // 如果不是数字，只添加基本变体
            variants.add("[]");
            variants.add("null");
        }

        return variants;
    }

    /**
     * 生成JSON ID变体 - 修复版本，支持长整数
     * @param originalValue 原始值
     * @return JSON变体列表
     */
    private List<JsonNode> generateJsonIdVariants(JsonNode originalValue) {
        List<JsonNode> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            // 处理32位整数
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
            arrayVariant1.add(id - 10);
            arrayVariant1.add(id - 100);
            variants.add(arrayVariant1);

            // 路径遍历变体
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)));
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)));
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)));

        } else if (originalValue.isLong()) {
            // 处理64位长整数
            long id = originalValue.asLong();

            // 空数组和null
            variants.add(JsonNodeFactory.instance.arrayNode());
            variants.add(JsonNodeFactory.instance.nullNode());
            // 长整型的递减变体
            variants.add(JsonNodeFactory.instance.numberNode(id - 4));
            variants.add(JsonNodeFactory.instance.numberNode(id - 10));
            variants.add(JsonNodeFactory.instance.numberNode(id - 100));
            // 数组变体
            ArrayNode arrayVariant1 = JsonNodeFactory.instance.arrayNode();
            arrayVariant1.add(id);
            arrayVariant1.add(id - 4);
            arrayVariant1.add(id - 10);
            arrayVariant1.add(id - 100);
            variants.add(arrayVariant1);

            // 路径遍历变体
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)));
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)));
            variants.add(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)));

        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);

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
                arrayVariant1.add(String.valueOf(id - 10));
                arrayVariant1.add(String.valueOf(id - 100));
                variants.add(arrayVariant1);

                // 路径遍历变体
                variants.add(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 4)));
                variants.add(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 10)));
                variants.add(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 100)));
            } catch (NumberFormatException e) {
                // 如果解析失败，只添加基本变体
                variants.add(JsonNodeFactory.instance.arrayNode());
                variants.add(JsonNodeFactory.instance.nullNode());
            }

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
                } else if (firstItem.isLong()) {
                    long id = firstItem.asLong();
                    ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                    arrayVariant.add(id);
                    arrayVariant.add(id - 4);
                    arrayVariant.add(id - 10);
                    arrayVariant.add(id - 100);
                    variants.add(arrayVariant);
                } else if (firstItem.isTextual() && isNumericId(firstItem.asText())) {
                    String idStr = firstItem.asText();
                    try {
                        long id = Long.parseLong(idStr);
                        ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                        arrayVariant.add(idStr);
                        arrayVariant.add(String.valueOf(id - 4));
                        arrayVariant.add(String.valueOf(id - 10));
                        arrayVariant.add(String.valueOf(id - 100));
                        variants.add(arrayVariant);
                    } catch (NumberFormatException e) {
                        // 如果解析失败，跳过数组变体生成
                    }
                }
            }
        }

        return variants;
    }

    /**
     * 设置字段值 - 支持数组索引路径
     * @param node 根节点
     * @param path 字段路径 (支持 "field[0].subfield" 格式)
     * @param value 新值
     */
    private void setFieldValue(ObjectNode node, String path, JsonNode value) {
        logging.logToOutput("Setting field value for path: " + path + " to value: " + value);

        String[] pathParts = path.split("\\.");
        logging.logToOutput("Path parts: " + Arrays.toString(pathParts));

        JsonNode current = node;

        for (int i = 0; i < pathParts.length - 1; i++) {
            String part = pathParts[i];
            logging.logToOutput("Processing path part " + i + ": " + part);

            // 检查是否包含数组索引
            if (part.contains("[") && part.contains("]")) {
                String fieldName = part.substring(0, part.indexOf("["));
                String indexStr = part.substring(part.indexOf("[") + 1, part.indexOf("]"));
                int index = Integer.parseInt(indexStr);

                logging.logToOutput("  Array access: field=" + fieldName + ", index=" + index);

                current = current.get(fieldName);
                if (current != null && current.isArray() && index < current.size()) {
                    current = current.get(index);
                    logging.logToOutput("  Successfully accessed array element: " + current.getNodeType());
                } else {
                    logging.logToOutput("  Failed to access array element: current=" + current + ", isArray=" + (current != null && current.isArray()) + ", size=" + (current != null && current.isArray() ? current.size() : "N/A"));
                    return;
                }
            } else {
                logging.logToOutput("  Object field access: " + part);
                current = current.get(part);
                if (current == null) {
                    logging.logToOutput("  Failed to access field: " + part);
                    return;
                } else {
                    logging.logToOutput("  Successfully accessed field: " + current.getNodeType());
                }
            }
        }

        // 处理最后一个路径部分
        String lastPart = pathParts[pathParts.length - 1];
        logging.logToOutput("Setting final field: " + lastPart + " on node type: " + current.getNodeType());

        if (current instanceof ObjectNode) {
            ((ObjectNode) current).set(lastPart, value);
            logging.logToOutput("Successfully set field value");
        } else {
            logging.logToOutput("Cannot set field - current node is not ObjectNode: " + current.getClass());
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