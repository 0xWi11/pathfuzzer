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
import java.util.regex.Matcher;

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

    // Hash 生成相关常量
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int HASH_LENGTH = 5;
    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);

    // 邮箱匹配正则表达式 - 修改为匹配新的邮箱格式
    private static final Pattern EMAIL_REGEX = Pattern.compile(
            "(zycc[+-][a-zA-Z0-9]+@intigriti\\.me|zcyy[+-][a-zA-Z0-9]+@(bugcrowdninja|wearehackerone)\\.com)"
    );
    private static final Pattern ID_REGEX = Pattern.compile("(\"[^\"]*ids?\":|[?&][^=&]*ids?=)", Pattern.CASE_INSENSITIVE);

    public JsonLister(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                      RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
        this.emailPattern = EMAIL_REGEX;
        this.idPattern = Pattern.compile("(\"[^\"]*ids?\":|[?&][^=&]*ids?=)", Pattern.CASE_INSENSITIVE);
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.nextModifiedId = nextModifiedId;
    }

    /**
     * 生成随机hash值
     * @return 5位随机hash字符串
     */
    private String generateHash() {
        char[] hash = new char[HASH_LENGTH];
        for (int i = 0; i < HASH_LENGTH; i++) {
            hash[i] = HASH_CHARS.charAt(RANDOM.get().nextInt(HASH_CHARS.length()));
        }
        return new String(hash);
    }

    /**
     * 根据目标邮箱生成攻击者邮箱
     * @param targetEmail 目标邮箱
     * @return 攻击者邮箱
     */
    private String generateAttackerEmail(String targetEmail) {
        String hash = generateHash();

        if (targetEmail.startsWith("zycc+") && targetEmail.endsWith("@intigriti.me")) {
            return "zycc+veryuser" + hash + "@intigriti.me";
        } else if (targetEmail.startsWith("zycc-") && targetEmail.endsWith("@intigriti.me")) {
            return "zycc-veryuser" + hash + "@intigriti.me";
        } else if (targetEmail.startsWith("zcyy+") && targetEmail.endsWith("@bugcrowdninja.com")) {
            return "zcyy+veryuser" + hash + "@bugcrowdninja.com";
        } else if (targetEmail.startsWith("zcyy-") && targetEmail.endsWith("@bugcrowdninja.com")) {
            return "zcyy-veryuser" + hash + "@bugcrowdninja.com";
        } else if (targetEmail.startsWith("zcyy+") && targetEmail.endsWith("@wearehackerone.com")) {
            return "zcyy+veryuser" + hash + "@wearehackerone.com";
        } else if (targetEmail.startsWith("zcyy-") && targetEmail.endsWith("@wearehackerone.com")) {
            return "zcyy-veryuser" + hash + "@wearehackerone.com";
        }

        // 默认返回原邮箱（不应该发生）
        return targetEmail;
    }

    /**
     * 检查邮箱是否匹配目标模式
     * @param email 邮箱地址
     * @return 是否匹配
     */
    private boolean isTargetEmail(String email) {
        return EMAIL_REGEX.matcher(email).matches();
    }

    /**
     * Payload变体类 - 将payload值和别名绑定在一起
     */
    private static class PayloadVariant {
        private final String value;
        private final String expression;
        private final String alias;
        private final boolean isParameterPollution;
        private final boolean isArrayFormat;
        private final String secondValue;

        public PayloadVariant(String value, String expression, String alias, boolean isParameterPollution, boolean isArrayFormat, String secondValue) {
            this.value = value;
            this.expression = expression;
            this.alias = alias;
            this.isParameterPollution = isParameterPollution;
            this.isArrayFormat = isArrayFormat;
            this.secondValue = secondValue;
        }

        public String getValue() { return value; }
        public String getExpression() { return expression; }
        public String getAlias() { return alias; }
        public boolean isParameterPollution() { return isParameterPollution; }
        public boolean isArrayFormat() { return isArrayFormat; }
        public String getSecondValue() { return secondValue; }
    }

    /**
     * JSON Payload变体类 - 用于JSON格式的payload
     */
    private static class JsonPayloadVariant {
        private final JsonNode value;
        private final String alias;

        public JsonPayloadVariant(JsonNode value, String alias) {
            this.value = value;
            this.alias = alias;
        }

        public JsonNode getValue() { return value; }
        public String getAlias() { return alias; }
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
     * 检查字符串是否为JSON格式
     */
    private boolean isJsonFormat(String text) {
        if (text == null || text.trim().isEmpty()) {
            return false;
        }
        try {
            objectMapper.readTree(text);
            return true;
        } catch (Exception e) {
            return false;
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

            // 处理POST body参数
            String bodyString = originalRequest.bodyToString();
            if (!bodyString.isEmpty()) {
                if (isJsonFormat(bodyString)) {
                    // 处理JSON格式的body参数
                    processJsonEmailReplacements(originalRequest, messageId, host);
                } else {
                    // 处理URL编码格式的body参数
                    processBodyEmailReplacements(originalRequest, messageId, host);
                }
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

                if (isTargetEmail(param.value())) {
                    String targetEmail = param.value();
                    String attackerEmail = generateAttackerEmail(targetEmail);

                    // 创建污染参数: email=target@email.com&email=attacker@email.com
                    HttpParameter newParam = HttpParameter.parameter(param.name(), attackerEmail, HttpParameterType.URL);
                    HttpRequest modifiedRequest = originalRequest.withAddedParameters(newParam);

                    // 生成 expression - 仅包含新增的污染参数
                    String expression = "&" + param.name() + "=" + attackerEmail;

                    sendModifiedRequest(modifiedRequest, messageId, host, expression, "&email", param.name());
                }
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理POST body中URL编码格式的邮箱替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processBodyEmailReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            List<ParsedHttpParameter> bodyParams = originalRequest.parameters(HttpParameterType.BODY);

            for (ParsedHttpParameter param : bodyParams) {
                if (isShuttingDown) {
                    return;
                }

                if (isTargetEmail(param.value())) {
                    String targetEmail = param.value();
                    String attackerEmail = generateAttackerEmail(targetEmail);

                    // 创建污染参数: email=target@email.com&email=attacker@email.com
                    HttpParameter newParam = HttpParameter.parameter(param.name(), attackerEmail, HttpParameterType.BODY);
                    HttpRequest modifiedRequest = originalRequest.withAddedParameters(newParam);

                    // 生成 expression - 仅包含新增的污染参数
                    String expression = "&" + param.name() + "=" + attackerEmail;

                    sendModifiedRequest(modifiedRequest, messageId, host, expression, "&email", param.name());
                }
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
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
                JsonNode originalValue = entry.getValue();

                // 获取原始邮箱值
                String targetEmail = null;
                if (originalValue.isTextual()) {
                    targetEmail = originalValue.asText();
                } else if (originalValue.isArray() && originalValue.size() > 0) {
                    // 如果是数组，获取第一个匹配的邮箱
                    for (JsonNode item : originalValue) {
                        if (item.isTextual() && isTargetEmail(item.asText())) {
                            targetEmail = item.asText();
                            break;
                        }
                    }
                }

                if (targetEmail != null && isTargetEmail(targetEmail)) {
                    String attackerEmail = generateAttackerEmail(targetEmail);

                    // 创建新的JSON with email array
                    ObjectNode newRoot = rootNode.deepCopy();

                    // 创建邮箱数组
                    ArrayNode emailArray = JsonNodeFactory.instance.arrayNode();
                    emailArray.add(targetEmail);
                    emailArray.add(attackerEmail);

                    // 替换字段值
                    setFieldValue(newRoot, fieldPath, emailArray);

                    // 生成 expression
                    String expression = generateJsonExpression(fieldPath, originalValue, emailArray);

                    // 提取参数名称（JSON路径的最后一段）
                    String currentParamName = extractParamNameFromPath(fieldPath);

                    // 发送修改后的请求
                    String modifiedBody = objectMapper.writeValueAsString(newRoot);
                    HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                    sendModifiedRequest(modifiedRequest, messageId, host, expression, "2emails", currentParamName);
                }
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

            // 处理POST body参数
            String bodyString = originalRequest.bodyToString();
            if (!bodyString.isEmpty()) {
                if (isJsonFormat(bodyString)) {
                    // 处理JSON格式的body参数
                    processJsonIdReplacements(originalRequest, messageId, host);
                } else {
                    // 处理URL编码格式的body参数
                    processBodyIdReplacements(originalRequest, messageId, host);
                }
            }
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    /**
     * 处理POST body中URL编码格式的ID替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processBodyIdReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            List<ParsedHttpParameter> bodyParams = originalRequest.parameters(HttpParameterType.BODY);

            for (ParsedHttpParameter param : bodyParams) {
                if (isShuttingDown) {
                    return;
                }

                if (isIdParameter(param.name()) && isNumericId(param.value())) {
                    // 直接使用字符串值，支持长整数
                    String originalIdStr = param.value();

                    // 生成各种ID替换变体 - 现在返回PayloadVariant列表
                    List<PayloadVariant> variants = generateBodyIdPayloadVariants(originalIdStr, param.name());

                    for (PayloadVariant variant : variants) {
                        if (isShuttingDown) {
                            return;
                        }

                        HttpRequest modifiedRequest;

                        if (variant.isParameterPollution()) {
                            // 参数污染情况 - 添加新的参数
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getSecondValue(), HttpParameterType.BODY);
                            modifiedRequest = originalRequest.withAddedParameters(newParam);
                        } else {
                            // 直接替换参数值
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getValue(), HttpParameterType.BODY);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                        }

                        sendModifiedRequest(modifiedRequest, messageId, host, variant.getExpression(), variant.getAlias(), param.name());
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processBodyIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
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

                    // 生成各种ID替换变体 - 现在返回PayloadVariant列表
                    List<PayloadVariant> variants = generateQueryIdPayloadVariants(originalIdStr, param.name());

                    for (PayloadVariant variant : variants) {
                        if (isShuttingDown) {
                            return;
                        }

                        HttpRequest modifiedRequest;

                        if (variant.isParameterPollution()) {
                            // 参数污染情况 - 添加新的参数
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getSecondValue(), HttpParameterType.URL);
                            modifiedRequest = originalRequest.withAddedParameters(newParam);
                        } else if (variant.isArrayFormat()) {
                            // 数组格式 - 修复：添加新的数组格式变体 [500,496,490,400]
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getValue(), HttpParameterType.URL);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                        } else {
                            // 直接替换参数值
                            HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getValue(), HttpParameterType.URL);
                            modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                        }

                        sendModifiedRequest(modifiedRequest, messageId, host, variant.getExpression(), variant.getAlias(), param.name());
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

                List<JsonPayloadVariant> variants = generateJsonIdPayloadVariants(originalValue);
                for (JsonPayloadVariant variant : variants) {
                    if (isShuttingDown) {
                        return;
                    }

                    ObjectNode newRoot = rootNode.deepCopy();
                    setFieldValue(newRoot, fieldPath, variant.getValue());

                    // 生成 expression
                    String expression = generateJsonExpression(fieldPath, originalValue, variant.getValue());

                    // 提取参数名称（JSON路径的最后一段）
                    String currentParamName = extractParamNameFromPath(fieldPath);

                    String modifiedBody = objectMapper.writeValueAsString(newRoot);

                    HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                    sendModifiedRequest(modifiedRequest, messageId, host, expression, variant.getAlias(), currentParamName);
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processJsonIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 生成Body ID的PayloadVariant列表 - 将payload和别名绑定
     * @param originalIdStr 原始ID字符串
     * @param paramName 参数名称
     * @return PayloadVariant列表
     */
    private List<PayloadVariant> generateBodyIdPayloadVariants(String originalIdStr, String paramName) {
        List<PayloadVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(originalIdStr);

            // 基本变体 - 直接将payload值和别名绑定
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));

            // 整型的递减变体
            variants.add(new PayloadVariant(String.valueOf(originalId - 4), paramName + "=" + (originalId - 4), "-4", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 10), paramName + "=" + (originalId - 10), "-10", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 100), paramName + "=" + (originalId - 100), "-100", false, false, null));

            // 参数污染变体 - 修改为仅包含新增的污染参数
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 4), "pollute-4", true, false, String.valueOf(originalId - 4)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 10), "pollute-10", true, false, String.valueOf(originalId - 10)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 100), "pollute-100", true, false, String.valueOf(originalId - 100)));

            // 新增：数组格式变体 XXID=500 -> XXID=[500,496,490,400]
            String arrayFormat = "[" + originalId + "," + (originalId - 4) + "," + (originalId - 10) + "," + (originalId - 100) + "]";
            variants.add(new PayloadVariant(arrayFormat, paramName + "=" + arrayFormat, "to[-4-10-100]", false, true, null));

            // 路径遍历变体
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 4), paramName + "=" + originalId + "/../" + (originalId - 4), "/../-4", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 10), paramName + "=" + originalId + "/../" + (originalId - 10), "/../-10", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 100), paramName + "=" + originalId + "/../" + (originalId - 100), "/../-100", false, false, null));
        } catch (NumberFormatException e) {
            // 如果不是数字，只添加基本变体
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
        }

        return variants;
    }

    /**
     * 生成Query ID的PayloadVariant列表 - 将payload和别名绑定
     * @param originalIdStr 原始ID字符串
     * @param paramName 参数名称
     * @return PayloadVariant列表
     */
    private List<PayloadVariant> generateQueryIdPayloadVariants(String originalIdStr, String paramName) {
        List<PayloadVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(originalIdStr);

            // 基本变体 - 直接将payload值和别名绑定
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));

            // 整型的递减变体
            variants.add(new PayloadVariant(String.valueOf(originalId - 4), paramName + "=" + (originalId - 4), "-4", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 10), paramName + "=" + (originalId - 10), "-10", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 100), paramName + "=" + (originalId - 100), "100", false, false, null));

            // 参数污染变体 - 修改为仅包含新增的污染参数
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 4), "pollute-4", true, false, String.valueOf(originalId - 4)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 10), "pollute-10", true, false, String.valueOf(originalId - 10)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 100), "pollute-100", true, false, String.valueOf(originalId - 100)));

            // 新增：数组格式变体 XXID=500 -> XXID=[500,496,490,400]
            String arrayFormat = "[" + originalId + "," + (originalId - 4) + "," + (originalId - 10) + "," + (originalId - 100) + "]";
            variants.add(new PayloadVariant(arrayFormat, paramName + "=" + arrayFormat, "to[-4-10-100]", false, true, null));

            // 路径遍历变体
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 4), paramName + "=" + originalId + "/../" + (originalId - 4), "/../-4", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 10), paramName + "=" + originalId + "/../" + (originalId - 10), "/../-10", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 100), paramName + "=" + originalId + "/../" + (originalId - 100), "/../-100", false, false, null));
        } catch (NumberFormatException e) {
            // 如果不是数字，只添加基本变体
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
        }

        return variants;
    }

    /**
     * 生成JSON ID的JsonPayloadVariant列表 - 将payload和别名绑定
     * @param originalValue 原始值
     * @return JsonPayloadVariant列表
     */
    private List<JsonPayloadVariant> generateJsonIdPayloadVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            // 处理32位整数
            int id = originalValue.asInt();

            // 空数组和null
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
            // 整型的递减变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 4), "-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 10), "-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 100), "-100"));
            // 数组变体 [原值,递减4,递减10,递减100]
            ArrayNode arrayVariant1 = JsonNodeFactory.instance.arrayNode();
            arrayVariant1.add(id);
            arrayVariant1.add(id - 4);
            arrayVariant1.add(id - 10);
            arrayVariant1.add(id - 100);
            variants.add(new JsonPayloadVariant(arrayVariant1, "to[-4-10-100]"));

            // 路径遍历变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)), "/../-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)), "/../-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)), "/../-100"));

        } else if (originalValue.isLong()) {
            // 处理64位长整数
            long id = originalValue.asLong();

            // 空数组和null
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
            // 长整型的递减变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 4), "-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 10), "-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 100), "-100"));
            // 数组变体
            ArrayNode arrayVariant2 = JsonNodeFactory.instance.arrayNode();
            arrayVariant2.add(id);
            arrayVariant2.add(id - 4);
            arrayVariant2.add(id - 10);
            arrayVariant2.add(id - 100);
            variants.add(new JsonPayloadVariant(arrayVariant2, "to[-4-10-100]"));

            // 路径遍历变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)), "/../-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)), "/../-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)), "/../-100"));

        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);

                // 空数组和null
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
                // 字符串型但是数值递减的变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 4)), "\"-4\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 10)), "\"-10\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 100)), "\"-100\""));
                // 字符串数组变体
                ArrayNode arrayVariant3 = JsonNodeFactory.instance.arrayNode();
                arrayVariant3.add(idStr);
                arrayVariant3.add(String.valueOf(id - 4));
                arrayVariant3.add(String.valueOf(id - 10));
                arrayVariant3.add(String.valueOf(id - 100));
                variants.add(new JsonPayloadVariant(arrayVariant3, "to[\"-4\"\"-10\"\"-100\"]"));

                // 路径遍历变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 4)), "\"/../-4\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 10)), "\"/../-10\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 100)), "\"/../-100\""));
            } catch (NumberFormatException e) {
                // 如果解析失败，只添加基本变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
            }

        } else if (originalValue.isArray()) {
            // 数组情况
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));

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
                    variants.add(new JsonPayloadVariant(arrayVariant, "to[-4-10-100]"));
                } else if (firstItem.isLong()) {
                    long id = firstItem.asLong();
                    ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                    arrayVariant.add(id);
                    arrayVariant.add(id - 4);
                    arrayVariant.add(id - 10);
                    arrayVariant.add(id - 100);
                    variants.add(new JsonPayloadVariant(arrayVariant, "to[-4-10-100]"));
                } else if (firstItem.isTextual() && isNumericId(firstItem.asText())) {
                    String idStr = firstItem.asText();
                    try {
                        long id = Long.parseLong(idStr);
                        ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                        arrayVariant.add(idStr);
                        arrayVariant.add(String.valueOf(id - 4));
                        arrayVariant.add(String.valueOf(id - 10));
                        arrayVariant.add(String.valueOf(id - 100));
                        variants.add(new JsonPayloadVariant(arrayVariant, "to[\"-4\"\"-10\"\"-100\"]"));
                    } catch (NumberFormatException e) {
                        // 如果解析失败，跳过数组变体生成
                    }
                }
            }
        }

        return variants;
    }

    /**
     * 提取参数名称（从路径中提取最后一段，去掉数组索引）
     * @param fieldPath 字段路径
     * @return 参数名称
     */
    private String extractParamNameFromPath(String fieldPath) {
        // 取字段路径的最后一段
        String[] pathParts = fieldPath.split("\\.");
        String lastFieldName = pathParts[pathParts.length - 1];

        // 处理数组索引的情况 (如 "field[0]")
        if (lastFieldName.contains("[") && lastFieldName.contains("]")) {
            lastFieldName = lastFieldName.substring(0, lastFieldName.indexOf("["));
        }

        return lastFieldName;
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
     * @param expression 变体修改的参数表达式
     * @param payloadAlias payload别名
     * @param currentParamName 当前测试参数名称
     */
    private void sendModifiedRequest(HttpRequest modifiedRequest, int messageId, String host, String expression, String payloadAlias, String currentParamName) {
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

            // 保存修改后的请求和响应，传递新的参数
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "JSON",             // 固定设置为"json"
                    expression,
                    payloadAlias,        // 新增：payload别名
                    currentParamName,    // 新增：当前测试参数名称
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

                if (fieldValue.isTextual() && isTargetEmail(fieldValue.asText())) {
                    emailFields.put(fieldPath, fieldValue);
                } else if (fieldValue.isArray()) {
                    // 检查数组是否直接包含目标email
                    for (JsonNode arrayItem : fieldValue) {
                        if (arrayItem.isTextual() && isTargetEmail(arrayItem.asText())) {
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

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;


                // 检查是否为ID参数
                boolean isIdParam = isIdParameter(fieldName);

                if (isIdParam) {

                    boolean isValidId = false;
                    if (fieldValue.isInt()) {
                        isValidId = true;
                    } else if (fieldValue.isLong()) {
                        isValidId = true;
                    } else if (fieldValue.isTextual() && isNumericId(fieldValue.asText())) {
                        isValidId = true;
                    } else if (fieldValue.isArray() && containsNumericIds(fieldValue)) {
                        isValidId = true;
                    }

                    if (isValidId) {
                        idFields.put(fieldPath, fieldValue);
                    }
                }

                // 不管是否是ID字段，都要继续递归处理嵌套结构
                if (fieldValue.isArray()) {
                    // 检查数组第一个元素是否为对象，如果是，递归查找其中的ID字段
                    if (fieldValue.size() > 0) {
                        JsonNode firstElement = fieldValue.get(0);
                        if (firstElement.isObject()) {
                            String arrayFirstPath = fieldPath + "[0]";
                            findIdFieldsRecursive(firstElement, arrayFirstPath, idFields);
                        }
                    }
                } else if (fieldValue.isObject()) {
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
     * 设置字段值 - 支持数组索引路径
     * @param node 根节点
     * @param path 字段路径 (支持 "field[0].subfield" 格式)
     * @param value 新值
     */
    private void setFieldValue(ObjectNode node, String path, JsonNode value) {

        String[] pathParts = path.split("\\.");

        JsonNode current = node;

        for (int i = 0; i < pathParts.length - 1; i++) {
            String part = pathParts[i];

            // 检查是否包含数组索引
            if (part.contains("[") && part.contains("]")) {
                String fieldName = part.substring(0, part.indexOf("["));
                String indexStr = part.substring(part.indexOf("[") + 1, part.indexOf("]"));
                int index = Integer.parseInt(indexStr);


                current = current.get(fieldName);
                if (current != null && current.isArray() && index < current.size()) {
                    current = current.get(index);
                } else {
                    return;
                }
            } else {
                current = current.get(part);
                if (current == null) {
                    return;
                }
            }
        }

        // 处理最后一个路径部分
        String lastPart = pathParts[pathParts.length - 1];

        if (current instanceof ObjectNode) {
            ((ObjectNode) current).set(lastPart, value);
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