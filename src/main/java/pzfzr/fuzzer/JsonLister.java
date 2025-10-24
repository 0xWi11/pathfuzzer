package pzfzr.fuzzer;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
import pzfzr.core.NettyManager;
import pzfzr.core.NettyHelper;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * JsonLister类 - 重构版本
 * 对HTTP请求中的参数进行替换和污染测试
 * 主要处理邮箱和ID类型的参数替换，支持路径ID fuzz
 *
 * 重构说明：
 * - 所有payload生成逻辑已移至 JsonListerPayloadGenerator 类
 * - 本类专注于请求处理主流程和与Burp API的交互
 * - 构造函数签名和所有public方法签名保持完全不变
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

    // 使用新的NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    // Payload生成器 - 新增
    private final JsonListerPayloadGenerator payloadGenerator;

    // 邮箱匹配正则表达式
    private static final Pattern EMAIL_REGEX = Pattern.compile(
            "(zycc[+-][a-zA-Z0-9]+@intigriti\\.me|zcyy[+-][a-zA-Z0-9]+@(bugcrowdninja|wearehackerone)\\.com)"
    );

    // 路径中数字ID的正则表达式
    private static final Pattern PATH_NUMERIC_PATTERN = Pattern.compile("/([0-9]+)(?=[/?#]|$)");

    /**
     * 构造函数 - 签名保持完全不变
     */
    public JsonLister(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                      RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
        this.emailPattern = EMAIL_REGEX;
        this.idPattern = Pattern.compile("(\"[^\"]*ids?\":|[^\"]*ids?=)", Pattern.CASE_INSENSITIVE);
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.nextModifiedId = nextModifiedId;

        // 获取已初始化的NettyManager实例
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        // 创建payload生成器实例 - 新增
        this.payloadGenerator = new JsonListerPayloadGenerator(this.objectMapper);

        logging.logToOutput("[JsonLister] Initialization complete, using new NettyManager client with refactored payload generator");
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
            // 检查路径中是否包含数字ID
            boolean hasPathId = hasNumericIdsInPath(originalRequest.path());

            if (hasEmail) {
                processEmailReplacements(originalRequest, messageId, host);
            }
            if (hasId) {
                processIdReplacements(originalRequest, messageId, host);
            }
            // 处理路径中的数字ID
            if (hasPathId) {
                processPathIdReplacements(originalRequest, messageId, host);
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processRequest: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 检查路径中是否有数字ID
     * @param path URL路径
     * @return 是否包含数字ID
     */
    private boolean hasNumericIdsInPath(String path) {
        return PATH_NUMERIC_PATTERN.matcher(path).find();
    }

    /**
     * 处理路径中的数字ID替换
     * @param originalRequest 原始HTTP请求
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processPathIdReplacements(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            String originalPath = originalRequest.path();
            // 查找路径中所有的数字ID - 使用payload生成器
            List<JsonListerPayloadGenerator.PathIdMatch> pathIds = payloadGenerator.extractPathIds(originalPath);

            // 对每个找到的数字ID进行fuzz
            for (JsonListerPayloadGenerator.PathIdMatch pathId : pathIds) {
                if (isShuttingDown) {
                    return;
                }
                // 生成该ID的所有变体 - 使用payload生成器
                List<JsonListerPayloadGenerator.PathIdVariant> variants =
                        payloadGenerator.generatePathIdVariants(originalPath, pathId);

                for (JsonListerPayloadGenerator.PathIdVariant variant : variants) {
                    if (isShuttingDown) {
                        return;
                    }
                    // 创建修改后的请求
                    HttpRequest modifiedRequest = originalRequest.withPath(variant.getNewPath());
                    // 发送修改后的请求
                    sendModifiedRequest(modifiedRequest, messageId, host, variant.getExpression(),
                            variant.getAlias(), pathId.getId());
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processPathIdReplacements: " + e.getMessage());
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
                if (payloadGenerator.isTargetEmail(param.value())) {
                    String targetEmail = param.value();
                    String attackerEmail = payloadGenerator.generateAttackerEmail(targetEmail);
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
                if (payloadGenerator.isTargetEmail(param.value())) {
                    String targetEmail = param.value();
                    String attackerEmail = payloadGenerator.generateAttackerEmail(targetEmail);
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
     * 处理JSON格式的邮箱替换
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
                        if (item.isTextual() && payloadGenerator.isTargetEmail(item.asText())) {
                            targetEmail = item.asText();
                            break;
                        }
                    }
                }

                if (targetEmail != null && payloadGenerator.isTargetEmail(targetEmail)) {
                    String attackerEmail = payloadGenerator.generateAttackerEmail(targetEmail);
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
                if (payloadGenerator.isIdParameter(param.name())) {
                    if (payloadGenerator.isNumericId(param.value())) {
                        String originalIdStr = param.value();
                        // 使用payload生成器生成变体
                        List<JsonListerPayloadGenerator.PayloadVariant> variants =
                                payloadGenerator.generateBodyIdPayloads(originalIdStr, param.name());

                        for (JsonListerPayloadGenerator.PayloadVariant variant : variants) {
                            if (isShuttingDown) {
                                return;
                            }
                            HttpRequest modifiedRequest;
                            if (variant.isParameterPollution()) {
                                HttpParameter newParam = HttpParameter.parameter(param.name(),
                                        variant.getSecondValue(), HttpParameterType.BODY);
                                modifiedRequest = originalRequest.withAddedParameters(newParam);
                            } else {
                                HttpParameter newParam = HttpParameter.parameter(param.name(),
                                        variant.getValue(), HttpParameterType.BODY);
                                modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            }
                            sendModifiedRequest(modifiedRequest, messageId, host,
                                    variant.getExpression(), variant.getAlias(), param.name());
                        }
                    } else {
                        // 非数字ID处理
                        processNonNumericBodyId(originalRequest, param, messageId, host);
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processBodyIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 处理非数字Body ID
     */
    private void processNonNumericBodyId(HttpRequest originalRequest, ParsedHttpParameter param,
                                         int messageId, String host) {
        String originalValue = param.value();

        HttpParameter newParamMinus1 = HttpParameter.parameter(param.name(), "-1", HttpParameterType.BODY);
        HttpRequest modifiedRequestMinus1 = originalRequest.withUpdatedParameters(newParamMinus1);
        sendModifiedRequest(modifiedRequestMinus1, messageId, host, param.name() + "=-1", "-1", param.name());

        String jsonValue = originalValue + ".json";
        HttpParameter newParamJson = HttpParameter.parameter(param.name(), jsonValue, HttpParameterType.BODY);
        HttpRequest modifiedRequestJson = originalRequest.withUpdatedParameters(newParamJson);
        sendModifiedRequest(modifiedRequestJson, messageId, host, param.name() + "=" + jsonValue, "orig.json", param.name());

        String slashValue = originalValue + "/";
        HttpParameter newParamSlash = HttpParameter.parameter(param.name(), slashValue, HttpParameterType.BODY);
        HttpRequest modifiedRequestSlash = originalRequest.withUpdatedParameters(newParamSlash);
        sendModifiedRequest(modifiedRequestSlash, messageId, host, param.name() + "=" + slashValue, "orig/", param.name());

        String upperValue = originalValue.toUpperCase();
        HttpParameter newParam1 = HttpParameter.parameter(param.name(), upperValue, HttpParameterType.BODY);
        HttpRequest modifiedRequest1 = originalRequest.withUpdatedParameters(newParam1);
        String expression1 = param.name() + "=" + upperValue;
        sendModifiedRequest(modifiedRequest1, messageId, host, expression1, "UPPER", param.name());

        List<JsonListerPayloadGenerator.PayloadVariant> spaceVars =
                payloadGenerator.generateNonNumericSpaceVariants(originalValue, param.name(), true);
        for (JsonListerPayloadGenerator.PayloadVariant spaceVar : spaceVars) {
            HttpParameter spaceParam = HttpParameter.parameter(param.name(), spaceVar.getValue(), HttpParameterType.BODY);
            HttpRequest spaceRequest = originalRequest.withUpdatedParameters(spaceParam);
            sendModifiedRequest(spaceRequest, messageId, host, spaceVar.getExpression(), spaceVar.getAlias(), param.name());
        }

        List<JsonListerPayloadGenerator.PayloadVariant> unicodeVars =
                payloadGenerator.generateNonNumericUnicodeCRLFVariants(originalValue, param.name(), false);
        for (JsonListerPayloadGenerator.PayloadVariant unicodeVar : unicodeVars) {
            HttpParameter unicodeParam = HttpParameter.parameter(param.name(), unicodeVar.getValue(), HttpParameterType.BODY);
            HttpRequest unicodeRequest = originalRequest.withUpdatedParameters(unicodeParam);
            sendModifiedRequest(unicodeRequest, messageId, host, unicodeVar.getExpression(), unicodeVar.getAlias(), param.name());
        }

        String crlfValue = originalValue + "%0D%0A";
        HttpParameter newParam2 = HttpParameter.parameter(param.name(), crlfValue, HttpParameterType.BODY);
        HttpRequest modifiedRequest2 = originalRequest.withUpdatedParameters(newParam2);
        String expression2 = param.name() + "=" + originalValue + "%0D%0A";
        sendModifiedRequest(modifiedRequest2, messageId, host, expression2, "orig%0D%0A", param.name());

        String hashValue = originalValue + "%23";
        HttpParameter newParam3 = HttpParameter.parameter(param.name(), hashValue, HttpParameterType.BODY);
        HttpRequest modifiedRequest3 = originalRequest.withUpdatedParameters(newParam3);
        String expression3 = param.name() + "=" + originalValue + "%23";
        sendModifiedRequest(modifiedRequest3, messageId, host, expression3, "orig%23", param.name());

        HttpParameter newParam4 = HttpParameter.parameter(param.name(), "[]", HttpParameterType.BODY);
        HttpRequest modifiedRequest4 = originalRequest.withUpdatedParameters(newParam4);
        String expression4 = param.name() + "=[]";
        sendModifiedRequest(modifiedRequest4, messageId, host, expression4, "[]", param.name());

        HttpParameter newParam5 = HttpParameter.parameter(param.name(), "null", HttpParameterType.BODY);
        HttpRequest modifiedRequest5 = originalRequest.withUpdatedParameters(newParam5);
        String expression5 = param.name() + "=null";
        sendModifiedRequest(modifiedRequest5, messageId, host, expression5, "null", param.name());
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
                if (payloadGenerator.isIdParameter(param.name())) {
                    if (payloadGenerator.isNumericId(param.value())) {
                        String originalIdStr = param.value();
                        // 使用payload生成器生成变体
                        List<JsonListerPayloadGenerator.PayloadVariant> variants =
                                payloadGenerator.generateQueryIdPayloads(originalIdStr, param.name());

                        for (JsonListerPayloadGenerator.PayloadVariant variant : variants) {
                            if (isShuttingDown) {
                                return;
                            }
                            HttpRequest modifiedRequest;
                            if (variant.isParameterPollution()) {
                                HttpParameter newParam = HttpParameter.parameter(param.name(),
                                        variant.getSecondValue(), HttpParameterType.URL);
                                modifiedRequest = originalRequest.withAddedParameters(newParam);
                            } else if (variant.isArrayFormat()) {
                                HttpParameter newParam = HttpParameter.parameter(param.name(),
                                        variant.getValue(), HttpParameterType.URL);
                                modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            } else {
                                HttpParameter newParam = HttpParameter.parameter(param.name(),
                                        variant.getValue(), HttpParameterType.URL);
                                modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            }
                            sendModifiedRequest(modifiedRequest, messageId, host,
                                    variant.getExpression(), variant.getAlias(), param.name());
                        }
                    } else {
                        // 非数字ID处理
                        processNonNumericQueryId(originalRequest, param, messageId, host);
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processQueryIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 处理非数字Query ID
     */
    private void processNonNumericQueryId(HttpRequest originalRequest, ParsedHttpParameter param,
                                          int messageId, String host) {
        String originalValue = param.value();

        HttpParameter newParamMinus1 = HttpParameter.parameter(param.name(), "-1", HttpParameterType.URL);
        HttpRequest modifiedRequestMinus1 = originalRequest.withUpdatedParameters(newParamMinus1);
        sendModifiedRequest(modifiedRequestMinus1, messageId, host, param.name() + "=-1", "-1", param.name());

        String jsonValue = originalValue + ".json";
        HttpParameter newParamJson = HttpParameter.parameter(param.name(), jsonValue, HttpParameterType.URL);
        HttpRequest modifiedRequestJson = originalRequest.withUpdatedParameters(newParamJson);
        sendModifiedRequest(modifiedRequestJson, messageId, host, param.name() + "=" + jsonValue, "orig.json", param.name());

        // 非数字ID - 斜杠后缀（修改expression）
        String slashValue = originalValue + "/";
        try {
            String encodedSlash = URLEncoder.encode(slashValue, StandardCharsets.UTF_8.name());
            HttpParameter newParamSlash = HttpParameter.parameter(param.name(), encodedSlash, HttpParameterType.URL);
            HttpRequest modifiedRequestSlash = originalRequest.withUpdatedParameters(newParamSlash);
            sendModifiedRequest(modifiedRequestSlash, messageId, host, param.name() + "=" + encodedSlash, "orig/", param.name());
        } catch (Exception ex) {
            logging.logToOutput("URL encoding error: " + ex.getMessage());
        }

        String upperValue = originalValue.toUpperCase();
        HttpParameter newParam1 = HttpParameter.parameter(param.name(), upperValue, HttpParameterType.URL);
        HttpRequest modifiedRequest1 = originalRequest.withUpdatedParameters(newParam1);
        String expression1 = param.name() + "=" + upperValue;
        sendModifiedRequest(modifiedRequest1, messageId, host, expression1, "UPPER", param.name());

        List<JsonListerPayloadGenerator.PayloadVariant> spaceVars =
                payloadGenerator.generateNonNumericSpaceVariants(originalValue, param.name(), true);
        for (JsonListerPayloadGenerator.PayloadVariant spaceVar : spaceVars) {
            HttpParameter spaceParam = HttpParameter.parameter(param.name(), spaceVar.getValue(), HttpParameterType.URL);
            HttpRequest spaceRequest = originalRequest.withUpdatedParameters(spaceParam);
            sendModifiedRequest(spaceRequest, messageId, host, spaceVar.getExpression(), spaceVar.getAlias(), param.name());
        }

        List<JsonListerPayloadGenerator.PayloadVariant> unicodeVars =
                payloadGenerator.generateNonNumericUnicodeCRLFVariants(originalValue, param.name(), true);
        for (JsonListerPayloadGenerator.PayloadVariant unicodeVar : unicodeVars) {
            HttpParameter unicodeParam = HttpParameter.parameter(param.name(), unicodeVar.getValue(), HttpParameterType.URL);
            HttpRequest unicodeRequest = originalRequest.withUpdatedParameters(unicodeParam);
            sendModifiedRequest(unicodeRequest, messageId, host, unicodeVar.getExpression(), unicodeVar.getAlias(), param.name());
        }

        String crlfValue = originalValue + "%0D%0A";
        HttpParameter newParam2 = HttpParameter.parameter(param.name(), crlfValue, HttpParameterType.URL);
        HttpRequest modifiedRequest2 = originalRequest.withUpdatedParameters(newParam2);
        String expression2 = param.name() + "=" + originalValue + "%0D%0A";
        sendModifiedRequest(modifiedRequest2, messageId, host, expression2, "orig%0D%0A", param.name());

        String hashValue = originalValue + "%23";
        HttpParameter newParam3 = HttpParameter.parameter(param.name(), hashValue, HttpParameterType.URL);
        HttpRequest modifiedRequest3 = originalRequest.withUpdatedParameters(newParam3);
        String expression3 = param.name() + "=" + originalValue + "%23";
        sendModifiedRequest(modifiedRequest3, messageId, host, expression3, "orig%23", param.name());

        HttpParameter newParam4 = HttpParameter.parameter(param.name(), "[]", HttpParameterType.URL);
        HttpRequest modifiedRequest4 = originalRequest.withUpdatedParameters(newParam4);
        String expression4 = param.name() + "=[]";
        sendModifiedRequest(modifiedRequest4, messageId, host, expression4, "[]", param.name());

        HttpParameter newParam5 = HttpParameter.parameter(param.name(), "null", HttpParameterType.URL);
        HttpRequest modifiedRequest5 = originalRequest.withUpdatedParameters(newParam5);
        String expression5 = param.name() + "=null";
        sendModifiedRequest(modifiedRequest5, messageId, host, expression5, "null", param.name());
    }

    /**
     * 处理JSON格式的ID替换
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

                boolean isNumeric = originalValue.isInt() || originalValue.isLong() ||
                        (originalValue.isTextual() && payloadGenerator.isNumericId(originalValue.asText()));

                if (isNumeric) {
                    // 使用payload生成器生成JSON变体
                    List<JsonListerPayloadGenerator.JsonPayloadVariant> variants =
                            payloadGenerator.generateJsonIdPayloads(originalValue);

                    for (JsonListerPayloadGenerator.JsonPayloadVariant variant : variants) {
                        if (isShuttingDown) {
                            return;
                        }
                        ObjectNode newRoot = rootNode.deepCopy();
                        setFieldValue(newRoot, fieldPath, variant.getValue());
                        String expression = generateJsonExpression(fieldPath, originalValue, variant.getValue());
                        String currentParamName = extractParamNameFromPath(fieldPath);
                        String modifiedBody = objectMapper.writeValueAsString(newRoot);
                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                        sendModifiedRequest(modifiedRequest, messageId, host, expression, variant.getAlias(), currentParamName);
                    }

                    processJsonDuplicateFieldVariants(originalRequest, fieldPath, originalValue, messageId, host);
                } else if (originalValue.isTextual()) {
                    processNonNumericJsonId(originalRequest, rootNode, fieldPath, originalValue, messageId, host);
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processJsonIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 处理非数字JSON ID
     */
    private void processNonNumericJsonId(HttpRequest originalRequest, JsonNode rootNode,
                                         String fieldPath, JsonNode originalValue,
                                         int messageId, String host) {
        try {
            String currentValue = originalValue.asText();
            String currentParamName = extractParamNameFromPath(fieldPath);

            String upperValue = currentValue.toUpperCase();
            ObjectNode newRoot1 = rootNode.deepCopy();
            setFieldValue(newRoot1, fieldPath, JsonNodeFactory.instance.textNode(upperValue));
            String expression1 = "\"" + currentParamName + "\":\"" + upperValue + "\"";
            String modifiedBody1 = objectMapper.writeValueAsString(newRoot1);
            HttpRequest modifiedRequest1 = originalRequest.withBody(modifiedBody1);
            sendModifiedRequest(modifiedRequest1, messageId, host, expression1, "\"UPPER\"", currentParamName);

            ObjectNode newRootSpace1 = rootNode.deepCopy();
            setFieldValue(newRootSpace1, fieldPath, JsonNodeFactory.instance.textNode(currentValue + " "));
            String expressionSpace1 = "\"" + currentParamName + "\":\"" + currentValue + " \"";
            String modifiedBodySpace1 = objectMapper.writeValueAsString(newRootSpace1);
            HttpRequest modifiedRequestSpace1 = originalRequest.withBody(modifiedBodySpace1);
            sendModifiedRequest(modifiedRequestSpace1, messageId, host, expressionSpace1, "\"orig \"", currentParamName);

            ObjectNode newRootSpace2 = rootNode.deepCopy();
            setFieldValue(newRootSpace2, fieldPath, JsonNodeFactory.instance.textNode(" " + currentValue));
            String expressionSpace2 = "\"" + currentParamName + "\":\" " + currentValue + "\"";
            String modifiedBodySpace2 = objectMapper.writeValueAsString(newRootSpace2);
            HttpRequest modifiedRequestSpace2 = originalRequest.withBody(modifiedBodySpace2);
            sendModifiedRequest(modifiedRequestSpace2, messageId, host, expressionSpace2, "\" orig\"", currentParamName);

            // Unicode CRLF - 非数字ID
            ObjectNode newRootUnicode = rootNode.deepCopy();
            setFieldValue(newRootUnicode, fieldPath, JsonNodeFactory.instance.textNode(currentValue + "\\u000D\\u000A"));
            String expressionUnicode = "\"" + currentParamName + "\":\"" + currentValue;
            String modifiedBodyUnicode = objectMapper.writeValueAsString(newRootUnicode);
            HttpRequest modifiedRequestUnicode = originalRequest.withBody(modifiedBodyUnicode);
            sendModifiedRequest(modifiedRequestUnicode, messageId, host, expressionUnicode, "\"orig\\\\u000D\\\\u000A\"", currentParamName);

            // CRLF - 非数字ID
            String crlfValue = currentValue + "\r\n";
            ObjectNode newRoot2 = rootNode.deepCopy();
            setFieldValue(newRoot2, fieldPath, JsonNodeFactory.instance.textNode(crlfValue));
            String expression2 = "\"" + currentParamName + "\":\"" + currentValue ;
            String modifiedBody2 = objectMapper.writeValueAsString(newRoot2);
            HttpRequest modifiedRequest2 = originalRequest.withBody(modifiedBody2);
            sendModifiedRequest(modifiedRequest2, messageId, host, expression2, "\"orig\\r\\n\"", currentParamName);

            String hashValue = currentValue + "%23";
            ObjectNode newRoot3 = rootNode.deepCopy();
            setFieldValue(newRoot3, fieldPath, JsonNodeFactory.instance.textNode(hashValue));
            String expression3 = "\"" + currentParamName + "\":\"" + currentValue + "%23\"";
            String modifiedBody3 = objectMapper.writeValueAsString(newRoot3);
            HttpRequest modifiedRequest3 = originalRequest.withBody(modifiedBody3);
            sendModifiedRequest(modifiedRequest3, messageId, host, expression3, "\"orig%23\"", currentParamName);

            ObjectNode newRoot4 = rootNode.deepCopy();
            setFieldValue(newRoot4, fieldPath, JsonNodeFactory.instance.arrayNode());
            String expression4 = "\"" + currentParamName + "\":[]";
            String modifiedBody4 = objectMapper.writeValueAsString(newRoot4);
            HttpRequest modifiedRequest4 = originalRequest.withBody(modifiedBody4);
            sendModifiedRequest(modifiedRequest4, messageId, host, expression4, "[]", currentParamName);

            ObjectNode newRoot5 = rootNode.deepCopy();
            setFieldValue(newRoot5, fieldPath, JsonNodeFactory.instance.nullNode());
            String expression5 = "\"" + currentParamName + "\":null";
            String modifiedBody5 = objectMapper.writeValueAsString(newRoot5);
            HttpRequest modifiedRequest5 = originalRequest.withBody(modifiedBody5);
            sendModifiedRequest(modifiedRequest5, messageId, host, expression5, "null", currentParamName);
        } catch (Exception e) {
            logging.logToOutput("Exception in processNonNumericJsonId: " + e.getMessage());
        }
    }

    /**
     * 生成JSON重复字段变体 - 通过直接修改JSON字符串
     * @param originalRequest 原始请求
     * @param fieldPath 字段路径
     * @param originalValue 原始值
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processJsonDuplicateFieldVariants(HttpRequest originalRequest, String fieldPath,
                                                   JsonNode originalValue, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            String originalBody = originalRequest.bodyToString();
            String fieldName = extractParamNameFromPath(fieldPath);

            if (originalValue.isInt()) {
                int id = originalValue.asInt();
                // 生成重复数字字段的变体
                List<String> duplicateVariants = generateJsonDuplicateStringVariants(originalBody, fieldName,
                        String.valueOf(id), String.valueOf(id - 4), String.valueOf(id - 10), String.valueOf(id - 100), false);
                for (int i = 0; i < duplicateVariants.size(); i++) {
                    String modifiedBody = duplicateVariants.get(i);
                    String[] aliases = {"dup-4", "dup-10", "dup-100"};
                    String alias = aliases[i];
                    HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                    String expression = generateDuplicateExpression(fieldName, String.valueOf(id), alias);
                    sendModifiedRequest(modifiedRequest, messageId, host, expression, alias, fieldName);
                }
            } else if (originalValue.isLong()) {
                long id = originalValue.asLong();
                // 生成重复数字字段的变体
                List<String> duplicateVariants = generateJsonDuplicateStringVariants(originalBody, fieldName,
                        String.valueOf(id), String.valueOf(id - 4), String.valueOf(id - 10), String.valueOf(id - 100), false);
                for (int i = 0; i < duplicateVariants.size(); i++) {
                    String modifiedBody = duplicateVariants.get(i);
                    String[] aliases = {"dup-4", "dup-10", "dup-100"};
                    String alias = aliases[i];
                    HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                    String expression = generateDuplicateExpression(fieldName, String.valueOf(id), alias);
                    sendModifiedRequest(modifiedRequest, messageId, host, expression, alias, fieldName);
                }
            } else if (originalValue.isTextual() && payloadGenerator.isNumericId(originalValue.asText())) {
                String idStr = originalValue.asText();
                try {
                    long id = Long.parseLong(idStr);
                    // 生成重复字符串字段的变体
                    List<String> duplicateVariants = generateJsonDuplicateStringVariants(originalBody, fieldName,
                            "\"" + idStr + "\"", "\"" + (id - 4) + "\"", "\"" + (id - 10) + "\"", "\"" + (id - 100) + "\"", true);
                    for (int i = 0; i < duplicateVariants.size(); i++) {
                        String modifiedBody = duplicateVariants.get(i);
                        String[] aliases = {"\"dup-4\"", "\"dup-10\"", "\"dup-100\""};
                        String alias = aliases[i];
                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                        String expression = generateDuplicateExpression(fieldName, "\"" + idStr + "\"", alias);
                        sendModifiedRequest(modifiedRequest, messageId, host, expression, alias, fieldName);
                    }
                } catch (NumberFormatException e) {
                    // 处理超长数字
                    if (payloadGenerator.isValidDigitString(idStr)) {
                        String decremented4 = payloadGenerator.decrementStringNumber(idStr, 4);
                        String decremented10 = payloadGenerator.decrementStringNumber(idStr, 10);
                        String decremented100 = payloadGenerator.decrementStringNumber(idStr, 100);
                        List<String> values = new ArrayList<>();
                        if (decremented4 != null && !decremented4.startsWith("-")) {
                            values.add("\"" + decremented4 + "\"");
                        }
                        if (decremented10 != null && !decremented10.startsWith("-")) {
                            values.add("\"" + decremented10 + "\"");
                        }
                        if (decremented100 != null && !decremented100.startsWith("-")) {
                            values.add("\"" + decremented100 + "\"");
                        }
                        if (values.size() >= 3) {
                            List<String> duplicateVariants = generateJsonDuplicateStringVariants(originalBody, fieldName,
                                    "\"" + idStr + "\"", values.get(0), values.get(1), values.get(2), true);
                            for (int i = 0; i < duplicateVariants.size(); i++) {
                                String modifiedBody = duplicateVariants.get(i);
                                String[] aliases = {"\"dup-4\"", "\"dup-10\"", "\"dup-100\""};
                                String alias = aliases[i];
                                HttpRequest modifiedRequest = originalRequest.withBody(modifiedBody);
                                String expression = generateDuplicateExpression(fieldName, "\"" + idStr + "\"", alias);
                                sendModifiedRequest(modifiedRequest, messageId, host, expression, alias, fieldName);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processJsonDuplicateFieldVariants: " + e.getMessage());
        }
    }

    /**
     * 生成JSON重复字段的字符串变体
     */
    private List<String> generateJsonDuplicateStringVariants(String originalJson, String fieldName,
                                                             String originalValue, String value4, String value10, String value100, boolean isStringValue) {
        List<String> variants = new ArrayList<>();
        try {
            // 查找字段在JSON中的位置
            String fieldPattern = "\"" + fieldName + "\"\\s*:\\s*" + Pattern.quote(originalValue);
            Pattern pattern = Pattern.compile(fieldPattern);
            Matcher matcher = pattern.matcher(originalJson);
            if (matcher.find()) {
                // 生成重复字段变体
                String duplicateField4 = ",\"" + fieldName + "\":" + value4;
                String duplicateField10 = ",\"" + fieldName + "\":" + value10;
                String duplicateField100 = ",\"" + fieldName + "\":" + value100;

                // 插入位置：在原字段匹配结束位置
                int insertPos = matcher.end();

                // 生成三个变体 - 直接插入
                variants.add(insertDuplicateField(originalJson, insertPos, duplicateField4));
                variants.add(insertDuplicateField(originalJson, insertPos, duplicateField10));
                variants.add(insertDuplicateField(originalJson, insertPos, duplicateField100));
            }
        } catch (Exception e) {
            logging.logToOutput("Error generating duplicate field variants: " + e.getMessage());
        }
        return variants;
    }

    /**
     * 在JSON字符串中插入重复字段
     */
    private String insertDuplicateField(String originalJson, int insertPos, String duplicateField) {
        StringBuilder sb = new StringBuilder(originalJson);
        sb.insert(insertPos, duplicateField);
        return sb.toString();
    }

    /**
     * 生成重复字段的expression
     */
    private String generateDuplicateExpression(String fieldName, String originalValue, String alias) {
        String duplicateValue;
        if (alias.equals("dup-4") || alias.equals("\"dup-4\"")) {
            if (originalValue.startsWith("\"") && originalValue.endsWith("\"")) {
                String numStr = originalValue.substring(1, originalValue.length() - 1);
                try {
                    long num = Long.parseLong(numStr);
                    duplicateValue = "\"" + (num - 4) + "\"";
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            } else {
                try {
                    long num = Long.parseLong(originalValue);
                    duplicateValue = String.valueOf(num - 4);
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            }
        } else if (alias.equals("dup-10") || alias.equals("\"dup-10\"")) {
            if (originalValue.startsWith("\"") && originalValue.endsWith("\"")) {
                String numStr = originalValue.substring(1, originalValue.length() - 1);
                try {
                    long num = Long.parseLong(numStr);
                    duplicateValue = "\"" + (num - 10) + "\"";
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            } else {
                try {
                    long num = Long.parseLong(originalValue);
                    duplicateValue = String.valueOf(num - 10);
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            }
        } else if (alias.equals("dup-100") || alias.equals("\"dup-100\"")) {
            if (originalValue.startsWith("\"") && originalValue.endsWith("\"")) {
                String numStr = originalValue.substring(1, originalValue.length() - 1);
                try {
                    long num = Long.parseLong(numStr);
                    duplicateValue = "\"" + (num - 100) + "\"";
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            } else {
                try {
                    long num = Long.parseLong(originalValue);
                    duplicateValue = String.valueOf(num - 100);
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            }
        } else {
            duplicateValue = originalValue;
        }
        return "\"" + fieldName + "\":" + duplicateValue;
    }

    /**
     * 提取参数名称（从路径中提取最后一段，去掉数组索引）
     */
    private String extractParamNameFromPath(String fieldPath) {
        String[] pathParts = fieldPath.split("\\.");
        String lastFieldName = pathParts[pathParts.length - 1];
        if (lastFieldName.contains("[") && lastFieldName.contains("]")) {
            lastFieldName = lastFieldName.substring(0, lastFieldName.indexOf("["));
        }
        return lastFieldName;
    }

    /**
     * 生成 JSON 变体的 expression 字符串
     */
    private String generateJsonExpression(String fieldPath, JsonNode originalValue, JsonNode variant) {
        String[] pathParts = fieldPath.split("\\.");
        String lastFieldName = pathParts[pathParts.length - 1];
        if (lastFieldName.contains("[") && lastFieldName.contains("]")) {
            lastFieldName = lastFieldName.substring(0, lastFieldName.indexOf("["));
        }

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
     */
    private void sendModifiedRequest(HttpRequest modifiedRequest, int messageId, String host,
                                     String expression, String payloadAlias, String currentParamName) {
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
            rateLimiter.acquire(modifiedRequest.url().split("\\?")[0] + modifiedRequest.method());

            // 生成请求ID
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);

            // 保存修改后的请求和响应，传递新的参数
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "JSON",
                    expression,
                    payloadAlias,
                    currentParamName,
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            nettyManager.sendRequest(modifiedRequest, new NettyManager.ResponseCallback() {
                @Override
                public void onResponse(HttpResponse response, long responseTimeMs) {
                    try {
                        HttpResponse processedResponse = nettyHelper.processResponse(response);
                        requestResponseSaver.handleNettyResponse(processedResponse, tempID, responseTimeMs, modifiedPair);
                    } catch (Exception e) {
                        logging.logToError("[JsonLister] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[JsonLister] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    // =============== 辅助方法 - 保留不变 ===============

    /**
     * 查找JSON中的邮箱字段
     */
    private Map<String, JsonNode> findEmailFields(JsonNode node) {
        Map<String, JsonNode> emailFields = new HashMap<>();
        findEmailFieldsRecursive(node, "", emailFields);
        return emailFields;
    }

    /**
     * 递归查找邮箱字段
     */
    private void findEmailFieldsRecursive(JsonNode node, String currentPath, Map<String, JsonNode> emailFields) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                if (fieldValue.isTextual() && payloadGenerator.isTargetEmail(fieldValue.asText())) {
                    emailFields.put(fieldPath, fieldValue);
                } else if (fieldValue.isArray()) {
                    for (JsonNode arrayItem : fieldValue) {
                        if (arrayItem.isTextual() && payloadGenerator.isTargetEmail(arrayItem.asText())) {
                            emailFields.put(fieldPath, fieldValue);
                            break;
                        }
                    }
                }

                if (fieldValue.isArray()) {
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
     */
    private Map<String, JsonNode> findIdFields(JsonNode node) {
        Map<String, JsonNode> idFields = new HashMap<>();
        findIdFieldsRecursive(node, "", idFields);
        return idFields;
    }

    /**
     * 递归查找ID字段
     */
    private void findIdFieldsRecursive(JsonNode node, String currentPath, Map<String, JsonNode> idFields) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                boolean isIdParam = payloadGenerator.isIdParameter(fieldName);
                if (isIdParam) {
                    boolean isValidId = false;
                    if (fieldValue.isInt()) {
                        isValidId = true;
                    } else if (fieldValue.isLong()) {
                        isValidId = true;
                    } else if (fieldValue.isTextual()) {
                        isValidId = true;
                    } else if (fieldValue.isArray() && payloadGenerator.containsNumericIds(fieldValue)) {
                        isValidId = true;
                    }
                    if (isValidId) {
                        idFields.put(fieldPath, fieldValue);
                    }
                }

                if (fieldValue.isArray()) {
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
     * 设置字段值 - 支持数组索引路径
     */
    private void setFieldValue(ObjectNode node, String path, JsonNode value) {
        String[] pathParts = path.split("\\.");
        JsonNode current = node;
        for (int i = 0; i < pathParts.length - 1; i++) {
            String part = pathParts[i];
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

        String lastPart = pathParts[pathParts.length - 1];
        if (current instanceof ObjectNode) {
            ((ObjectNode) current).set(lastPart, value);
        }
    }

    /**
     * 设置停止状态
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
        if (shuttingDown) {
            logging.logToOutput("[JsonLister] Starting shutdown...");
            logging.logToOutput("[JsonLister] Shutdown complete");
        }
    }
}