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
 * JsonLister类 - 使用新NettyManager的版本
 * 对HTTP请求中的参数进行替换和污染测试
 * 主要处理邮箱和ID类型的参数替换，现在支持路径ID fuzz
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

    // Hash 生成相关常量
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int HASH_LENGTH = 5;
    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);

    // 邮箱匹配正则表达式
    private static final Pattern EMAIL_REGEX = Pattern.compile(
            "(zycc[+-][a-zA-Z0-9]+@intigriti\\.me|zcyy[+-][a-zA-Z0-9]+@(bugcrowdninja|wearehackerone)\\.com)"
    );
    private static final Pattern ID_REGEX = Pattern.compile("(\"[^\"]*ids?\":|[?&][^=&]*ids?=)", Pattern.CASE_INSENSITIVE);

    // 路径中数字ID的正则表达式
    private static final Pattern PATH_NUMERIC_PATTERN = Pattern.compile("/([0-9]+)(?=[/?#]|$)");

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

        // 获取已初始化的NettyManager实例
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[JsonLister] Initialization complete, using new NettyManager client");
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
     * 路径ID变体类 - 用于路径中的ID fuzz
     */
    private static class PathIdVariant {
        private final String newPath;
        private final String expression;
        private final String alias;

        public PathIdVariant(String newPath, String expression, String alias) {
            this.newPath = newPath;
            this.expression = expression;
            this.alias = alias;
        }

        public String getNewPath() { return newPath; }
        public String getExpression() { return expression; }
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
            // 检查路径中是否包含数字ID
            boolean hasPathId = hasNumericIdsInPath(originalRequest.path());

            if (hasEmail) {
                processEmailReplacements(originalRequest, messageId, host);
            }
            if (hasId) {
                processIdReplacements(originalRequest, messageId, host);
            }
            // 新增：处理路径中的数字ID
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

            // 查找路径中所有的数字ID
            List<PathIdMatch> pathIds = extractPathIds(originalPath);

            // 对每个找到的数字ID进行fuzz
            for (PathIdMatch pathId : pathIds) {
                if (isShuttingDown) {
                    return;
                }

                // 生成该ID的所有变体
                List<PathIdVariant> variants = generatePathIdVariants(originalPath, pathId);

                for (PathIdVariant variant : variants) {
                    if (isShuttingDown) {
                        return;
                    }

                    // 创建修改后的请求
                    HttpRequest modifiedRequest = originalRequest.withPath(variant.getNewPath());

                    // 发送修改后的请求
                    sendModifiedRequest(modifiedRequest, messageId, host, variant.getExpression(), variant.getAlias(), pathId.getId());
                }
            }

        } catch (Exception e) {
            logging.logToOutput("Exception in processPathIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 路径ID匹配类
     */
    private static class PathIdMatch {
        private final String id;
        private final int startIndex;
        private final int endIndex;

        public PathIdMatch(String id, int startIndex, int endIndex) {
            this.id = id;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public String getId() { return id; }
        public int getStartIndex() { return startIndex; }
        public int getEndIndex() { return endIndex; }
    }

    /**
     * 从路径中提取所有数字ID
     * @param path URL路径
     * @return 路径ID匹配列表
     */
    private List<PathIdMatch> extractPathIds(String path) {
        List<PathIdMatch> pathIds = new ArrayList<>();
        Matcher matcher = PATH_NUMERIC_PATTERN.matcher(path);
        while (matcher.find()) {
            String id = matcher.group(1);
            int startIndex = matcher.start(1);
            int endIndex = matcher.end(1);
            pathIds.add(new PathIdMatch(id, startIndex, endIndex));
        }
        return pathIds;
    }

    /**
     * 生成路径ID的变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @return 路径ID变体列表
     */
    private List<PathIdVariant> generatePathIdVariants(String originalPath, PathIdMatch pathId) {
        List<PathIdVariant> variants = new ArrayList<>();
        String idStr = pathId.getId();

        variants.add(createPathVariant(originalPath, pathId, "-1", "-1"));
        variants.addAll(generatePathIdJsonSuffixVariants(originalPath, pathId, idStr));

        if (idStr.length() > 18 || isUltraLongNumber(idStr)) {
            variants.addAll(generateStringBasedVariants(originalPath, pathId, idStr));
        } else {
            try {
                long originalId = Long.parseLong(idStr);

                if (originalId > 4) {
                    variants.add(createPathVariant(originalPath, pathId, String.valueOf(originalId - 4), "-4"));
                }
                if (originalId > 10) {
                    variants.add(createPathVariant(originalPath, pathId, String.valueOf(originalId - 10), "-10"));
                }
                if (originalId > 100) {
                    variants.add(createPathVariant(originalPath, pathId, String.valueOf(originalId - 100), "-100"));
                }

                // 新增：前缀零变体
                variants.addAll(generatePathIdZeroPrefixVariants(originalPath, pathId, idStr));

                // 新增：后缀"a"变体
                variants.addAll(generatePathIdSuffixAVariants(originalPath, pathId, idStr));

                // 新增：小数点变体
                variants.addAll(generatePathIdDecimalVariants(originalPath, pathId, idStr));

                // 新增：多个9变体
                variants.addAll(generatePathIdNinesVariants(originalPath, pathId));

                // 修改：空格变体在路径中使用+编码，添加原始ID的变体
                // 新增：原始ID的空格变体
                variants.add(createPathVariant(originalPath, pathId, originalId + "+", originalId + "+"));
                variants.add(createPathVariant(originalPath, pathId, "+" + originalId, "+" + originalId));

                if (originalId > 4) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "+", (originalId - 4) + "+"));
                    variants.add(createPathVariant(originalPath, pathId, "+" + (originalId - 4), "+" + (originalId - 4)));
                }
                if (originalId > 10) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "+", (originalId - 10) + "+"));
                    variants.add(createPathVariant(originalPath, pathId, "+" + (originalId - 10), "+" + (originalId - 10)));
                }
                if (originalId > 100) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "+", (originalId - 100) + "+"));
                    variants.add(createPathVariant(originalPath, pathId, "+" + (originalId - 100), "+" + (originalId - 100)));
                }

                // 新增：原始ID的Unicode CRLF变体
                variants.add(createPathVariant(originalPath, pathId, originalId + "%5cu000D%5cu000A", originalId + "%5cu000D%5cu000A"));

                if (originalId > 4) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "%5cu000D%5cu000A", (originalId - 4) + "%5cu000D%5cu000A"));
                }
                if (originalId > 10) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "%5cu000D%5cu000A", (originalId - 10) + "%5cu000D%5cu000A"));
                }
                if (originalId > 100) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "%5cu000D%5cu000A", (originalId - 100) + "%5cu000D%5cu000A"));
                }

                variants.addAll(generatePathIdSlashSuffixVariants(originalPath, pathId, idStr));
                variants.addAll(generatePathIdCommaVariants(originalPath, pathId, idStr));
                variants.add(createPathVariantWithQuery(originalPath, pathId, idStr, "/?size=88", "/?size=88"));
                variants.addAll(generatePathIdHashVariants(originalPath, pathId, idStr));

                if (originalId > 4) {
                    variants.add(createPathVariant(originalPath, pathId, originalId + "/../" + (originalId - 4), "/../-4"));
                }
                if (originalId > 10) {
                    variants.add(createPathVariant(originalPath, pathId, originalId + "/../" + (originalId - 10), "/../-10"));
                }
                if (originalId > 100) {
                    variants.add(createPathVariant(originalPath, pathId, originalId + "/../" + (originalId - 100), "/../-100"));
                }

            } catch (NumberFormatException e) {
                // 对于非数字或超范围数字，使用字符串处理
                variants.addAll(generateStringBasedVariants(originalPath, pathId, idStr));
                // 非数字情况下也添加多个9变体
                variants.addAll(generatePathIdNinesVariants(originalPath, pathId));
            }
        }

        variants.add(createPathVariant(originalPath, pathId, "[]", "[]"));
        variants.add(createPathVariant(originalPath, pathId, "null", "null"));
        return variants;
    }

    private List<PathIdVariant> generatePathIdJsonSuffixVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            variants.add(createPathVariant(originalPath, pathId, originalId + ".json", originalId + ".json"));
            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + ".json", (originalId - 4) + ".json"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + ".json", (originalId - 10) + ".json"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + ".json", (originalId - 100) + ".json"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                variants.add(createPathVariant(originalPath, pathId, idStr + ".json", idStr + ".json"));
                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec4 + ".json", dec4 + ".json"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec10 + ".json", dec10 + ".json"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec100 + ".json", dec100 + ".json"));
                }
            }
        }
        return variants;
    }

    private List<PathIdVariant> generatePathIdSlashSuffixVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);

            // 新增：原始ID的斜杠后缀
            variants.add(createPathVariant(originalPath, pathId, originalId + "/", originalId + "/"));

            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "/", (originalId - 4) + "/"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "/", (originalId - 10) + "/"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "/", (originalId - 100) + "/"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                // 新增：原始ID的斜杠后缀
                variants.add(createPathVariant(originalPath, pathId, idStr + "/", idStr + "/"));

                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec4 + "/", dec4 + "/"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec10 + "/", dec10 + "/"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec100 + "/", dec100 + "/"));
                }
            }
        }
        return variants;
    }

    private List<PathIdVariant> generatePathIdCommaVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            if (originalId > 4) {
                String commaValue = originalId + "," + (originalId - 4);
                variants.add(createPathVariant(originalPath, pathId, commaValue, commaValue));
            }
            if (originalId > 10) {
                String commaValue = originalId + "," + (originalId - 10);
                variants.add(createPathVariant(originalPath, pathId, commaValue, commaValue));
            }
            if (originalId > 100) {
                String commaValue = originalId + "," + (originalId - 100);
                variants.add(createPathVariant(originalPath, pathId, commaValue, commaValue));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, idStr + "," + dec4, idStr + "," + dec4));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, idStr + "," + dec10, idStr + "," + dec10));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, idStr + "," + dec100, idStr + "," + dec100));
                }
            }
        }
        return variants;
    }

    private List<PathIdVariant> generatePathIdHashVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);

            // 新增：原始ID的%23后缀
            variants.add(createPathVariant(originalPath, pathId, originalId + "%23", originalId + "%23"));

            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "%23", (originalId - 4) + "%23"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "%23", (originalId - 10) + "%23"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "%23", (originalId - 100) + "%23"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                // 新增：原始ID的%23后缀
                variants.add(createPathVariant(originalPath, pathId, idStr + "%23", idStr + "%23"));

                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec4 + "%23", dec4 + "%23"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec10 + "%23", dec10 + "%23"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec100 + "%23", dec100 + "%23"));
                }
            }
        }
        return variants;
    }

    private PathIdVariant createPathVariantWithQuery(String originalPath, PathIdMatch pathId, String idValue, String querySuffix, String alias) {
        String newPath = originalPath.substring(0, pathId.getEndIndex()) + querySuffix + originalPath.substring(pathId.getEndIndex());
        String expression = idValue + querySuffix;
        return new PathIdVariant(newPath, expression, alias);
    }

    private List<PayloadVariant> generateSpaceVariants(String originalIdStr, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);

            // 新增：原始ID的空格变体
            if (isQuery) {
                variants.add(new PayloadVariant(originalId + "+", paramName + "=" + originalId + "+", originalId + "+", false, false, null));
                variants.add(new PayloadVariant("+" + originalId, paramName + "=+" + originalId, "+" + originalId, false, false, null));
            } else {
                variants.add(new PayloadVariant(originalId + " ", paramName + "=" + originalId + " ", originalId + " ", false, false, null));
                variants.add(new PayloadVariant(" " + originalId, paramName + "= " + originalId, " " + originalId, false, false, null));
            }

            if (isQuery) {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "+", paramName + "=" + (originalId - 4) + "+", (originalId - 4) + "+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 4), paramName + "=+" + (originalId - 4), "+" + (originalId - 4), false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "+", paramName + "=" + (originalId - 10) + "+", (originalId - 10) + "+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 10), paramName + "=+" + (originalId - 10), "+" + (originalId - 10), false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "+", paramName + "=" + (originalId - 100) + "+", (originalId - 100) + "+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 100), paramName + "=+" + (originalId - 100), "+" + (originalId - 100), false, false, null));
                }
            } else {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + " ", paramName + "=" + (originalId - 4) + " ", (originalId - 4) + " ", false, false, null));
                    variants.add(new PayloadVariant(" " + (originalId - 4), paramName + "= " + (originalId - 4), " " + (originalId - 4), false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + " ", paramName + "=" + (originalId - 10) + " ", (originalId - 10) + " ", false, false, null));
                    variants.add(new PayloadVariant(" " + (originalId - 10), paramName + "= " + (originalId - 10), " " + (originalId - 10), false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + " ", paramName + "=" + (originalId - 100) + " ", (originalId - 100) + " ", false, false, null));
                    variants.add(new PayloadVariant(" " + (originalId - 100), paramName + "= " + (originalId - 100), " " + (originalId - 100), false, false, null));
                }
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                // 新增：原始ID的空格变体
                if (isQuery) {
                    variants.add(new PayloadVariant(originalIdStr + "+", paramName + "=" + originalIdStr + "+", originalIdStr + "+", false, false, null));
                    variants.add(new PayloadVariant("+" + originalIdStr, paramName + "=+" + originalIdStr, "+" + originalIdStr, false, false, null));
                } else {
                    variants.add(new PayloadVariant(originalIdStr + " ", paramName + "=" + originalIdStr + " ", originalIdStr + " ", false, false, null));
                    variants.add(new PayloadVariant(" " + originalIdStr, paramName + "= " + originalIdStr, " " + originalIdStr, false, false, null));
                }

                String dec4 = decrementStringNumber(originalIdStr, 4);
                String dec10 = decrementStringNumber(originalIdStr, 10);
                String dec100 = decrementStringNumber(originalIdStr, 100);
                if (isQuery) {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "+", paramName + "=" + dec4 + "+", dec4 + "+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec4, paramName + "=+" + dec4, "+" + dec4, false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "+", paramName + "=" + dec10 + "+", dec10 + "+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec10, paramName + "=+" + dec10, "+" + dec10, false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "+", paramName + "=" + dec100 + "+", dec100 + "+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec100, paramName + "=+" + dec100, "+" + dec100, false, false, null));
                    }
                } else {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + " ", paramName + "=" + dec4 + " ", dec4 + " ", false, false, null));
                        variants.add(new PayloadVariant(" " + dec4, paramName + "= " + dec4, " " + dec4, false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + " ", paramName + "=" + dec10 + " ", dec10 + " ", false, false, null));
                        variants.add(new PayloadVariant(" " + dec10, paramName + "= " + dec10, " " + dec10, false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + " ", paramName + "=" + dec100 + " ", dec100 + " ", false, false, null));
                        variants.add(new PayloadVariant(" " + dec100, paramName + "= " + dec100, " " + dec100, false, false, null));
                    }
                }
            }
        }
        return variants;
    }

    private List<PayloadVariant> generateNonNumericSpaceVariants(String originalValue, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        if (isQuery) {
            variants.add(new PayloadVariant(originalValue + "+", paramName + "=" + originalValue + "+", originalValue + "+", false, false, null));
            variants.add(new PayloadVariant("+" + originalValue, paramName + "=+" + originalValue, "+" + originalValue, false, false, null));
        } else {
            variants.add(new PayloadVariant(originalValue + " ", paramName + "=" + originalValue + " ", originalValue + " ", false, false, null));
            variants.add(new PayloadVariant(" " + originalValue, paramName + "= " + originalValue, " " + originalValue, false, false, null));
        }
        return variants;
    }

    private List<PayloadVariant> generateNonNumericUnicodeCRLFVariants(String originalValue, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        if (isQuery) {
            variants.add(new PayloadVariant(originalValue + "%5cu000D%5cu000A", paramName + "=" + originalValue + "%5cu000D%5cu000A", originalValue + "%5cu000D%5cu000A", false, false, null));
        } else {
            variants.add(new PayloadVariant(originalValue + "\\u000D\\u000A", paramName + "=" + originalValue + "\\u000D\\u000A", originalValue + "\\u000D\\u000A", false, false, null));
        }
        return variants;
    }

    private List<PayloadVariant> generateUnicodeCRLFVariants(String originalIdStr, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);

            // 新增：原始ID的Unicode CRLF变体
            if (isQuery) {
                variants.add(new PayloadVariant(originalId + "%5cu000D%5cu000A", paramName + "=" + originalId + "%5cu000D%5cu000A", originalId + "%5cu000D%5cu000A", false, false, null));
            } else {
                variants.add(new PayloadVariant(originalId + "\\u000D\\u000A", paramName + "=" + originalId + "\\u000D\\u000A", originalId + "\\u000D\\u000A", false, false, null));
            }

            if (isQuery) {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "%5cu000D%5cu000A", paramName + "=" + (originalId - 4) + "%5cu000D%5cu000A", (originalId - 4) + "%5cu000D%5cu000A", false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "%5cu000D%5cu000A", paramName + "=" + (originalId - 10) + "%5cu000D%5cu000A", (originalId - 10) + "%5cu000D%5cu000A", false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "%5cu000D%5cu000A", paramName + "=" + (originalId - 100) + "%5cu000D%5cu000A", (originalId - 100) + "%5cu000D%5cu000A", false, false, null));
                }
            } else {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "\\u000D\\u000A", paramName + "=" + (originalId - 4) + "\\u000D\\u000A", (originalId - 4) + "\\u000D\\u000A", false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "\\u000D\\u000A", paramName + "=" + (originalId - 10) + "\\u000D\\u000A", (originalId - 10) + "\\u000D\\u000A", false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "\\u000D\\u000A", paramName + "=" + (originalId - 100) + "\\u000D\\u000A", (originalId - 100) + "\\u000D\\u000A", false, false, null));
                }
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                // 新增：原始ID的Unicode CRLF变体
                if (isQuery) {
                    variants.add(new PayloadVariant(originalIdStr + "%5cu000D%5cu000A", paramName + "=" + originalIdStr + "%5cu000D%5cu000A", originalIdStr + "%5cu000D%5cu000A", false, false, null));
                } else {
                    variants.add(new PayloadVariant(originalIdStr + "\\u000D\\u000A", paramName + "=" + originalIdStr + "\\u000D\\u000A", originalIdStr + "\\u000D\\u000A", false, false, null));
                }

                String dec4 = decrementStringNumber(originalIdStr, 4);
                String dec10 = decrementStringNumber(originalIdStr, 10);
                String dec100 = decrementStringNumber(originalIdStr, 100);
                if (isQuery) {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "%5cu000D%5cu000A", paramName + "=" + dec4 + "%5cu000D%5cu000A", dec4 + "%5cu000D%5cu000A", false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "%5cu000D%5cu000A", paramName + "=" + dec10 + "%5cu000D%5cu000A", dec10 + "%5cu000D%5cu000A", false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "%5cu000D%5cu000A", paramName + "=" + dec100 + "%5cu000D%5cu000A", dec100 + "%5cu000D%5cu000A", false, false, null));
                    }
                } else {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "\\u000D\\u000A", paramName + "=" + dec4 + "\\u000D\\u000A", dec4 + "\\u000D\\u000A", false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "\\u000D\\u000A", paramName + "=" + dec10 + "\\u000D\\u000A", dec10 + "\\u000D\\u000A", false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "\\u000D\\u000A", paramName + "=" + dec100 + "\\u000D\\u000A", dec100 + "\\u000D\\u000A", false, false, null));
                    }
                }
            }
        }
        return variants;
    }

    private List<PayloadVariant> generateJsonSuffixVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            variants.add(new PayloadVariant(originalId + ".json", paramName + "=" + originalId + ".json", originalId + ".json", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + ".json", paramName + "=" + (originalId - 4) + ".json", (originalId - 4) + ".json", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + ".json", paramName + "=" + (originalId - 10) + ".json", (originalId - 10) + ".json", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + ".json", paramName + "=" + (originalId - 100) + ".json", (originalId - 100) + ".json", false, false, null));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                variants.add(new PayloadVariant(originalIdStr + ".json", paramName + "=" + originalIdStr + ".json", originalIdStr + ".json", false, false, null));
                String dec4 = decrementStringNumber(originalIdStr, 4);
                String dec10 = decrementStringNumber(originalIdStr, 10);
                String dec100 = decrementStringNumber(originalIdStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(new PayloadVariant(dec4 + ".json", paramName + "=" + dec4 + ".json", dec4 + ".json", false, false, null));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(new PayloadVariant(dec10 + ".json", paramName + "=" + dec10 + ".json", dec10 + ".json", false, false, null));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(new PayloadVariant(dec100 + ".json", paramName + "=" + dec100 + ".json", dec100 + ".json", false, false, null));
                }
            }
        }
        return variants;
    }

    private List<PayloadVariant> generateZeroPrefixVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            String originalWithZeros = String.format("000%s", originalIdStr);
            String minus4WithZeros = String.format("000%d", originalId - 4);
            String minus10WithZeros = String.format("000%d", originalId - 10);
            String minus100WithZeros = String.format("000%d", originalId - 100);

            variants.add(new PayloadVariant(originalWithZeros, paramName + "=" + originalWithZeros, "000orig", false, false, null));
            variants.add(new PayloadVariant(minus4WithZeros, paramName + "=" + minus4WithZeros, "000-4", false, false, null));
            variants.add(new PayloadVariant(minus10WithZeros, paramName + "=" + minus10WithZeros, "000-10", false, false, null));
            variants.add(new PayloadVariant(minus100WithZeros, paramName + "=" + minus100WithZeros, "000-100", false, false, null));
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                String originalWithZeros = "000" + originalIdStr;
                String decremented4 = decrementStringNumber(originalIdStr, 4);
                String decremented10 = decrementStringNumber(originalIdStr, 10);
                String decremented100 = decrementStringNumber(originalIdStr, 100);

                variants.add(new PayloadVariant(originalWithZeros, paramName + "=" + originalWithZeros, "000orig", false, false, null));
                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant("000" + decremented4, paramName + "=" + "000" + decremented4, "000-4", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant("000" + decremented10, paramName + "=" + "000" + decremented10, "000-10", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant("000" + decremented100, paramName + "=" + "000" + decremented100, "000-100", false, false, null));
                }
            }
        }
        return variants;
    }

    /**
     * 生成后缀"a"的变体
     * @param originalIdStr 原始ID字符串
     * @param paramName 参数名
     * @param isBody 是否为Body参数
     * @return 后缀"a"变体列表
     */
    private List<PayloadVariant> generateSuffixAVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(originalIdStr);

            // 新增：原始ID的后缀"a"变体
            String originalWithA = originalId + "a";
            variants.add(new PayloadVariant(originalWithA, paramName + "=" + originalWithA, "origa", false, false, null));

            // 生成后缀"a"变体
            String minus4WithA = (originalId - 4) + "a";
            String minus10WithA = (originalId - 10) + "a";
            String minus100WithA = (originalId - 100) + "a";

            variants.add(new PayloadVariant(minus4WithA, paramName + "=" + minus4WithA, "-4a", false, false, null));
            variants.add(new PayloadVariant(minus10WithA, paramName + "=" + minus10WithA, "-10a", false, false, null));
            variants.add(new PayloadVariant(minus100WithA, paramName + "=" + minus100WithA, "-100a", false, false, null));
        } catch (NumberFormatException e) {
            // 对于超长数字，使用字符串处理
            if (isValidDigitString(originalIdStr)) {
                // 新增：原始ID的后缀"a"变体
                variants.add(new PayloadVariant(originalIdStr + "a", paramName + "=" + originalIdStr + "a", "origa", false, false, null));

                String decremented4 = decrementStringNumber(originalIdStr, 4);
                String decremented10 = decrementStringNumber(originalIdStr, 10);
                String decremented100 = decrementStringNumber(originalIdStr, 100);

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented4 + "a", paramName + "=" + decremented4 + "a", "-4a", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented10 + "a", paramName + "=" + decremented10 + "a", "-10a", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented100 + "a", paramName + "=" + decremented100 + "a", "-100a", false, false, null));
                }
            }
        }
        return variants;
    }
    /**
     * 生成小数点变体
     * @param originalIdStr 原始ID字符串
     * @param paramName 参数名
     * @param isBody 是否为Body参数
     * @return 小数点变体列表
     */
    private List<PayloadVariant> generateDecimalVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(originalIdStr);

            // 新增：原始ID-1的小数点变体
            String minus1Decimal = (originalId - 1) + ".99999";
            variants.add(new PayloadVariant(minus1Decimal, paramName + "=" + minus1Decimal, "-1.99999", false, false, null));

            // 生成小数点变体 (-5, -11, -101)
            String minus5Decimal = (originalId - 5) + ".99999";
            String minus11Decimal = (originalId - 11) + ".99999";
            String minus101Decimal = (originalId - 101) + ".99999";

            variants.add(new PayloadVariant(minus5Decimal, paramName + "=" + minus5Decimal, "-5.99999", false, false, null));
            variants.add(new PayloadVariant(minus11Decimal, paramName + "=" + minus11Decimal, "-11.99999", false, false, null));
            variants.add(new PayloadVariant(minus101Decimal, paramName + "=" + minus101Decimal, "-101.99999", false, false, null));
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                // 新增：原始ID-1的小数点变体
                String decremented1 = decrementStringNumber(originalIdStr, 1);
                if (decremented1 != null && !decremented1.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented1 + ".99999", paramName + "=" + decremented1 + ".99999", "-1.99999", false, false, null));
                }

                String decremented5 = decrementStringNumber(originalIdStr, 5);
                String decremented11 = decrementStringNumber(originalIdStr, 11);
                String decremented101 = decrementStringNumber(originalIdStr, 101);

                if (decremented5 != null && !decremented5.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented5 + ".99999", paramName + "=" + decremented5 + ".99999", "-5.99999", false, false, null));
                }
                if (decremented11 != null && !decremented11.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented11 + ".99999", paramName + "=" + decremented11 + ".99999", "-11.99999", false, false, null));
                }
                if (decremented101 != null && !decremented101.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented101 + ".99999", paramName + "=" + decremented101 + ".99999", "-101.99999", false, false, null));
                }
            }
        }
        return variants;
    }

    /**
     * 生成多个9的变体
     * @param paramName 参数名
     * @param isBody 是否为Body参数
     * @return 多个9变体列表
     */
    private List<PayloadVariant> generateNinesVariant(String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        String ninesValue = "999999999999999999999";
        variants.add(new PayloadVariant(ninesValue, paramName + "=" + ninesValue, "999s", false, false, null));
        return variants;
    }

    /**
     * 生成JSON前缀零变体
     * @param originalValue 原始值
     * @return JSON前缀零变体列表
     */
    private List<JsonPayloadVariant> generateJsonZeroPrefixVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            int id = originalValue.asInt();
            // 修改：先格式化字符串，再转为int，确保前导零被解析为数字
            String origStr = String.format("%06d", id);  // 使用6位确保有前导零
            String m4Str = String.format("%06d", id - 4);
            String m10Str = String.format("%06d", id - 10);
            String m100Str = String.format("%06d", id - 100);
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Integer.parseInt(String.format("000%d", id))), "000orig"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Integer.parseInt(String.format("000%d", id - 4))), "000-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Integer.parseInt(String.format("000%d", id - 10))), "000-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Integer.parseInt(String.format("000%d", id - 100))), "000-100"));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Long.parseLong(String.format("000%d", id))), "000orig"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Long.parseLong(String.format("000%d", id - 4))), "000-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Long.parseLong(String.format("000%d", id - 10))), "000-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(Long.parseLong(String.format("000%d", id - 100))), "000-100"));
        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);

                // 前缀零变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%s", idStr)), "\"000orig\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%d", id - 4)), "\"000-4\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%d", id - 10)), "\"000-10\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%d", id - 100)), "\"000-100\""));

            } catch (NumberFormatException e) {
                // 处理超长数字
                if (isValidDigitString(idStr)) {
                    String decremented4 = decrementStringNumber(idStr, 4);
                    String decremented10 = decrementStringNumber(idStr, 10);
                    String decremented100 = decrementStringNumber(idStr, 100);

                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("000" + idStr), "\"000orig\""));
                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("000" + decremented4), "\"000-4\""));
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("000" + decremented10), "\"000-10\""));
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("000" + decremented100), "\"000-100\""));
                    }
                }
            }
        }

        return variants;
    }

    /**
     * 生成JSON后缀"a"变体
     * @param originalValue 原始值
     * @return JSON后缀"a"变体列表
     */
    private List<JsonPayloadVariant> generateJsonSuffixAVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            int id = originalValue.asInt();

            // 新增：原始ID的后缀"a"变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "a"), "\"origa\""));

            // 数字型转字符串型的后缀"a"变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "a"), "\"-4a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "a"), "\"-10a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "a"), "\"-100a\""));

        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();

            // 新增：原始ID的后缀"a"变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "a"), "\"origa\""));

            // 数字型转字符串型的后缀"a"变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "a"), "\"-4a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "a"), "\"-10a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "a"), "\"-100a\""));

        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);

                // 新增：原始ID的后缀"a"变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "a"), "\"origa\""));

                // 字符串型的后缀"a"变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "a"), "\"-4a\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "a"), "\"-10a\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "a"), "\"-100a\""));

            } catch (NumberFormatException e) {
                // 处理超长数字
                if (isValidDigitString(idStr)) {
                    // 新增：原始ID的后缀"a"变体
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "a"), "\"origa\""));

                    String decremented4 = decrementStringNumber(idStr, 4);
                    String decremented10 = decrementStringNumber(idStr, 10);
                    String decremented100 = decrementStringNumber(idStr, 100);

                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "a"), "\"-4a\""));
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "a"), "\"-10a\""));
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "a"), "\"-100a\""));
                    }
                }
            }
        }

        return variants;
    }

    /**
     * 生成JSON小数点变体
     * @param originalValue 原始值
     * @return JSON小数点变体列表
     */
    private List<JsonPayloadVariant> generateJsonDecimalVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            int id = originalValue.asInt();

            // 新增：原始ID-1的小数点变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 1) + 0.99999), "-1.99999"));

            // 数字型小数点变体 (-5, -11, -101) - 只生成数字型，不生成字符串型
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 5) + 0.99999), "-5.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 11) + 0.99999), "-11.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 101) + 0.99999), "-101.99999"));

        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();

            // 新增：原始ID-1的小数点变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 1) + 0.99999), "-1.99999"));

            // 数字型小数点变体 (-5, -11, -101) - 只生成数字型，不生成字符串型
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 5) + 0.99999), "-5.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 11) + 0.99999), "-11.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 101) + 0.99999), "-101.99999"));

        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);

                // 新增：原始ID-1的小数点变体
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 1) + ".99999"), "\"-1.99999\""));

                // 字符串型小数点变体 (-5, -11, -101)
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 5) + ".99999"), "\"-5.99999\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 11) + ".99999"), "\"-11.99999\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 101) + ".99999"), "\"-101.99999\""));

            } catch (NumberFormatException e) {
                // 处理超长数字
                if (isValidDigitString(idStr)) {
                    // 新增：原始ID-1的小数点变体
                    String decremented1 = decrementStringNumber(idStr, 1);
                    if (decremented1 != null && !decremented1.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented1 + ".99999"), "\"-1.99999\""));
                    }

                    String decremented5 = decrementStringNumber(idStr, 5);
                    String decremented11 = decrementStringNumber(idStr, 11);
                    String decremented101 = decrementStringNumber(idStr, 101);

                    if (decremented5 != null && !decremented5.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented5 + ".99999"), "\"-5.99999\""));
                    }
                    if (decremented11 != null && !decremented11.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented11 + ".99999"), "\"-11.99999\""));
                    }
                    if (decremented101 != null && !decremented101.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented101 + ".99999"), "\"-101.99999\""));
                    }
                }
            }
        }
        return variants;
    }

    private List<JsonPayloadVariant> generateJsonSpaceVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();

            // 新增：原始ID的空格变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + " "), "\"" + id + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + id), "\" " + id + "\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + " "), "\"" + (id - 4) + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + " "), "\"" + (id - 10) + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + " "), "\"" + (id - 100) + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 4)), "\" " + (id - 4) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 10)), "\" " + (id - 10) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 100)), "\" " + (id - 100) + "\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();

            // 新增：原始ID的空格变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + " "), "\"" + id + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + id), "\" " + id + "\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + " "), "\"" + (id - 4) + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + " "), "\"" + (id - 10) + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + " "), "\"" + (id - 100) + " \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 4)), "\" " + (id - 4) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 10)), "\" " + (id - 10) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 100)), "\" " + (id - 100) + "\""));
        } else if (originalValue.isTextual()) {
            String idStr = originalValue.asText();
            if (isNumericId(idStr)) {
                try {
                    long id = Long.parseLong(idStr);

                    // 新增：原始ID的空格变体
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + " "), "\"" + idStr + " \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + idStr), "\" " + idStr + "\""));

                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + " "), "\"" + (id - 4) + " \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + " "), "\"" + (id - 10) + " \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + " "), "\"" + (id - 100) + " \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 4)), "\" " + (id - 4) + "\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 10)), "\" " + (id - 10) + "\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 100)), "\" " + (id - 100) + "\""));
                } catch (NumberFormatException e) {
                }
            } else {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + " "), "\"" + idStr + " \""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + idStr), "\" " + idStr + "\""));
            }
        }
        return variants;
    }

    private List<JsonPayloadVariant> generateJsonUnicodeCRLFVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();

            // 新增：原始ID的Unicode CRLF变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "\\u000D\\u000A"), "\"" + id + "\\\\u000D\\\\u000A\""));

            // 修复：expression使用字面字符串 \\u000D\\u000A
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\\u000D\\u000A"), "\"" + (id - 4) + "\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\\u000D\\u000A"), "\"" + (id - 10) + "\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\\u000D\\u000A"), "\"" + (id - 100) + "\\\\u000D\\\\u000A\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();

            // 新增：原始ID的Unicode CRLF变体
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "\\u000D\\u000A"), "\"" + id + "\\\\u000D\\\\u000A\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\\u000D\\u000A"), "\"" + (id - 4) + "\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\\u000D\\u000A"), "\"" + (id - 10) + "\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\\u000D\\u000A"), "\"" + (id - 100) + "\\\\u000D\\\\u000A\""));
        } else if (originalValue.isTextual()) {
            String idStr = originalValue.asText();
            if (isNumericId(idStr)) {
                try {
                    long id = Long.parseLong(idStr);

                    // 新增：原始ID的Unicode CRLF变体
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "\\u000D\\u000A"), "\"" + idStr + "\\\\u000D\\\\u000A\""));

                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\\u000D\\u000A"), "\"" + (id - 4) + "\\\\u000D\\\\u000A\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\\u000D\\u000A"), "\"" + (id - 10) + "\\\\u000D\\\\u000A\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\\u000D\\u000A"), "\"" + (id - 100) + "\\\\u000D\\\\u000A\""));
                } catch (NumberFormatException e) {
                }
            } else {
                // 非数字ID
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "\\u000D\\u000A"), "\"" + idStr + "\\\\u000D\\\\u000A\""));
            }
        }
        return variants;
    }

    private List<JsonPayloadVariant> generateJsonJsonSuffixVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + ".json"), "\"" + id + ".json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + ".json"), "\"" + (id - 4) + ".json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + ".json"), "\"" + (id - 10) + ".json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + ".json"), "\"" + (id - 100) + ".json\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + ".json"), "\"" + id + ".json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + ".json"), "\"" + (id - 4) + ".json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + ".json"), "\"" + (id - 10) + ".json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + ".json"), "\"" + (id - 100) + ".json\""));
        } else if (originalValue.isTextual()) {
            String idStr = originalValue.asText();
            if (isNumericId(idStr)) {
                try {
                    long id = Long.parseLong(idStr);
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + ".json"), "\"" + idStr + ".json\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + ".json"), "\"" + (id - 4) + ".json\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + ".json"), "\"" + (id - 10) + ".json\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + ".json"), "\"" + (id - 100) + ".json\""));
                } catch (NumberFormatException e) {
                    if (isValidDigitString(idStr)) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + ".json"), "\"" + idStr + ".json\""));
                        String dec4 = decrementStringNumber(idStr, 4);
                        String dec10 = decrementStringNumber(idStr, 10);
                        String dec100 = decrementStringNumber(idStr, 100);
                        if (dec4 != null && !dec4.startsWith("-")) {
                            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(dec4 + ".json"), "\"" + dec4 + ".json\""));
                        }
                        if (dec10 != null && !dec10.startsWith("-")) {
                            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(dec10 + ".json"), "\"" + dec10 + ".json\""));
                        }
                        if (dec100 != null && !dec100.startsWith("-")) {
                            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(dec100 + ".json"), "\"" + dec100 + ".json\""));
                        }
                    }
                }
            } else {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + ".json"), "\"" + idStr + ".json\""));
            }
        }
        return variants;
    }

    /**
     * 生成JSON多个9变体
     * @param originalValue 原始值
     * @return JSON多个9变体列表
     */
    private List<JsonPayloadVariant> generateJsonNinesVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt() || originalValue.isLong()) {
            try {
                java.math.BigInteger bigInt = new java.math.BigInteger("999999999999999999999");
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(new java.math.BigDecimal(bigInt)), "999s"));
            } catch (Exception e) {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("999999999999999999999"), "\"999s\""));
            }
        } else if (originalValue.isTextual()) {
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("999999999999999999999"), "\"999s\""));
        }

        return variants;
    }

    /**
     * 生成路径ID的前缀零变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @param idStr ID字符串
     * @return 路径ID前缀零变体列表
     */
    private List<PathIdVariant> generatePathIdZeroPrefixVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(idStr);

            // 生成前缀零变体
            String originalWithZeros = String.format("000%s", idStr);
            String minus4WithZeros = String.format("000%d", originalId - 4);
            String minus10WithZeros = String.format("000%d", originalId - 10);
            String minus100WithZeros = String.format("000%d", originalId - 100);

            // 创建路径变体
            variants.add(createPathVariant(originalPath, pathId, originalWithZeros, "000orig"));

            // 只在递减结果为正数时添加
            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, minus4WithZeros, "000-4"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, minus10WithZeros, "000-10"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, minus100WithZeros, "000-100"));
            }

        } catch (NumberFormatException e) {
            // 处理超长数字
            if (isValidDigitString(idStr)) {
                String originalWithZeros = "000" + idStr;
                String decremented4 = decrementStringNumber(idStr, 4);
                String decremented10 = decrementStringNumber(idStr, 10);
                String decremented100 = decrementStringNumber(idStr, 100);

                variants.add(createPathVariant(originalPath, pathId, originalWithZeros, "000orig"));

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, "000" + decremented4, "000-4"));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, "000" + decremented10, "000-10"));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, "000" + decremented100, "000-100"));
                }
            }
        }

        return variants;
    }

    /**
     * 生成路径ID的后缀"a"变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @param idStr ID字符串
     * @return 路径ID后缀"a"变体列表
     */
    private List<PathIdVariant> generatePathIdSuffixAVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(idStr);

            // 新增：原始ID的后缀"a"变体
            String originalWithA = originalId + "a";
            variants.add(createPathVariant(originalPath, pathId, originalWithA, "origa"));

            // 生成后缀"a"变体
            String minus4WithA = (originalId - 4) + "a";
            String minus10WithA = (originalId - 10) + "a";
            String minus100WithA = (originalId - 100) + "a";

            // 只在递减结果为正数时添加
            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, minus4WithA, "-4a"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, minus10WithA, "-10a"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, minus100WithA, "-100a"));
            }

        } catch (NumberFormatException e) {
            // 处理超长数字
            if (isValidDigitString(idStr)) {
                // 新增：原始ID的后缀"a"变体
                variants.add(createPathVariant(originalPath, pathId, idStr + "a", "origa"));

                String decremented4 = decrementStringNumber(idStr, 4);
                String decremented10 = decrementStringNumber(idStr, 10);
                String decremented100 = decrementStringNumber(idStr, 100);

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented4 + "a", "-4a"));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented10 + "a", "-10a"));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented100 + "a", "-100a"));
                }
            }
        }

        return variants;
    }

    /**
     * 生成路径ID的小数点变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @param idStr ID字符串
     * @return 路径ID小数点变体列表
     */
    private List<PathIdVariant> generatePathIdDecimalVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(idStr);

            // 新增：原始ID-1的小数点变体
            if (originalId > 1) {
                String minus1Decimal = (originalId - 1) + ".99999";
                variants.add(createPathVariant(originalPath, pathId, minus1Decimal, "-1.99999"));
            }

            // 生成小数点变体 (-5, -11, -101)
            String minus5Decimal = (originalId - 5) + ".99999";
            String minus11Decimal = (originalId - 11) + ".99999";
            String minus101Decimal = (originalId - 101) + ".99999";

            // 只在递减结果为正数时添加
            if (originalId > 5) {
                variants.add(createPathVariant(originalPath, pathId, minus5Decimal, "-5.99999"));
            }
            if (originalId > 11) {
                variants.add(createPathVariant(originalPath, pathId, minus11Decimal, "-11.99999"));
            }
            if (originalId > 101) {
                variants.add(createPathVariant(originalPath, pathId, minus101Decimal, "-101.99999"));
            }

        } catch (NumberFormatException e) {
            // 处理超长数字
            if (isValidDigitString(idStr)) {
                // 新增：原始ID-1的小数点变体
                String decremented1 = decrementStringNumber(idStr, 1);
                if (decremented1 != null && !decremented1.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented1 + ".99999", "-1.99999"));
                }

                String decremented5 = decrementStringNumber(idStr, 5);
                String decremented11 = decrementStringNumber(idStr, 11);
                String decremented101 = decrementStringNumber(idStr, 101);

                if (decremented5 != null && !decremented5.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented5 + ".99999", "-5.99999"));
                }
                if (decremented11 != null && !decremented11.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented11 + ".99999", "-11.99999"));
                }
                if (decremented101 != null && !decremented101.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented101 + ".99999", "-101.99999"));
                }
            }
        }

        return variants;
    }

    /**
     * 生成路径ID的多个9变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @return 路径ID多个9变体列表
     */
    private List<PathIdVariant> generatePathIdNinesVariants(String originalPath, PathIdMatch pathId) {
        List<PathIdVariant> variants = new ArrayList<>();

        String ninesValue = "999999999999999999999";
        variants.add(createPathVariant(originalPath, pathId, ninesValue, "999s"));

        return variants;
    }

    /**
     * 检查是否为超长数字（可能超出Long范围）
     * @param idStr ID字符串
     * @return 是否为超长数字
     */
    private boolean isUltraLongNumber(String idStr) {
        // 检查长度是否可能超出Long.MAX_VALUE
        if (idStr.length() > 19) {
            return true;
        }
        if (idStr.length() == 19) {
            // 对于19位数字，需要比较是否超过Long.MAX_VALUE (9223372036854775807)
            return idStr.compareTo("9223372036854775807") > 0;
        }
        return false;
    }

    /**
     * 为超长数字或特殊情况生成基于字符串的变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @param idStr ID字符串
     * @return 路径ID变体列表
     */
    private List<PathIdVariant> generateStringBasedVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();

        try {
            // 尝试使用大数运算进行递减
            if (idStr.length() >= 1 && idStr.matches("\\d+")) {
                // 使用字符串运算处理超长数字的递减
                String decremented4 = decrementStringNumber(idStr, 4);
                String decremented10 = decrementStringNumber(idStr, 10);
                String decremented100 = decrementStringNumber(idStr, 100);

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented4, "-4"));
                    // 路径遍历变体
                    variants.add(createPathVariant(originalPath, pathId, idStr + "/../" + decremented4, "/../-4"));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented10, "-10"));
                    // 路径遍历变体
                    variants.add(createPathVariant(originalPath, pathId, idStr + "/../" + decremented10, "/../-10"));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented100, "-100"));
                    // 路径遍历变体
                    variants.add(createPathVariant(originalPath, pathId, idStr + "/../" + decremented100, "/../-100"));
                }

                // 对于超长数字，还可以尝试修改最后几位
                if (idStr.length() >= 3) {
                    // 修改最后一位为0
                    String lastDigitZero = idStr.substring(0, idStr.length() - 1) + "0";
                    variants.add(createPathVariant(originalPath, pathId, lastDigitZero, "last→0"));

                    // 修改最后一位递减1
                    String lastDigit = idStr.substring(idStr.length() - 1);
                    if (!lastDigit.equals("0")) {
                        int digit = Integer.parseInt(lastDigit);
                        String lastDigitDec = idStr.substring(0, idStr.length() - 1) + (digit - 1);
                        variants.add(createPathVariant(originalPath, pathId, lastDigitDec, "last-1"));
                    }
                }

                // 对于超长数字，尝试截断
                if (idStr.length() > 10) {
                    String truncated = idStr.substring(0, 10);
                    variants.add(createPathVariant(originalPath, pathId, truncated, "trunc10"));
                }
            }
        } catch (Exception e) {
            // 如果字符串处理也失败，记录但不影响其他变体生成
            logging.logToOutput("Warning: Failed to generate string-based variants for ID: " + idStr);
        }

        return variants;
    }

    /**
     * 字符串数字递减运算
     * @param numberStr 数字字符串
     * @param decrement 递减值
     * @return 递减后的结果，如果结果为负数则返回null
     */
    private String decrementStringNumber(String numberStr, int decrement) {
        try {
            // 使用BigInteger处理超长数字
            java.math.BigInteger bigInt = new java.math.BigInteger(numberStr);
            java.math.BigInteger result = bigInt.subtract(java.math.BigInteger.valueOf(decrement));

            // 如果结果为负数，返回null
            if (result.compareTo(java.math.BigInteger.ZERO) < 0) {
                return null;
            }

            return result.toString();
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * 创建路径变体
     * @param originalPath 原始路径
     * @param pathId 路径ID匹配
     * @param newValue 新值
     * @param alias 别名
     * @return 路径ID变体
     */
    private PathIdVariant createPathVariant(String originalPath, PathIdMatch pathId, String newValue, String alias) {
        String newPath = originalPath.substring(0, pathId.getStartIndex()) + newValue + originalPath.substring(pathId.getEndIndex());
        String expression = newValue;

        return new PathIdVariant(newPath, expression, alias);
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
                if (isIdParameter(param.name())) {
                    if (isNumericId(param.value())) {
                        String originalIdStr = param.value();
                        List<PayloadVariant> variants = generateBodyIdPayloadVariants(originalIdStr, param.name());

                        for (PayloadVariant variant : variants) {
                            if (isShuttingDown) {
                                return;
                            }
                            HttpRequest modifiedRequest;
                            if (variant.isParameterPollution()) {
                                HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getSecondValue(), HttpParameterType.BODY);
                                modifiedRequest = originalRequest.withAddedParameters(newParam);
                            } else {
                                HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getValue(), HttpParameterType.BODY);
                                modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            }
                            sendModifiedRequest(modifiedRequest, messageId, host, variant.getExpression(), variant.getAlias(), param.name());
                        }
                    } else {
                        String originalValue = param.value();
                        HttpParameter newParamMinus1 = HttpParameter.parameter(param.name(), "-1", HttpParameterType.BODY);
                        HttpRequest modifiedRequestMinus1 = originalRequest.withUpdatedParameters(newParamMinus1);
                        sendModifiedRequest(modifiedRequestMinus1, messageId, host, param.name() + "=-1", "-1", param.name());

                        String jsonValue = originalValue + ".json";
                        HttpParameter newParamJson = HttpParameter.parameter(param.name(), jsonValue, HttpParameterType.BODY);
                        HttpRequest modifiedRequestJson = originalRequest.withUpdatedParameters(newParamJson);
                        sendModifiedRequest(modifiedRequestJson, messageId, host, param.name() + "=" + jsonValue, originalValue + ".json", param.name());

                        String slashValue = originalValue + "/";
                        HttpParameter newParamSlash = HttpParameter.parameter(param.name(), slashValue, HttpParameterType.BODY);
                        HttpRequest modifiedRequestSlash = originalRequest.withUpdatedParameters(newParamSlash);
                        sendModifiedRequest(modifiedRequestSlash, messageId, host, param.name() + "=" + slashValue, originalValue + "/", param.name());

                        String upperValue = originalValue.toUpperCase();
                        HttpParameter newParam1 = HttpParameter.parameter(param.name(), upperValue, HttpParameterType.BODY);
                        HttpRequest modifiedRequest1 = originalRequest.withUpdatedParameters(newParam1);
                        String expression1 = param.name() + "=" + upperValue;
                        sendModifiedRequest(modifiedRequest1, messageId, host, expression1, "UPPER", param.name());

                        List<PayloadVariant> spaceVars = generateNonNumericSpaceVariants(originalValue, param.name(), true);
                        for (PayloadVariant spaceVar : spaceVars) {
                            HttpParameter spaceParam = HttpParameter.parameter(param.name(), spaceVar.getValue(), HttpParameterType.BODY);
                            HttpRequest spaceRequest = originalRequest.withUpdatedParameters(spaceParam);
                            sendModifiedRequest(spaceRequest, messageId, host, spaceVar.getExpression(), spaceVar.getAlias(), param.name());
                        }

                        List<PayloadVariant> unicodeVars = generateNonNumericUnicodeCRLFVariants(originalValue, param.name(), true);
                        for (PayloadVariant unicodeVar : unicodeVars) {
                            HttpParameter unicodeParam = HttpParameter.parameter(param.name(), unicodeVar.getValue(), HttpParameterType.BODY);
                            HttpRequest unicodeRequest = originalRequest.withUpdatedParameters(unicodeParam);
                            sendModifiedRequest(unicodeRequest, messageId, host, unicodeVar.getExpression(), unicodeVar.getAlias(), param.name());
                        }

                        String crlfValue = originalValue + "%0D%0A";
                        HttpParameter newParam2 = HttpParameter.parameter(param.name(), crlfValue, HttpParameterType.BODY);
                        HttpRequest modifiedRequest2 = originalRequest.withUpdatedParameters(newParam2);
                        String expression2 = param.name() + "=" + originalValue + "%0D%0A";
                        sendModifiedRequest(modifiedRequest2, messageId, host, expression2, originalValue + "%0D%0A", param.name());

                        String hashValue = originalValue + "%23";
                        HttpParameter newParam3 = HttpParameter.parameter(param.name(), hashValue, HttpParameterType.BODY);
                        HttpRequest modifiedRequest3 = originalRequest.withUpdatedParameters(newParam3);
                        String expression3 = param.name() + "=" + originalValue + "%23";
                        sendModifiedRequest(modifiedRequest3, messageId, host, expression3, originalValue + "%23", param.name());

                        HttpParameter newParam4 = HttpParameter.parameter(param.name(), "[]", HttpParameterType.BODY);
                        HttpRequest modifiedRequest4 = originalRequest.withUpdatedParameters(newParam4);
                        String expression4 = param.name() + "=[]";
                        sendModifiedRequest(modifiedRequest4, messageId, host, expression4, "[]", param.name());

                        HttpParameter newParam5 = HttpParameter.parameter(param.name(), "null", HttpParameterType.BODY);
                        HttpRequest modifiedRequest5 = originalRequest.withUpdatedParameters(newParam5);
                        String expression5 = param.name() + "=null";
                        sendModifiedRequest(modifiedRequest5, messageId, host, expression5, "null", param.name());
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processBodyIdReplacements: " + e.getMessage());
            e.printStackTrace();
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
                if (isIdParameter(param.name())) {
                    if (isNumericId(param.value())) {
                        String originalIdStr = param.value();
                        List<PayloadVariant> variants = generateQueryIdPayloadVariants(originalIdStr, param.name());

                        for (PayloadVariant variant : variants) {
                            if (isShuttingDown) {
                                return;
                            }
                            HttpRequest modifiedRequest;
                            if (variant.isParameterPollution()) {
                                HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getSecondValue(), HttpParameterType.URL);
                                modifiedRequest = originalRequest.withAddedParameters(newParam);
                            } else if (variant.isArrayFormat()) {
                                HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getValue(), HttpParameterType.URL);
                                modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            } else {
                                HttpParameter newParam = HttpParameter.parameter(param.name(), variant.getValue(), HttpParameterType.URL);
                                modifiedRequest = originalRequest.withUpdatedParameters(newParam);
                            }
                            sendModifiedRequest(modifiedRequest, messageId, host, variant.getExpression(), variant.getAlias(), param.name());
                        }
                    } else {
                        String originalValue = param.value();
                        HttpParameter newParamMinus1 = HttpParameter.parameter(param.name(), "-1", HttpParameterType.URL);
                        HttpRequest modifiedRequestMinus1 = originalRequest.withUpdatedParameters(newParamMinus1);
                        sendModifiedRequest(modifiedRequestMinus1, messageId, host, param.name() + "=-1", "-1", param.name());

                        String jsonValue = originalValue + ".json";
                        HttpParameter newParamJson = HttpParameter.parameter(param.name(), jsonValue, HttpParameterType.URL);
                        HttpRequest modifiedRequestJson = originalRequest.withUpdatedParameters(newParamJson);
                        sendModifiedRequest(modifiedRequestJson, messageId, host, param.name() + "=" + jsonValue, originalValue + ".json", param.name());

                        // 非数字ID - 斜杠后缀（修改expression）
                        String slashValue = originalValue + "/";
                        try {
                            String encodedSlash = URLEncoder.encode(slashValue, StandardCharsets.UTF_8.name());
                            HttpParameter newParamSlash = HttpParameter.parameter(param.name(), encodedSlash, HttpParameterType.URL);
                            HttpRequest modifiedRequestSlash = originalRequest.withUpdatedParameters(newParamSlash);
                            // 修改：expression也显示编码后的
                            sendModifiedRequest(modifiedRequestSlash, messageId, host, param.name() + "=" + encodedSlash, originalValue + "/", param.name());
                        } catch (Exception ex) {
                            logging.logToOutput("URL encoding error: " + ex.getMessage());
                        }

                        String upperValue = originalValue.toUpperCase();
                        HttpParameter newParam1 = HttpParameter.parameter(param.name(), upperValue, HttpParameterType.URL);
                        HttpRequest modifiedRequest1 = originalRequest.withUpdatedParameters(newParam1);
                        String expression1 = param.name() + "=" + upperValue;
                        sendModifiedRequest(modifiedRequest1, messageId, host, expression1, "UPPER", param.name());

                        List<PayloadVariant> spaceVars = generateNonNumericSpaceVariants(originalValue, param.name(), true);
                        for (PayloadVariant spaceVar : spaceVars) {
                            HttpParameter spaceParam = HttpParameter.parameter(param.name(), spaceVar.getValue(), HttpParameterType.URL);
                            HttpRequest spaceRequest = originalRequest.withUpdatedParameters(spaceParam);
                            sendModifiedRequest(spaceRequest, messageId, host, spaceVar.getExpression(), spaceVar.getAlias(), param.name());
                        }

                        List<PayloadVariant> unicodeVars = generateNonNumericUnicodeCRLFVariants(originalValue, param.name(), true);
                        for (PayloadVariant unicodeVar : unicodeVars) {
                            HttpParameter unicodeParam = HttpParameter.parameter(param.name(), unicodeVar.getValue(), HttpParameterType.URL);
                            HttpRequest unicodeRequest = originalRequest.withUpdatedParameters(unicodeParam);
                            sendModifiedRequest(unicodeRequest, messageId, host, unicodeVar.getExpression(), unicodeVar.getAlias(), param.name());
                        }

                        String crlfValue = originalValue + "%0D%0A";
                        HttpParameter newParam2 = HttpParameter.parameter(param.name(), crlfValue, HttpParameterType.URL);
                        HttpRequest modifiedRequest2 = originalRequest.withUpdatedParameters(newParam2);
                        String expression2 = param.name() + "=" + originalValue + "%0D%0A";
                        sendModifiedRequest(modifiedRequest2, messageId, host, expression2, originalValue + "%0D%0A", param.name());

                        String hashValue = originalValue + "%23";
                        HttpParameter newParam3 = HttpParameter.parameter(param.name(), hashValue, HttpParameterType.URL);
                        HttpRequest modifiedRequest3 = originalRequest.withUpdatedParameters(newParam3);
                        String expression3 = param.name() + "=" + originalValue + "%23";
                        sendModifiedRequest(modifiedRequest3, messageId, host, expression3, originalValue + "%23", param.name());

                        HttpParameter newParam4 = HttpParameter.parameter(param.name(), "[]", HttpParameterType.URL);
                        HttpRequest modifiedRequest4 = originalRequest.withUpdatedParameters(newParam4);
                        String expression4 = param.name() + "=[]";
                        sendModifiedRequest(modifiedRequest4, messageId, host, expression4, "[]", param.name());

                        HttpParameter newParam5 = HttpParameter.parameter(param.name(), "null", HttpParameterType.URL);
                        HttpRequest modifiedRequest5 = originalRequest.withUpdatedParameters(newParam5);
                        String expression5 = param.name() + "=null";
                        sendModifiedRequest(modifiedRequest5, messageId, host, expression5, "null", param.name());
                    }
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processQueryIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

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
                        (originalValue.isTextual() && isNumericId(originalValue.asText()));

                if (isNumeric) {
                    List<JsonPayloadVariant> variants = generateJsonIdPayloadVariants(originalValue);
                    for (JsonPayloadVariant variant : variants) {
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
                    sendModifiedRequest(modifiedRequestSpace1, messageId, host, expressionSpace1, "\"" + currentValue + " \"", currentParamName);

                    ObjectNode newRootSpace2 = rootNode.deepCopy();
                    setFieldValue(newRootSpace2, fieldPath, JsonNodeFactory.instance.textNode(" " + currentValue));
                    String expressionSpace2 = "\"" + currentParamName + "\":\" " + currentValue + "\"";
                    String modifiedBodySpace2 = objectMapper.writeValueAsString(newRootSpace2);
                    HttpRequest modifiedRequestSpace2 = originalRequest.withBody(modifiedBodySpace2);
                    sendModifiedRequest(modifiedRequestSpace2, messageId, host, expressionSpace2, "\" " + currentValue + "\"", currentParamName);

                    // Unicode CRLF - 非数字ID
                    ObjectNode newRootUnicode = rootNode.deepCopy();
                    setFieldValue(newRootUnicode, fieldPath, JsonNodeFactory.instance.textNode(currentValue + "\\u000D\\u000A"));
                    String expressionUnicode = "\"" + currentParamName + "\":\"" + currentValue;
                    String modifiedBodyUnicode = objectMapper.writeValueAsString(newRootUnicode);
                    HttpRequest modifiedRequestUnicode = originalRequest.withBody(modifiedBodyUnicode);
                    sendModifiedRequest(modifiedRequestUnicode, messageId, host, expressionUnicode, "\"" + currentValue + "\\\\u000D\\\\u000A\"", currentParamName);

                    // CRLF - 非数字ID
                    String crlfValue = currentValue + "\r\n";
                    ObjectNode newRoot2 = rootNode.deepCopy();
                    setFieldValue(newRoot2, fieldPath, JsonNodeFactory.instance.textNode(crlfValue));
                    String expression2 = "\"" + currentParamName + "\":\"" + currentValue ;
                    String modifiedBody2 = objectMapper.writeValueAsString(newRoot2);
                    HttpRequest modifiedRequest2 = originalRequest.withBody(modifiedBody2);
                    sendModifiedRequest(modifiedRequest2, messageId, host, expression2, "\"" + currentValue + "\\r\\n\"", currentParamName);

                    String hashValue = currentValue + "%23";
                    ObjectNode newRoot3 = rootNode.deepCopy();
                    setFieldValue(newRoot3, fieldPath, JsonNodeFactory.instance.textNode(hashValue));
                    String expression3 = "\"" + currentParamName + "\":\"" + currentValue + "%23\"";
                    String modifiedBody3 = objectMapper.writeValueAsString(newRoot3);
                    HttpRequest modifiedRequest3 = originalRequest.withBody(modifiedBody3);
                    sendModifiedRequest(modifiedRequest3, messageId, host, expression3, "\"" + currentValue + "%23\"", currentParamName);

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
                }
            }
        } catch (Exception e) {
            logging.logToOutput("Exception in processJsonIdReplacements: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private List<PayloadVariant> generateBodyIdPayloadVariants(String originalIdStr, String paramName) {
        List<PayloadVariant> variants = new ArrayList<>();

        try {
            long originalId = Long.parseLong(originalIdStr);

            variants.add(new PayloadVariant("-1", paramName + "=-1", "-1", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 4), paramName + "=" + (originalId - 4), "-4", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 10), paramName + "=" + (originalId - 10), "-10", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 100), paramName + "=" + (originalId - 100), "-100", false, false, null));

            variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, true));
            variants.addAll(generateSuffixAVariants(originalIdStr, paramName, true));
            variants.addAll(generateDecimalVariants(originalIdStr, paramName, true));
            variants.addAll(generateNinesVariant(paramName, true));
            variants.addAll(generateSpaceVariants(originalIdStr, paramName, false));
            variants.addAll(generateUnicodeCRLFVariants(originalIdStr, paramName, false));
            variants.addAll(generateJsonSuffixVariants(originalIdStr, paramName, true));

            // 新增：原始ID的斜杠后缀
            variants.add(new PayloadVariant(originalId + "/", paramName + "=" + originalId + "/", originalId + "/", false, false, null));

            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "/", paramName + "=" + (originalId - 4) + "/", (originalId - 4) + "/", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "/", paramName + "=" + (originalId - 10) + "/", (originalId - 10) + "/", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "/", paramName + "=" + (originalId - 100) + "/", (originalId - 100) + "/", false, false, null));
            }

            if (originalId > 4) {
                String commaValue = originalId + "," + (originalId - 4);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, commaValue, false, false, null));
            }
            if (originalId > 10) {
                String commaValue = originalId + "," + (originalId - 10);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, commaValue, false, false, null));
            }
            if (originalId > 100) {
                String commaValue = originalId + "," + (originalId - 100);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, commaValue, false, false, null));
            }

            // 新增：原始ID的CRLF
            variants.add(new PayloadVariant(originalId + "%0D%0A", paramName + "=" + originalId + "%0D%0A", originalId + "%0D%0A", false, false, null));

            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%0D%0A", paramName + "=" + (originalId - 4) + "%0D%0A", (originalId - 4) + "%0D%0A", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%0D%0A", paramName + "=" + (originalId - 10) + "%0D%0A", (originalId - 10) + "%0D%0A", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%0D%0A", paramName + "=" + (originalId - 100) + "%0D%0A", (originalId - 100) + "%0D%0A", false, false, null));
            }

            // 新增：原始ID的%23后缀
            variants.add(new PayloadVariant(originalId + "%23", paramName + "=" + originalId + "%23", originalId + "%23", false, false, null));

            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%23", paramName + "=" + (originalId - 4) + "%23", (originalId - 4) + "%23", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%23", paramName + "=" + (originalId - 10) + "%23", (originalId - 10) + "%23", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%23", paramName + "=" + (originalId - 100) + "%23", (originalId - 100) + "%23", false, false, null));
            }

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

            // 基本变体 - 移到最后（倒数第二和倒数第一）
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
        } catch (NumberFormatException e) {
            // 处理超长数字或非数字情况
            if (isValidDigitString(originalIdStr)) {
                variants.add(new PayloadVariant("-1", paramName + "=-1", "-1", false, false, null));

                String decremented4 = decrementStringNumber(originalIdStr, 4);
                String decremented10 = decrementStringNumber(originalIdStr, 10);
                String decremented100 = decrementStringNumber(originalIdStr, 100);

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented4, paramName + "=" + decremented4, "-4", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented10, paramName + "=" + decremented10, "-10", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented100, paramName + "=" + decremented100, "-100", false, false, null));
                }

                // 新增：前缀零变体
                variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, true));

                // 新增：后缀"a"变体
                variants.addAll(generateSuffixAVariants(originalIdStr, paramName, true));

                // 新增：小数点变体
                variants.addAll(generateDecimalVariants(originalIdStr, paramName, true));

                // 新增：多个9变体
                variants.addAll(generateNinesVariant(paramName, true));
                variants.addAll(generateJsonSuffixVariants(originalIdStr, paramName, true));

                // 新增：原始ID的斜杠后缀
                variants.add(new PayloadVariant(originalIdStr + "/", paramName + "=" + originalIdStr + "/", originalIdStr + "/", false, false, null));

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented4 + "/", paramName + "=" + decremented4 + "/", decremented4 + "/", false, false, null));
                    variants.add(new PayloadVariant(originalIdStr + "," + decremented4, paramName + "=" + originalIdStr + "," + decremented4, originalIdStr + "," + decremented4, false, false, null));
                    variants.add(new PayloadVariant(decremented4 + "%0D%0A", paramName + "=" + decremented4 + "%0D%0A", decremented4 + "%0D%0A", false, false, null));
                    variants.add(new PayloadVariant(decremented4 + "%23", paramName + "=" + decremented4 + "%23", decremented4 + "%23", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented10 + "/", paramName + "=" + decremented10 + "/", decremented10 + "/", false, false, null));
                    variants.add(new PayloadVariant(originalIdStr + "," + decremented10, paramName + "=" + originalIdStr + "," + decremented10, originalIdStr + "," + decremented10, false, false, null));
                    variants.add(new PayloadVariant(decremented10 + "%0D%0A", paramName + "=" + decremented10 + "%0D%0A", decremented10 + "%0D%0A", false, false, null));
                    variants.add(new PayloadVariant(decremented10 + "%23", paramName + "=" + decremented10 + "%23", decremented10 + "%23", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented100 + "/", paramName + "=" + decremented100 + "/", decremented100 + "/", false, false, null));
                    variants.add(new PayloadVariant(originalIdStr + "," + decremented100, paramName + "=" + originalIdStr + "," + decremented100, originalIdStr + "," + decremented100, false, false, null));
                    variants.add(new PayloadVariant(decremented100 + "%0D%0A", paramName + "=" + decremented100 + "%0D%0A", decremented100 + "%0D%0A", false, false, null));
                    variants.add(new PayloadVariant(decremented100 + "%23", paramName + "=" + decremented100 + "%23", decremented100 + "%23", false, false, null));
                }

                // 新增：原始ID的CRLF
                variants.add(new PayloadVariant(originalIdStr + "%0D%0A", paramName + "=" + originalIdStr + "%0D%0A", originalIdStr + "%0D%0A", false, false, null));

                // 新增：原始ID的%23后缀
                variants.add(new PayloadVariant(originalIdStr + "%23", paramName + "=" + originalIdStr + "%23", originalIdStr + "%23", false, false, null));

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented4, "pollute-4", true, false, decremented4));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented10, "pollute-10", true, false, decremented10));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented100, "pollute-100", true, false, decremented100));
                }

                // 数组格式变体
                StringBuilder arrayFormat = new StringBuilder("[" + originalIdStr);
                if (decremented4 != null && !decremented4.startsWith("-")) {
                    arrayFormat.append(",").append(decremented4);
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    arrayFormat.append(",").append(decremented10);
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    arrayFormat.append(",").append(decremented100);
                }
                arrayFormat.append("]");
                variants.add(new PayloadVariant(arrayFormat.toString(), paramName + "=" + arrayFormat, "to[-4-10-100]", false, true, null));

                // 路径遍历变体
                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr + "/../" + decremented4, paramName + "=" + originalIdStr + "/../" + decremented4, "/../-4", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr + "/../" + decremented10, paramName + "=" + originalIdStr + "/../" + decremented10, "/../-10", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr + "/../" + decremented100, paramName + "=" + originalIdStr + "/../" + decremented100, "/../-100", false, false, null));
                }
            }

            // 基本变体 - 移到最后（倒数第二和倒数第一）
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
            variants.addAll(generateNinesVariant(paramName, true));
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

            variants.add(new PayloadVariant("-1", paramName + "=-1", "-1", false, false, null));
            variants.addAll(generateJsonSuffixVariants(originalIdStr, paramName, false));

            variants.add(new PayloadVariant(String.valueOf(originalId - 4), paramName + "=" + (originalId - 4), "-4", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 10), paramName + "=" + (originalId - 10), "-10", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 100), paramName + "=" + (originalId - 100), "-100", false, false, null));

            // 新增：前缀零变体
            variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, false));

            // 新增：后缀"a"变体
            variants.addAll(generateSuffixAVariants(originalIdStr, paramName, false));

            // 新增：小数点变体
            variants.addAll(generateDecimalVariants(originalIdStr, paramName, false));

            // 新增：多个9变体
            variants.addAll(generateNinesVariant(paramName, false));
            variants.addAll(generateSpaceVariants(originalIdStr, paramName, true));
            variants.addAll(generateUnicodeCRLFVariants(originalIdStr, paramName, true));

            // 新增：原始ID的斜杠后缀（URL编码）
            String encodedOrigSlash = URLEncoder.encode(originalId + "/", StandardCharsets.UTF_8.name());
            variants.add(new PayloadVariant(encodedOrigSlash, paramName + "=" + encodedOrigSlash, originalId + "/", false, false, null));

            if (originalId > 4) {
                String encodedValue = URLEncoder.encode((originalId - 4) + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedValue, paramName + "=" + encodedValue, (originalId - 4) + "/", false, false, null));
            }
            if (originalId > 10) {
                String encodedValue = URLEncoder.encode((originalId - 10) + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedValue, paramName + "=" + encodedValue, (originalId - 10) + "/", false, false, null));
            }
            if (originalId > 100) {
                String encodedValue = URLEncoder.encode((originalId - 100) + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedValue, paramName + "=" + encodedValue, (originalId - 100) + "/", false, false, null));
            }

            if (originalId > 4) {
                String commaValue = originalId + "," + (originalId - 4);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, commaValue, false, false, null));
            }
            if (originalId > 10) {
                String commaValue = originalId + "," + (originalId - 10);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, commaValue, false, false, null));
            }
            if (originalId > 100) {
                String commaValue = originalId + "," + (originalId - 100);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, commaValue, false, false, null));
            }

            // 新增：原始ID的CRLF
            variants.add(new PayloadVariant(originalId + "%0D%0A", paramName + "=" + originalId + "%0D%0A", originalId + "%0D%0A", false, false, null));

            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%0D%0A", paramName + "=" + (originalId - 4) + "%0D%0A", (originalId - 4) + "%0D%0A", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%0D%0A", paramName + "=" + (originalId - 10) + "%0D%0A", (originalId - 10) + "%0D%0A", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%0D%0A", paramName + "=" + (originalId - 100) + "%0D%0A", (originalId - 100) + "%0D%0A", false, false, null));
            }

            // 新增：原始ID的%23后缀
            variants.add(new PayloadVariant(originalId + "%23", paramName + "=" + originalId + "%23", originalId + "%23", false, false, null));

            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%23", paramName + "=" + (originalId - 4) + "%23", (originalId - 4) + "%23", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%23", paramName + "=" + (originalId - 10) + "%23", (originalId - 10) + "%23", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%23", paramName + "=" + (originalId - 100) + "%23", (originalId - 100) + "%23", false, false, null));
            }

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

            // 基本变体 - 移到最后（倒数第二和倒数第一）
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
        } catch (NumberFormatException e) {
            // 处理超长数字或非数字情况
            if (isValidDigitString(originalIdStr)) {
                // 使用BigInteger处理超长数字
                String decremented4 = decrementStringNumber(originalIdStr, 4);
                String decremented10 = decrementStringNumber(originalIdStr, 10);
                String decremented100 = decrementStringNumber(originalIdStr, 100);

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented4, paramName + "=" + decremented4, "-4", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented10, paramName + "=" + decremented10, "-10", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(decremented100, paramName + "=" + decremented100, "-100", false, false, null));
                }

                // 新增：前缀零变体
                variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, false));

                // 新增：后缀"a"变体
                variants.addAll(generateSuffixAVariants(originalIdStr, paramName, false));

                // 新增：小数点变体
                variants.addAll(generateDecimalVariants(originalIdStr, paramName, false));

                // 新增：多个9变体
                variants.addAll(generateNinesVariant(paramName, false));

                try {
                    // 新增：原始ID的斜杠后缀
                    String encodedOrigSlash = URLEncoder.encode(originalIdStr + "/", StandardCharsets.UTF_8.name());
                    variants.add(new PayloadVariant(encodedOrigSlash, paramName + "=" + originalIdStr + "/", originalIdStr + "/", false, false, null));

                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        String encodedSlash = URLEncoder.encode(decremented4 + "/", StandardCharsets.UTF_8.name());
                        variants.add(new PayloadVariant(encodedSlash, paramName + "=" + decremented4 + "/", decremented4 + "/", false, false, null));
                        variants.add(new PayloadVariant(originalIdStr + "," + decremented4, paramName + "=" + originalIdStr + "," + decremented4, originalIdStr + "," + decremented4, false, false, null));
                        variants.add(new PayloadVariant(decremented4 + "%0D%0A", paramName + "=" + decremented4 + "%0D%0A", decremented4 + "%0D%0A", false, false, null));
                        variants.add(new PayloadVariant(decremented4 + "%23", paramName + "=" + decremented4 + "%23", decremented4 + "%23", false, false, null));
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        String encodedSlash = URLEncoder.encode(decremented10 + "/", StandardCharsets.UTF_8.name());
                        variants.add(new PayloadVariant(encodedSlash, paramName + "=" + decremented10 + "/", decremented10 + "/", false, false, null));
                        variants.add(new PayloadVariant(originalIdStr + "," + decremented10, paramName + "=" + originalIdStr + "," + decremented10, originalIdStr + "," + decremented10, false, false, null));
                        variants.add(new PayloadVariant(decremented10 + "%0D%0A", paramName + "=" + decremented10 + "%0D%0A", decremented10 + "%0D%0A", false, false, null));
                        variants.add(new PayloadVariant(decremented10 + "%23", paramName + "=" + decremented10 + "%23", decremented10 + "%23", false, false, null));
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        String encodedSlash = URLEncoder.encode(decremented100 + "/", StandardCharsets.UTF_8.name());
                        variants.add(new PayloadVariant(encodedSlash, paramName + "=" + decremented100 + "/", decremented100 + "/", false, false, null));
                        variants.add(new PayloadVariant(originalIdStr + "," + decremented100, paramName + "=" + originalIdStr + "," + decremented100, originalIdStr + "," + decremented100, false, false, null));
                        variants.add(new PayloadVariant(decremented100 + "%0D%0A", paramName + "=" + decremented100 + "%0D%0A", decremented100 + "%0D%0A", false, false, null));
                        variants.add(new PayloadVariant(decremented100 + "%23", paramName + "=" + decremented100 + "%23", decremented100 + "%23", false, false, null));
                    }
                } catch (Exception ex) {
                    logging.logToOutput("URL encoding error: " + ex.getMessage());
                }

                // 新增：原始ID的CRLF
                variants.add(new PayloadVariant(originalIdStr + "%0D%0A", paramName + "=" + originalIdStr + "%0D%0A", originalIdStr + "%0D%0A", false, false, null));

                // 新增：原始ID的%23后缀
                variants.add(new PayloadVariant(originalIdStr + "%23", paramName + "=" + originalIdStr + "%23", originalIdStr + "%23", false, false, null));

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented4, "pollute-4", true, false, decremented4));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented10, "pollute-10", true, false, decremented10));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented100, "pollute-100", true, false, decremented100));
                }

                // 数组格式变体
                StringBuilder arrayFormat = new StringBuilder("[" + originalIdStr);
                if (decremented4 != null && !decremented4.startsWith("-")) {
                    arrayFormat.append(",").append(decremented4);
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    arrayFormat.append(",").append(decremented10);
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    arrayFormat.append(",").append(decremented100);
                }
                arrayFormat.append("]");
                variants.add(new PayloadVariant(arrayFormat.toString(), paramName + "=" + arrayFormat, "to[-4-10-100]", false, true, null));

                // 路径遍历变体
                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr + "/../" + decremented4, paramName + "=" + originalIdStr + "/../" + decremented4, "/../-4", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr + "/../" + decremented10, paramName + "=" + originalIdStr + "/../" + decremented10, "/../-10", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(new PayloadVariant(originalIdStr + "/../" + decremented100, paramName + "=" + originalIdStr + "/../" + decremented100, "/../-100", false, false, null));
                }
            }

            // 基本变体 - 移到最后（倒数第二和倒数第一）
            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
            variants.addAll(generateNinesVariant(paramName, false));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
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

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(-1), "-1"));
            variants.addAll(generateJsonJsonSuffixVariants(originalValue));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 4), "-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 10), "-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 100), "-100"));

            // 新增：前缀零变体
            variants.addAll(generateJsonZeroPrefixVariants(originalValue));

            // 新增：后缀"a"变体
            variants.addAll(generateJsonSuffixAVariants(originalValue));

            // 新增：小数点变体
            variants.addAll(generateJsonDecimalVariants(originalValue));

            // 新增：多个9变体
            variants.addAll(generateJsonNinesVariants(originalValue));
            variants.addAll(generateJsonSpaceVariants(originalValue));
            variants.addAll(generateJsonUnicodeCRLFVariants(originalValue));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "/"), "\"-4/\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "/"), "\"-10/\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "/"), "\"-100/\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 4)), "\"" + id + "," + (id - 4) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 10)), "\"" + id + "," + (id - 10) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 100)), "\"" + id + "," + (id - 100) + "\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\r\n"), "\"" + (id - 4) + "\\r\\n\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\r\n"), "\"" + (id - 10) + "\\r\\n\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\r\n"), "\"" + (id - 100) + "\\r\\n\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "%23"), "\"" + (id - 4) + "%23\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "%23"), "\"" + (id - 10) + "%23\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "%23"), "\"" + (id - 100) + "%23\""));

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

            // 空数组和null - 移到最后
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));

        } else if (originalValue.isLong()) {
            // 处理64位长整数
            long id = originalValue.asLong();

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(-1), "-1"));
            variants.addAll(generateJsonJsonSuffixVariants(originalValue));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 4), "-4"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 10), "-10"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 100), "-100"));

            // 新增：前缀零变体
            variants.addAll(generateJsonZeroPrefixVariants(originalValue));

            // 新增：后缀"a"变体
            variants.addAll(generateJsonSuffixAVariants(originalValue));

            // 新增：小数点变体
            variants.addAll(generateJsonDecimalVariants(originalValue));

            // 新增：多个9变体
            variants.addAll(generateJsonNinesVariants(originalValue));
            variants.addAll(generateJsonSpaceVariants(originalValue));
            variants.addAll(generateJsonUnicodeCRLFVariants(originalValue));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "/"), "\"-4/\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "/"), "\"-10/\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "/"), "\"-100/\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 4)), "\"" + id + "," + (id - 4) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 10)), "\"" + id + "," + (id - 10) + "\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 100)), "\"" + id + "," + (id - 100) + "\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\r\n"), "\"" + (id - 4) + "\\r\\n\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\r\n"), "\"" + (id - 10) + "\\r\\n\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\r\n"), "\"" + (id - 100) + "\\r\\n\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "%23"), "\"" + (id - 4) + "%23\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "%23"), "\"" + (id - 10) + "%23\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "%23"), "\"" + (id - 100) + "%23\""));

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

            // 空数组和null - 移到最后
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));

        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);

                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("-1"), "\"-1\""));
                variants.addAll(generateJsonJsonSuffixVariants(originalValue));

                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 4)), "\"-4\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 10)), "\"-10\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 100)), "\"-100\""));

                // 新增：前缀零变体
                variants.addAll(generateJsonZeroPrefixVariants(originalValue));

                // 新增：后缀"a"变体
                variants.addAll(generateJsonSuffixAVariants(originalValue));

                // 新增：小数点变体
                variants.addAll(generateJsonDecimalVariants(originalValue));

                // 新增：多个9变体
                variants.addAll(generateJsonNinesVariants(originalValue));
                variants.addAll(generateJsonSpaceVariants(originalValue));
                variants.addAll(generateJsonUnicodeCRLFVariants(originalValue));

                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "/"), "\"" + (id - 4) + "/\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "/"), "\"" + (id - 10) + "/\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "/"), "\"" + (id - 100) + "/\""));

                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + (id - 4)), "\"" + idStr + "," + (id - 4) + "\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + (id - 10)), "\"" + idStr + "," + (id - 10) + "\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + (id - 100)), "\"" + idStr + "," + (id - 100) + "\""));

                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\r\n"), "\"" + (id - 4) + "\\r\\n\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\r\n"), "\"" + (id - 10) + "\\r\\n\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\r\n"), "\"" + (id - 100) + "\\r\\n\""));

                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "%23"), "\"" + (id - 4) + "%23\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "%23"), "\"" + (id - 10) + "%23\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "%23"), "\"" + (id - 100) + "%23\""));

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

                // 空数组和null - 移到最后
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
            } catch (NumberFormatException e) {
                // 处理超长数字
                if (isValidDigitString(idStr)) {
                    String decremented4 = decrementStringNumber(idStr, 4);
                    String decremented10 = decrementStringNumber(idStr, 10);
                    String decremented100 = decrementStringNumber(idStr, 100);

                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4), "\"-4\""));
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10), "\"-10\""));
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100), "\"-100\""));
                    }

                    // 新增：前缀零变体
                    variants.addAll(generateJsonZeroPrefixVariants(originalValue));

                    // 新增：后缀"a"变体
                    variants.addAll(generateJsonSuffixAVariants(originalValue));

                    // 新增：小数点变体
                    variants.addAll(generateJsonDecimalVariants(originalValue));

                    // 新增：多个9变体
                    variants.addAll(generateJsonNinesVariants(originalValue));

                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "/"), "\"" + decremented4 + "/\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + decremented4), "\"" + idStr + "," + decremented4 + "\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "\r\n"), "\"" + decremented4 + "\\r\\n\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "%23"), "\"" + decremented4 + "%23\""));
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "/"), "\"" + decremented10 + "/\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + decremented10), "\"" + idStr + "," + decremented10 + "\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "\r\n"), "\"" + decremented10 + "\\r\\n\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "%23"), "\"" + decremented10 + "%23\""));
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "/"), "\"" + decremented100 + "/\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + decremented100), "\"" + idStr + "," + decremented100 + "\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "\r\n"), "\"" + decremented100 + "\\r\\n\""));
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "%23"), "\"" + decremented100 + "%23\""));
                    }

                    ArrayNode arrayVariant3 = JsonNodeFactory.instance.arrayNode();
                    arrayVariant3.add(idStr);
                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        arrayVariant3.add(decremented4);
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        arrayVariant3.add(decremented10);
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        arrayVariant3.add(decremented100);
                    }
                    variants.add(new JsonPayloadVariant(arrayVariant3, "to[\"-4\"\"-10\"\"-100\"]"));

                    // 路径遍历变体
                    if (decremented4 != null && !decremented4.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + decremented4), "\"/../-4\""));
                    }
                    if (decremented10 != null && !decremented10.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + decremented10), "\"/../-10\""));
                    }
                    if (decremented100 != null && !decremented100.startsWith("-")) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + decremented100), "\"/../-100\""));
                    }
                }

                // 空数组和null - 移到最后
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
                variants.addAll(generateJsonNinesVariants(originalValue));
            }

        } else if (originalValue.isArray()) {
            // 数组情况
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
                        // 处理超长数字
                        if (isValidDigitString(idStr)) {
                            String decremented4 = decrementStringNumber(idStr, 4);
                            String decremented10 = decrementStringNumber(idStr, 10);
                            String decremented100 = decrementStringNumber(idStr, 100);

                            ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
                            arrayVariant.add(idStr);
                            if (decremented4 != null && !decremented4.startsWith("-")) {
                                arrayVariant.add(decremented4);
                            }
                            if (decremented10 != null && !decremented10.startsWith("-")) {
                                arrayVariant.add(decremented10);
                            }
                            if (decremented100 != null && !decremented100.startsWith("-")) {
                                arrayVariant.add(decremented100);
                            }
                            variants.add(new JsonPayloadVariant(arrayVariant, "to[\"-4\"\"-10\"\"-100\"]"));
                        }
                    }
                }
            }

            // 数组情况下的空数组和null - 移到最后
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));

            // 新增：多个9变体
            variants.addAll(generateJsonNinesVariants(originalValue));
        }

        return variants;
    }

    /**
     * 生成JSON重复字段变体 - 通过直接修改JSON字符串
     * @param originalRequest 原始请求
     * @param fieldPath 字段路径
     * @param originalValue 原始值
     * @param messageId 消息ID
     * @param host 主机名
     */
    private void processJsonDuplicateFieldVariants(HttpRequest originalRequest, String fieldPath, JsonNode originalValue, int messageId, String host) {
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

            } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
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
                    if (isValidDigitString(idStr)) {
                        String decremented4 = decrementStringNumber(idStr, 4);
                        String decremented10 = decrementStringNumber(idStr, 10);
                        String decremented100 = decrementStringNumber(idStr, 100);

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
     * @param originalJson 原始JSON字符串
     * @param fieldName 字段名
     * @param originalValue 原始值
     * @param value4 -4值
     * @param value10 -10值
     * @param value100 -100值
     * @param isStringValue 是否为字符串值
     * @return 修改后的JSON字符串列表
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
     * @param originalJson 原始JSON
     * @param insertPos 插入位置
     * @param duplicateField 重复字段
     * @return 修改后的JSON
     */
    private String insertDuplicateField(String originalJson, int insertPos, String duplicateField) {
        StringBuilder sb = new StringBuilder(originalJson);
        sb.insert(insertPos, duplicateField);
        return sb.toString();
    }

    /**
     * 生成重复字段的expression - 修改后只显示新值
     * @param fieldName 字段名
     * @param originalValue 原始值
     * @param alias 别名
     * @return expression字符串
     */
    private String generateDuplicateExpression(String fieldName, String originalValue, String alias) {
        // 根据别名确定实际的重复值
        String duplicateValue;
        if (alias.equals("dup-4") || alias.equals("\"dup-4\"")) {
            // 从原始值中提取数字并减4
            if (originalValue.startsWith("\"") && originalValue.endsWith("\"")) {
                // 字符串格式："500" -> "496"
                String numStr = originalValue.substring(1, originalValue.length() - 1);
                try {
                    long num = Long.parseLong(numStr);
                    duplicateValue = "\"" + (num - 4) + "\"";
                } catch (NumberFormatException e) {
                    duplicateValue = originalValue;
                }
            } else {
                // 数字格式：500 -> 496
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

        // 修改：只返回修改后的值，不显示原值
        return "\"" + fieldName + "\":" + duplicateValue;
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
     * 发送修改后的请求并保存响应 - 使用新NettyManager
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
            rateLimiter.acquire(modifiedRequest.url().split("\\?")[0] + modifiedRequest.method());

            // 生成请求ID
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);

            // 保存修改后的请求和响应，传递新的参数
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "JSON",             // 固定设置为"JSON"
                    expression,
                    payloadAlias,        // 新增：payload别名
                    currentParamName,    // 新增：当前测试参数名称
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

    // =============== 以下是辅助方法，保持不变 ===============

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
     * 递归查找邮箱字段 - 支持数组中对象的email字段
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
     * 递归查找ID字段 - 支持数组中对象的ID字段
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


                // 检查是否为ID参数 - 修复：扩展匹配规则以支持 "clientNameisd" 等
                boolean isIdParam = isIdParameter(fieldName);

                if (isIdParam) {

                    boolean isValidId = false;
                    if (fieldValue.isInt()) {
                        isValidId = true;
                    } else if (fieldValue.isLong()) {
                        isValidId = true;
                    } else if (fieldValue.isTextual()) {
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
     * 检查是否为ID参数 - 只匹配以id/ids结尾的字段名
     * @param paramName 参数名
     * @return 是否为ID参数
     */
    private boolean isIdParameter(String paramName) {
        String lowerName = paramName.toLowerCase();
        return lowerName.endsWith("id") || lowerName.endsWith("ids");
    }

    /**
     * 检查是否为数字ID - 修复：支持长整数和超长数字
     * @param value 值
     * @return 是否为数字ID
     */
    private boolean isNumericId(String value) {
        // 修复：首先检查是否为纯数字字符串
        if (!isValidDigitString(value)) {
            return false;
        }

        try {
            // 尝试使用Long.parseLong()解析
            Long.parseLong(value);
            return true;
        } catch (NumberFormatException e) {
            // 如果Long.parseLong()失败，但是是有效的数字字符串，仍然认为是数字ID
            // 这样可以支持超长数字
            return true;
        }
    }

    /**
     * 检查字符串是否为有效的数字字符串（只包含数字）
     * @param str 字符串
     * @return 是否为有效的数字字符串
     */
    private boolean isValidDigitString(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        return str.matches("\\d+");
    }

    /**
     * 检查数组是否包含数字ID - 支持长整数
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

        if (shuttingDown) {
            logging.logToOutput("[JsonLister] Starting shutdown...");
            logging.logToOutput("[JsonLister] Shutdown complete");
        }
    }
}