package pzfzr.fuzzer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.io.UnsupportedEncodingException;

/**
 * JsonListerPayloadGenerator类
 * 负责生成各种类型的payload变体,包括邮箱、ID和路径ID的fuzz payload
 *
 * 主要功能:
 * - 邮箱payload生成
 * - ID参数payload生成(Query/Body/JSON)
 * - 路径ID payload生成
 * - 各种辅助工具方法
 */
public class JsonListerPayloadGenerator {

    // =============== 常量定义 ===============

    /** Hash生成字符集 */
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";

    /** Hash长度 */
    private static final int HASH_LENGTH = 5;

    /** 线程本地随机数生成器 */
    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);

    /** 邮箱匹配正则表达式 */
    private static final Pattern EMAIL_REGEX = Pattern.compile(
            "(zycc[+-][a-zA-Z0-9]+@intigriti\\.me|zcyy[+-][a-zA-Z0-9]+@(bugcrowdninja|wearehackerone)\\.com)"
    );

    /** ID参数匹配正则表达式 */
    private static final Pattern ID_REGEX = Pattern.compile(
            "(\"[^\"]*ids?\":|[?&][^=&]*ids?=)",
            Pattern.CASE_INSENSITIVE
    );

    /** 路径中数字ID的正则表达式 */
    private static final Pattern PATH_NUMERIC_PATTERN = Pattern.compile("/([0-9]+)(?=[/?#]|$)");

    // =============== 依赖对象 ===============

    /** JSON对象映射器 */
    private final ObjectMapper objectMapper;

    /** 邮箱匹配模式 */
    private final Pattern emailPattern;

    /**
     * 构造函数
     * @param objectMapper JSON对象映射器
     */
    public JsonListerPayloadGenerator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.emailPattern = EMAIL_REGEX;
    }

    // =============== 内部类定义 ===============

    /**
     * Payload变体类 - 将payload值和别名绑定在一起
     * 用于Query和Body参数的payload
     */
    public static class PayloadVariant {
        private final String value;
        private final String expression;
        private final String alias;
        private final boolean isParameterPollution;
        private final boolean isArrayFormat;
        private final String secondValue;

        public PayloadVariant(String value, String expression, String alias,
                              boolean isParameterPollution, boolean isArrayFormat, String secondValue) {
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
    public static class JsonPayloadVariant {
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
    public static class PathIdVariant {
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
     * 路径ID匹配类
     */
    public static class PathIdMatch {
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

    // =============== 邮箱相关方法 ===============

    /**
     * 生成随机hash值
     * @return 5位随机hash字符串
     */
    public String generateHash() {
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
    public String generateAttackerEmail(String targetEmail) {
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
        return targetEmail;
    }

    /**
     * 检查邮箱是否匹配目标模式
     * @param email 邮箱地址
     * @return 是否匹配
     */
    public boolean isTargetEmail(String email) {
        return EMAIL_REGEX.matcher(email).matches();
    }

    // =============== ID参数判断方法 ===============

    /**
     * 检查是否为ID参数 - 只匹配以id/ids结尾的字段名
     * @param paramName 参数名
     * @return 是否为ID参数
     */
    public boolean isIdParameter(String paramName) {
        String lowerName = paramName.toLowerCase();
        return lowerName.endsWith("id") || lowerName.endsWith("ids");
    }

    /**
     * 检查是否为数字ID
     * @param value 值
     * @return 是否为数字ID
     */
    public boolean isNumericId(String value) {
        if (!isValidDigitString(value)) {
            return false;
        }
        try {
            Long.parseLong(value);
            return true;
        } catch (NumberFormatException e) {
            return true; // 超长数字也认为是数字ID
        }
    }

    /**
     * 检查字符串是否为有效的数字字符串
     * @param str 字符串
     * @return 是否为有效的数字字符串
     */
    public boolean isValidDigitString(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        return str.matches("\\d+");
    }

    /**
     * 检查数组是否包含数字ID
     * @param arrayNode 数组节点
     * @return 是否包含数字ID
     */
    public boolean containsNumericIds(JsonNode arrayNode) {
        for (JsonNode item : arrayNode) {
            if (item.isInt() || item.isLong() || (item.isTextual() && isNumericId(item.asText()))) {
                return true;
            }
        }
        return false;
    }

    // =============== Query ID Payload生成 ===============

    /**
     * 生成Query ID的PayloadVariant列表
     * @param originalIdStr 原始ID字符串
     * @param paramName 参数名称
     * @return PayloadVariant列表
     */
    public List<PayloadVariant> generateQueryIdPayloads(String originalIdStr, String paramName) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            variants.add(new PayloadVariant("-1", paramName + "=-1", "-1", false, false, null));
            variants.addAll(generateJsonSuffixVariants(originalIdStr, paramName, false));
            variants.add(new PayloadVariant(String.valueOf(originalId - 4), paramName + "=" + (originalId - 4), "-4", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 10), paramName + "=" + (originalId - 10), "-10", false, false, null));
            variants.add(new PayloadVariant(String.valueOf(originalId - 100), paramName + "=" + (originalId - 100), "-100", false, false, null));

            variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, false));
            variants.addAll(generateSuffixAVariants(originalIdStr, paramName, false));
            variants.addAll(generateDecimalVariants(originalIdStr, paramName, false));
            variants.addAll(generateNinesVariant(paramName, false));
            variants.addAll(generateSpaceVariants(originalIdStr, paramName, true));
            variants.addAll(generateUnicodeCRLFVariants(originalIdStr, paramName, true));

            String encodedOrigSlash = URLEncoder.encode(originalId + "/", StandardCharsets.UTF_8.name());
            variants.add(new PayloadVariant(encodedOrigSlash, paramName + "=" + encodedOrigSlash, "orig/", false, false, null));

            if (originalId > 4) {
                String encodedValue = URLEncoder.encode((originalId - 4) + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedValue, paramName + "=" + encodedValue, "orig-4/", false, false, null));
            }
            if (originalId > 10) {
                String encodedValue = URLEncoder.encode((originalId - 10) + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedValue, paramName + "=" + encodedValue, "orig-10/", false, false, null));
            }
            if (originalId > 100) {
                String encodedValue = URLEncoder.encode((originalId - 100) + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedValue, paramName + "=" + encodedValue, "orig-100/", false, false, null));
            }

            if (originalId > 4) {
                String commaValue = originalId + "," + (originalId - 4);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, "orig,orig-4", false, false, null));
            }
            if (originalId > 10) {
                String commaValue = originalId + "," + (originalId - 10);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, "orig,orig-10", false, false, null));
            }
            if (originalId > 100) {
                String commaValue = originalId + "," + (originalId - 100);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, "orig,orig-100", false, false, null));
            }

            variants.add(new PayloadVariant(originalId + "%0D%0A", paramName + "=" + originalId + "%0D%0A", "orig%0D%0A", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%0D%0A", paramName + "=" + (originalId - 4) + "%0D%0A", "orig-4%0D%0A", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%0D%0A", paramName + "=" + (originalId - 10) + "%0D%0A", "orig-10%0D%0A", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%0D%0A", paramName + "=" + (originalId - 100) + "%0D%0A", "orig-100%0D%0A", false, false, null));
            }

            variants.add(new PayloadVariant(originalId + "%23", paramName + "=" + originalId + "%23", "orig%23", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%23", paramName + "=" + (originalId - 4) + "%23", "orig-4%23", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%23", paramName + "=" + (originalId - 10) + "%23", "orig-10%23", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%23", paramName + "=" + (originalId - 100) + "%23", "orig-100%23", false, false, null));
            }

            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 4), "pollute-4", true, false, String.valueOf(originalId - 4)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 10), "pollute-10", true, false, String.valueOf(originalId - 10)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 100), "pollute-100", true, false, String.valueOf(originalId - 100)));

            String arrayFormat = "[" + originalId + "," + (originalId - 4) + "," + (originalId - 10) + "," + (originalId - 100) + "]";
            variants.add(new PayloadVariant(arrayFormat, paramName + "=" + arrayFormat, "to[-4-10-100]", false, true, null));

            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 4), paramName + "=" + originalId + "/../" + (originalId - 4), "/../-4", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 10), paramName + "=" + originalId + "/../" + (originalId - 10), "/../-10", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 100), paramName + "=" + originalId + "/../" + (originalId - 100), "/../-100", false, false, null));

            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));

        } catch (NumberFormatException e) {
            handleLongNumberQueryPayloads(originalIdStr, paramName, variants);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return variants;
    }

    /**
     * 处理超长数字的Query payload生成
     */
    private void handleLongNumberQueryPayloads(String originalIdStr, String paramName, List<PayloadVariant> variants) {
        if (isValidDigitString(originalIdStr)) {
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

            variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, false));
            variants.addAll(generateSuffixAVariants(originalIdStr, paramName, false));
            variants.addAll(generateDecimalVariants(originalIdStr, paramName, false));
            variants.addAll(generateNinesVariant(paramName, false));

            try {
                String encodedOrigSlash = URLEncoder.encode(originalIdStr + "/", StandardCharsets.UTF_8.name());
                variants.add(new PayloadVariant(encodedOrigSlash, paramName + "=" + originalIdStr + "/", "orig/", false, false, null));

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    String encodedSlash = URLEncoder.encode(decremented4 + "/", StandardCharsets.UTF_8.name());
                    variants.add(new PayloadVariant(encodedSlash, paramName + "=" + decremented4 + "/", "orig-4/", false, false, null));
                    variants.add(new PayloadVariant(originalIdStr + "," + decremented4, paramName + "=" + originalIdStr + "," + decremented4, "orig,orig-4", false, false, null));
                    variants.add(new PayloadVariant(decremented4 + "%0D%0A", paramName + "=" + decremented4 + "%0D%0A", "orig-4%0D%0A", false, false, null));
                    variants.add(new PayloadVariant(decremented4 + "%23", paramName + "=" + decremented4 + "%23", "orig-4%23", false, false, null));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    String encodedSlash = URLEncoder.encode(decremented10 + "/", StandardCharsets.UTF_8.name());
                    variants.add(new PayloadVariant(encodedSlash, paramName + "=" + decremented10 + "/", "orig-10/", false, false, null));
                    variants.add(new PayloadVariant(originalIdStr + "," + decremented10, paramName + "=" + originalIdStr + "," + decremented10, "orig,orig-10", false, false, null));
                    variants.add(new PayloadVariant(decremented10 + "%0D%0A", paramName + "=" + decremented10 + "%0D%0A", "orig-10%0D%0A", false, false, null));
                    variants.add(new PayloadVariant(decremented10 + "%23", paramName + "=" + decremented10 + "%23", "orig-10%23", false, false, null));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    String encodedSlash = URLEncoder.encode(decremented100 + "/", StandardCharsets.UTF_8.name());
                    variants.add(new PayloadVariant(encodedSlash, paramName + "=" + decremented100 + "/", "orig-100/", false, false, null));
                    variants.add(new PayloadVariant(originalIdStr + "," + decremented100, paramName + "=" + originalIdStr + "," + decremented100, "orig,orig-100", false, false, null));
                    variants.add(new PayloadVariant(decremented100 + "%0D%0A", paramName + "=" + decremented100 + "%0D%0A", "orig-100%0D%0A", false, false, null));
                    variants.add(new PayloadVariant(decremented100 + "%23", paramName + "=" + decremented100 + "%23", "orig-100%23", false, false, null));
                }
            } catch (Exception ex) {
                // 忽略编码错误
            }

            variants.add(new PayloadVariant(originalIdStr + "%0D%0A", paramName + "=" + originalIdStr + "%0D%0A", "orig%0D%0A", false, false, null));
            variants.add(new PayloadVariant(originalIdStr + "%23", paramName + "=" + originalIdStr + "%23", "orig%23", false, false, null));

            if (decremented4 != null && !decremented4.startsWith("-")) {
                variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented4, "pollute-4", true, false, decremented4));
            }
            if (decremented10 != null && !decremented10.startsWith("-")) {
                variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented10, "pollute-10", true, false, decremented10));
            }
            if (decremented100 != null && !decremented100.startsWith("-")) {
                variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented100, "pollute-100", true, false, decremented100));
            }

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

        variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
        variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
        variants.addAll(generateNinesVariant(paramName, false));
    }

    // =============== Body ID Payload生成 ===============

    /**
     * 生成Body ID的PayloadVariant列表
     * @param originalIdStr 原始ID字符串
     * @param paramName 参数名称
     * @return PayloadVariant列表
     */
    public List<PayloadVariant> generateBodyIdPayloads(String originalIdStr, String paramName) {
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

            variants.add(new PayloadVariant(originalId + "/", paramName + "=" + originalId + "/", "orig/", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "/", paramName + "=" + (originalId - 4) + "/", "orig-4/", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "/", paramName + "=" + (originalId - 10) + "/", "orig-10/", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "/", paramName + "=" + (originalId - 100) + "/", "orig-100/", false, false, null));
            }

            if (originalId > 4) {
                String commaValue = originalId + "," + (originalId - 4);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, "orig,orig-4", false, false, null));
            }
            if (originalId > 10) {
                String commaValue = originalId + "," + (originalId - 10);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, "orig,orig-10", false, false, null));
            }
            if (originalId > 100) {
                String commaValue = originalId + "," + (originalId - 100);
                variants.add(new PayloadVariant(commaValue, paramName + "=" + commaValue, "orig,orig-100", false, false, null));
            }

            variants.add(new PayloadVariant(originalId + "%0D%0A", paramName + "=" + originalId + "%0D%0A", "orig%0D%0A", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%0D%0A", paramName + "=" + (originalId - 4) + "%0D%0A", "orig-4%0D%0A", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%0D%0A", paramName + "=" + (originalId - 10) + "%0D%0A", "orig-10%0D%0A", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%0D%0A", paramName + "=" + (originalId - 100) + "%0D%0A", "orig-100%0D%0A", false, false, null));
            }

            variants.add(new PayloadVariant(originalId + "%23", paramName + "=" + originalId + "%23", "orig%23", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + "%23", paramName + "=" + (originalId - 4) + "%23", "orig-4%23", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + "%23", paramName + "=" + (originalId - 10) + "%23", "orig-10%23", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + "%23", paramName + "=" + (originalId - 100) + "%23", "orig-100%23", false, false, null));
            }

            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 4), "pollute-4", true, false, String.valueOf(originalId - 4)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 10), "pollute-10", true, false, String.valueOf(originalId - 10)));
            variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + (originalId - 100), "pollute-100", true, false, String.valueOf(originalId - 100)));

            String arrayFormat = "[" + originalId + "," + (originalId - 4) + "," + (originalId - 10) + "," + (originalId - 100) + "]";
            variants.add(new PayloadVariant(arrayFormat, paramName + "=" + arrayFormat, "to[-4-10-100]", false, true, null));

            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 4), paramName + "=" + originalId + "/../" + (originalId - 4), "/../-4", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 10), paramName + "=" + originalId + "/../" + (originalId - 10), "/../-10", false, false, null));
            variants.add(new PayloadVariant(originalId + "/../" + (originalId - 100), paramName + "=" + originalId + "/../" + (originalId - 100), "/../-100", false, false, null));

            variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
            variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));

        } catch (NumberFormatException e) {
            handleLongNumberBodyPayloads(originalIdStr, paramName, variants);
        }
        return variants;
    }

    /**
     * 处理超长数字的Body payload生成
     */
    private void handleLongNumberBodyPayloads(String originalIdStr, String paramName, List<PayloadVariant> variants) {
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

            variants.addAll(generateZeroPrefixVariants(originalIdStr, paramName, true));
            variants.addAll(generateSuffixAVariants(originalIdStr, paramName, true));
            variants.addAll(generateDecimalVariants(originalIdStr, paramName, true));
            variants.addAll(generateNinesVariant(paramName, true));
            variants.addAll(generateJsonSuffixVariants(originalIdStr, paramName, true));

            variants.add(new PayloadVariant(originalIdStr + "/", paramName + "=" + originalIdStr + "/", "orig/", false, false, null));

            if (decremented4 != null && !decremented4.startsWith("-")) {
                variants.add(new PayloadVariant(decremented4 + "/", paramName + "=" + decremented4 + "/", "orig-4/", false, false, null));
                variants.add(new PayloadVariant(originalIdStr + "," + decremented4, paramName + "=" + originalIdStr + "," + decremented4, "orig,orig-4", false, false, null));
                variants.add(new PayloadVariant(decremented4 + "%0D%0A", paramName + "=" + decremented4 + "%0D%0A", "orig-4%0D%0A", false, false, null));
                variants.add(new PayloadVariant(decremented4 + "%23", paramName + "=" + decremented4 + "%23", "orig-4%23", false, false, null));
            }
            if (decremented10 != null && !decremented10.startsWith("-")) {
                variants.add(new PayloadVariant(decremented10 + "/", paramName + "=" + decremented10 + "/", "orig-10/", false, false, null));
                variants.add(new PayloadVariant(originalIdStr + "," + decremented10, paramName + "=" + originalIdStr + "," + decremented10, "orig,orig-10", false, false, null));
                variants.add(new PayloadVariant(decremented10 + "%0D%0A", paramName + "=" + decremented10 + "%0D%0A", "orig-10%0D%0A", false, false, null));
                variants.add(new PayloadVariant(decremented10 + "%23", paramName + "=" + decremented10 + "%23", "orig-10%23", false, false, null));
            }
            if (decremented100 != null && !decremented100.startsWith("-")) {
                variants.add(new PayloadVariant(decremented100 + "/", paramName + "=" + decremented100 + "/", "orig-100/", false, false, null));
                variants.add(new PayloadVariant(originalIdStr + "," + decremented100, paramName + "=" + originalIdStr + "," + decremented100, "orig,orig-100", false, false, null));
                variants.add(new PayloadVariant(decremented100 + "%0D%0A", paramName + "=" + decremented100 + "%0D%0A", "orig-100%0D%0A", false, false, null));
                variants.add(new PayloadVariant(decremented100 + "%23", paramName + "=" + decremented100 + "%23", "orig-100%23", false, false, null));
            }

            variants.add(new PayloadVariant(originalIdStr + "%0D%0A", paramName + "=" + originalIdStr + "%0D%0A", "orig%0D%0A", false, false, null));
            variants.add(new PayloadVariant(originalIdStr + "%23", paramName + "=" + originalIdStr + "%23", "orig%23", false, false, null));

            if (decremented4 != null && !decremented4.startsWith("-")) {
                variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented4, "pollute-4", true, false, decremented4));
            }
            if (decremented10 != null && !decremented10.startsWith("-")) {
                variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented10, "pollute-10", true, false, decremented10));
            }
            if (decremented100 != null && !decremented100.startsWith("-")) {
                variants.add(new PayloadVariant(originalIdStr, "&" + paramName + "=" + decremented100, "pollute-100", true, false, decremented100));
            }

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

        variants.add(new PayloadVariant("[]", paramName + "=[]", "[]", false, true, null));
        variants.add(new PayloadVariant("null", paramName + "=null", "null", false, false, null));
        variants.addAll(generateNinesVariant(paramName, true));
    }

    // =============== JSON ID Payload生成 ===============

    /**
     * 生成JSON ID的JsonPayloadVariant列表
     * @param originalValue 原始值
     * @return JsonPayloadVariant列表
     */
    public List<JsonPayloadVariant> generateJsonIdPayloads(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();

        if (originalValue.isInt()) {
            generateIntegerJsonPayloads(originalValue.asInt(), variants);
        } else if (originalValue.isLong()) {
            generateLongJsonPayloads(originalValue.asLong(), variants);
        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            generateStringJsonPayloads(originalValue.asText(), variants);
        } else if (originalValue.isArray()) {
            generateArrayJsonPayloads(originalValue, variants);
        }

        return variants;
    }

    /**
     * 生成整数类型的JSON payload
     */
    private void generateIntegerJsonPayloads(int id, List<JsonPayloadVariant> variants) {
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(-1), "-1"));
        variants.addAll(generateJsonJsonSuffixVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 4), "-4"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 10), "-10"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 100), "-100"));

        variants.addAll(generateJsonZeroPrefixVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonSuffixAVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonDecimalVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonNinesVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonSpaceVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonUnicodeCRLFVariants(JsonNodeFactory.instance.numberNode(id)));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "/"), "\"-4/\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "/"), "\"-10/\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "/"), "\"-100/\""));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 4)), "\"orig,orig-4\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 10)), "\"orig,orig-10\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 100)), "\"orig,orig-100\""));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\r\n"), "\"orig-4\\r\\n\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\r\n"), "\"orig-10\\r\\n\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\r\n"), "\"orig-100\\r\\n\""));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "%23"), "\"orig-4%23\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "%23"), "\"orig-10%23\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "%23"), "\"orig-100%23\""));

        ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
        arrayVariant.add(id);
        arrayVariant.add(id - 4);
        arrayVariant.add(id - 10);
        arrayVariant.add(id - 100);
        variants.add(new JsonPayloadVariant(arrayVariant, "to[-4-10-100]"));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)), "/../-4"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)), "/../-10"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)), "/../-100"));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
    }

    /**
     * 生成长整数类型的JSON payload
     */
    private void generateLongJsonPayloads(long id, List<JsonPayloadVariant> variants) {
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(-1), "-1"));
        variants.addAll(generateJsonJsonSuffixVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 4), "-4"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 10), "-10"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode(id - 100), "-100"));

        variants.addAll(generateJsonZeroPrefixVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonSuffixAVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonDecimalVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonNinesVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonSpaceVariants(JsonNodeFactory.instance.numberNode(id)));
        variants.addAll(generateJsonUnicodeCRLFVariants(JsonNodeFactory.instance.numberNode(id)));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "/"), "\"-4/\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "/"), "\"-10/\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "/"), "\"-100/\""));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 4)), "\"orig,orig-4\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 10)), "\"orig,orig-10\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "," + (id - 100)), "\"orig,orig-100\""));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\r\n"), "\"orig-4\\r\\n\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\r\n"), "\"orig-10\\r\\n\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\r\n"), "\"orig-100\\r\\n\""));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "%23"), "\"orig-4%23\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "%23"), "\"orig-10%23\""));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "%23"), "\"orig-100%23\""));

        ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
        arrayVariant.add(id);
        arrayVariant.add(id - 4);
        arrayVariant.add(id - 10);
        arrayVariant.add(id - 100);
        variants.add(new JsonPayloadVariant(arrayVariant, "to[-4-10-100]"));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 4)), "/../-4"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 10)), "/../-10"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "/../" + (id - 100)), "/../-100"));

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
    }

    /**
     * 生成字符串类型的JSON payload
     */
    private void generateStringJsonPayloads(String idStr, List<JsonPayloadVariant> variants) {
        try {
            long id = Long.parseLong(idStr);
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode("-1"), "\"-1\""));
            variants.addAll(generateJsonJsonSuffixVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 4)), "\"-4\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 10)), "\"-10\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.valueOf(id - 100)), "\"-100\""));

            variants.addAll(generateJsonZeroPrefixVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonSuffixAVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonDecimalVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonNinesVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonSpaceVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonUnicodeCRLFVariants(JsonNodeFactory.instance.textNode(idStr)));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "/"), "\"orig-4/\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "/"), "\"orig-10/\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "/"), "\"orig-100/\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + (id - 4)), "\"orig,orig-4\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + (id - 10)), "\"orig,orig-10\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + (id - 100)), "\"orig,orig-100\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\r\n"), "\"orig-4\\r\\n\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\r\n"), "\"orig-10\\r\\n\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\r\n"), "\"orig-100\\r\\n\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "%23"), "\"orig-4%23\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "%23"), "\"orig-10%23\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "%23"), "\"orig-100%23\""));

            ArrayNode arrayVariant = JsonNodeFactory.instance.arrayNode();
            arrayVariant.add(idStr);
            arrayVariant.add(String.valueOf(id - 4));
            arrayVariant.add(String.valueOf(id - 10));
            arrayVariant.add(String.valueOf(id - 100));
            variants.add(new JsonPayloadVariant(arrayVariant, "to[\"-4\"\"-10\"\"-100\"]"));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 4)), "\"/../-4\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 10)), "\"/../-10\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "/../" + (id - 100)), "\"/../-100\""));

            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));

        } catch (NumberFormatException e) {
            handleLongNumberStringJsonPayloads(idStr, variants);
        }
    }

    /**
     * 处理超长数字字符串的JSON payload
     */
    private void handleLongNumberStringJsonPayloads(String idStr, List<JsonPayloadVariant> variants) {
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

            variants.addAll(generateJsonZeroPrefixVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonSuffixAVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonDecimalVariants(JsonNodeFactory.instance.textNode(idStr)));
            variants.addAll(generateJsonNinesVariants(JsonNodeFactory.instance.textNode(idStr)));

            if (decremented4 != null && !decremented4.startsWith("-")) {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "/"), "\"orig-4/\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + decremented4), "\"orig,orig-4\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "\r\n"), "\"orig-4\\r\\n\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented4 + "%23"), "\"orig-4%23\""));
            }
            if (decremented10 != null && !decremented10.startsWith("-")) {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "/"), "\"orig-10/\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + decremented10), "\"orig,orig-10\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "\r\n"), "\"orig-10\\r\\n\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented10 + "%23"), "\"orig-10%23\""));
            }
            if (decremented100 != null && !decremented100.startsWith("-")) {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "/"), "\"orig-100/\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "," + decremented100), "\"orig,orig-100\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "\r\n"), "\"orig-100\\r\\n\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(decremented100 + "%23"), "\"orig-100%23\""));
            }

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

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
        variants.addAll(generateJsonNinesVariants(JsonNodeFactory.instance.textNode(idStr)));
    }

    /**
     * 生成数组类型的JSON payload
     */
    private void generateArrayJsonPayloads(JsonNode arrayNode, List<JsonPayloadVariant> variants) {
        JsonNode firstItem = arrayNode.get(0);
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

        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.arrayNode(), "[]"));
        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.nullNode(), "null"));
        variants.addAll(generateJsonNinesVariants(arrayNode));
    }

    // =============== 路径ID Payload生成 ===============

    /**
     * 从路径中提取所有数字ID
     * @param path URL路径
     * @return 路径ID匹配列表
     */
    public List<PathIdMatch> extractPathIds(String path) {
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
    public List<PathIdVariant> generatePathIdVariants(String originalPath, PathIdMatch pathId) {
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

                variants.addAll(generatePathIdZeroPrefixVariants(originalPath, pathId, idStr));
                variants.addAll(generatePathIdSuffixAVariants(originalPath, pathId, idStr));
                variants.addAll(generatePathIdDecimalVariants(originalPath, pathId, idStr));
                variants.addAll(generatePathIdNinesVariants(originalPath, pathId));

                variants.add(createPathVariant(originalPath, pathId, originalId + "+", "orig+"));
                variants.add(createPathVariant(originalPath, pathId, "+" + originalId, "+orig"));

                if (originalId > 4) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "+", "orig-4+"));
                    variants.add(createPathVariant(originalPath, pathId, "+" + (originalId - 4), "+orig-4"));
                }
                if (originalId > 10) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "+", "orig-10+"));
                    variants.add(createPathVariant(originalPath, pathId, "+" + (originalId - 10), "+orig-10"));
                }
                if (originalId > 100) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "+", "orig-100+"));
                    variants.add(createPathVariant(originalPath, pathId, "+" + (originalId - 100), "+orig-100"));
                }

                variants.add(createPathVariant(originalPath, pathId, originalId + "%5cu000D%5cu000A", "orig%5cu000D%5cu000A"));
                if (originalId > 4) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "%5cu000D%5cu000A", "orig-4%5cu000D%5cu000A"));
                }
                if (originalId > 10) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "%5cu000D%5cu000A", "orig-10%5cu000D%5cu000A"));
                }
                if (originalId > 100) {
                    variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "%5cu000D%5cu000A", "orig-100%5cu000D%5cu000A"));
                }

                variants.addAll(generatePathIdSlashSuffixVariants(originalPath, pathId, idStr));
                variants.addAll(generatePathIdCommaVariants(originalPath, pathId, idStr));
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
                variants.addAll(generateStringBasedVariants(originalPath, pathId, idStr));
                variants.addAll(generatePathIdNinesVariants(originalPath, pathId));
            }
        }

        variants.add(createPathVariant(originalPath, pathId, "[]", "[]"));
        variants.add(createPathVariant(originalPath, pathId, "null", "null"));

        return variants;
    }

    // =============== 辅助工具方法 ===============

    /**
     * 字符串数字递减运算
     * @param numberStr 数字字符串
     * @param decrement 递减值
     * @return 递减后的结果，如果结果为负数则返回null
     */
    public String decrementStringNumber(String numberStr, int decrement) {
        try {
            java.math.BigInteger bigInt = new java.math.BigInteger(numberStr);
            java.math.BigInteger result = bigInt.subtract(java.math.BigInteger.valueOf(decrement));
            if (result.compareTo(java.math.BigInteger.ZERO) < 0) {
                return null;
            }
            return result.toString();
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * 检查是否为超长数字
     */
    private boolean isUltraLongNumber(String idStr) {
        if (idStr.length() > 19) {
            return true;
        }
        if (idStr.length() == 19) {
            return idStr.compareTo("9223372036854775807") > 0;
        }
        return false;
    }

    /**
     * 创建路径变体
     */
    private PathIdVariant createPathVariant(String originalPath, PathIdMatch pathId, String newValue, String alias) {
        String newPath = originalPath.substring(0, pathId.getStartIndex()) + newValue + originalPath.substring(pathId.getEndIndex());
        return new PathIdVariant(newPath, newValue, alias);
    }

    /**
     * 为超长数字生成基于字符串的变体
     */
    private List<PathIdVariant> generateStringBasedVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            if (idStr.length() >= 1 && idStr.matches("\\d+")) {
                String decremented4 = decrementStringNumber(idStr, 4);
                String decremented10 = decrementStringNumber(idStr, 10);
                String decremented100 = decrementStringNumber(idStr, 100);

                if (decremented4 != null && !decremented4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented4, "-4"));
                    variants.add(createPathVariant(originalPath, pathId, idStr + "/../" + decremented4, "/../-4"));
                }
                if (decremented10 != null && !decremented10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented10, "-10"));
                    variants.add(createPathVariant(originalPath, pathId, idStr + "/../" + decremented10, "/../-10"));
                }
                if (decremented100 != null && !decremented100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, decremented100, "-100"));
                    variants.add(createPathVariant(originalPath, pathId, idStr + "/../" + decremented100, "/../-100"));
                }

                if (idStr.length() >= 3) {
                    String lastDigitZero = idStr.substring(0, idStr.length() - 1) + "0";
                    variants.add(createPathVariant(originalPath, pathId, lastDigitZero, "last→0"));

                    String lastDigit = idStr.substring(idStr.length() - 1);
                    if (!lastDigit.equals("0")) {
                        int digit = Integer.parseInt(lastDigit);
                        String lastDigitDec = idStr.substring(0, idStr.length() - 1) + (digit - 1);
                        variants.add(createPathVariant(originalPath, pathId, lastDigitDec, "last-1"));
                    }
                }

                if (idStr.length() > 10) {
                    String truncated = idStr.substring(0, 10);
                    variants.add(createPathVariant(originalPath, pathId, truncated, "trunc10"));
                }
            }
        } catch (Exception e) {
            // 忽略错误
        }
        return variants;
    }

    // =============== 各种变体生成方法(以下为原有方法的简化声明,完整实现保持不变) ===============

    private List<PayloadVariant> generateJsonSuffixVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            variants.add(new PayloadVariant(originalId + ".json", paramName + "=" + originalId + ".json", "orig.json", false, false, null));
            if (originalId > 4) {
                variants.add(new PayloadVariant((originalId - 4) + ".json", paramName + "=" + (originalId - 4) + ".json", "orig-4.json", false, false, null));
            }
            if (originalId > 10) {
                variants.add(new PayloadVariant((originalId - 10) + ".json", paramName + "=" + (originalId - 10) + ".json", "orig-10.json", false, false, null));
            }
            if (originalId > 100) {
                variants.add(new PayloadVariant((originalId - 100) + ".json", paramName + "=" + (originalId - 100) + ".json", "orig-100.json", false, false, null));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                variants.add(new PayloadVariant(originalIdStr + ".json", paramName + "=" + originalIdStr + ".json", "orig.json", false, false, null));
                String dec4 = decrementStringNumber(originalIdStr, 4);
                String dec10 = decrementStringNumber(originalIdStr, 10);
                String dec100 = decrementStringNumber(originalIdStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(new PayloadVariant(dec4 + ".json", paramName + "=" + dec4 + ".json", "orig-4.json", false, false, null));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(new PayloadVariant(dec10 + ".json", paramName + "=" + dec10 + ".json", "orig-10.json", false, false, null));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(new PayloadVariant(dec100 + ".json", paramName + "=" + dec100 + ".json", "orig-100.json", false, false, null));
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

    private List<PayloadVariant> generateSuffixAVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            String originalWithA = originalId + "a";
            variants.add(new PayloadVariant(originalWithA, paramName + "=" + originalWithA, "origa", false, false, null));
            String minus4WithA = (originalId - 4) + "a";
            String minus10WithA = (originalId - 10) + "a";
            String minus100WithA = (originalId - 100) + "a";
            variants.add(new PayloadVariant(minus4WithA, paramName + "=" + minus4WithA, "-4a", false, false, null));
            variants.add(new PayloadVariant(minus10WithA, paramName + "=" + minus10WithA, "-10a", false, false, null));
            variants.add(new PayloadVariant(minus100WithA, paramName + "=" + minus100WithA, "-100a", false, false, null));
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
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

    private List<PayloadVariant> generateDecimalVariants(String originalIdStr, String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            String minus1Decimal = (originalId - 1) + ".99999";
            variants.add(new PayloadVariant(minus1Decimal, paramName + "=" + minus1Decimal, "-1.99999", false, false, null));
            String minus5Decimal = (originalId - 5) + ".99999";
            String minus11Decimal = (originalId - 11) + ".99999";
            String minus101Decimal = (originalId - 101) + ".99999";
            variants.add(new PayloadVariant(minus5Decimal, paramName + "=" + minus5Decimal, "-5.99999", false, false, null));
            variants.add(new PayloadVariant(minus11Decimal, paramName + "=" + minus11Decimal, "-11.99999", false, false, null));
            variants.add(new PayloadVariant(minus101Decimal, paramName + "=" + minus101Decimal, "-101.99999", false, false, null));
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
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

    private List<PayloadVariant> generateNinesVariant(String paramName, boolean isBody) {
        List<PayloadVariant> variants = new ArrayList<>();
        String ninesValue = "999999999999999999999";
        variants.add(new PayloadVariant(ninesValue, paramName + "=" + ninesValue, "999s", false, false, null));
        return variants;
    }

    public List<PayloadVariant> generateSpaceVariants(String originalIdStr, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            if (isQuery) {
                variants.add(new PayloadVariant(originalId + "+", paramName + "=" + originalId + "+", "orig+", false, false, null));
                variants.add(new PayloadVariant("+" + originalId, paramName + "=+" + originalId, "+orig", false, false, null));
            } else {
                // POST body 使用 + 号代替空格（URL编码格式）
                variants.add(new PayloadVariant(originalId + "+", paramName + "=" + originalId + "+", "orig+", false, false, null));
                variants.add(new PayloadVariant("+" + originalId, paramName + "=+" + originalId, "+orig", false, false, null));
            }
            if (isQuery) {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "+", paramName + "=" + (originalId - 4) + "+", "orig-4+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 4), paramName + "=+" + (originalId - 4), "+orig-4", false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "+", paramName + "=" + (originalId - 10) + "+", "orig-10+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 10), paramName + "=+" + (originalId - 10), "+orig-10", false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "+", paramName + "=" + (originalId - 100) + "+", "orig-100+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 100), paramName + "=+" + (originalId - 100), "+orig-100", false, false, null));
                }
            } else {
                // POST body 使用 + 号代替空格（URL编码格式）
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "+", paramName + "=" + (originalId - 4) + "+", "orig-4+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 4), paramName + "=+" + (originalId - 4), "+orig-4", false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "+", paramName + "=" + (originalId - 10) + "+", "orig-10+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 10), paramName + "=+" + (originalId - 10), "+orig-10", false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "+", paramName + "=" + (originalId - 100) + "+", "orig-100+", false, false, null));
                    variants.add(new PayloadVariant("+" + (originalId - 100), paramName + "=+" + (originalId - 100), "+orig-100", false, false, null));
                }
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                if (isQuery) {
                    variants.add(new PayloadVariant(originalIdStr + "+", paramName + "=" + originalIdStr + "+", "orig+", false, false, null));
                    variants.add(new PayloadVariant("+" + originalIdStr, paramName + "=+" + originalIdStr, "+orig", false, false, null));
                } else {
                    // POST body 使用 + 号代替空格（URL编码格式）
                    variants.add(new PayloadVariant(originalIdStr + "+", paramName + "=" + originalIdStr + "+", "orig+", false, false, null));
                    variants.add(new PayloadVariant("+" + originalIdStr, paramName + "=+" + originalIdStr, "+orig", false, false, null));
                }
                String dec4 = decrementStringNumber(originalIdStr, 4);
                String dec10 = decrementStringNumber(originalIdStr, 10);
                String dec100 = decrementStringNumber(originalIdStr, 100);
                if (isQuery) {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "+", paramName + "=" + dec4 + "+", "orig-4+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec4, paramName + "=+" + dec4, "+orig-4", false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "+", paramName + "=" + dec10 + "+", "orig-10+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec10, paramName + "=+" + dec10, "+orig-10", false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "+", paramName + "=" + dec100 + "+", "orig-100+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec100, paramName + "=+" + dec100, "+orig-100", false, false, null));
                    }
                } else {
                    // POST body 使用 + 号代替空格（URL编码格式）
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "+", paramName + "=" + dec4 + "+", "orig-4+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec4, paramName + "=+" + dec4, "+orig-4", false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "+", paramName + "=" + dec10 + "+", "orig-10+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec10, paramName + "=+" + dec10, "+orig-10", false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "+", paramName + "=" + dec100 + "+", "orig-100+", false, false, null));
                        variants.add(new PayloadVariant("+" + dec100, paramName + "=+" + dec100, "+orig-100", false, false, null));
                    }
                }
            }
        }
        return variants;
    }

    public List<PayloadVariant> generateNonNumericSpaceVariants(String originalValue, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        if (isQuery) {
            variants.add(new PayloadVariant(originalValue + "+", paramName + "=" + originalValue + "+", "orig+", false, false, null));
            variants.add(new PayloadVariant("+" + originalValue, paramName + "=+" + originalValue, "+orig", false, false, null));
        } else {
            variants.add(new PayloadVariant(originalValue + " ", paramName + "=" + originalValue + " ", "orig ", false, false, null));
            variants.add(new PayloadVariant(" " + originalValue, paramName + "= " + originalValue, " orig", false, false, null));
        }
        return variants;
    }

    public List<PayloadVariant> generateUnicodeCRLFVariants(String originalIdStr, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(originalIdStr);
            if (isQuery) {
                variants.add(new PayloadVariant(originalId + "%5cu000D%5cu000A", paramName + "=" + originalId + "%5cu000D%5cu000A", "orig%5cu000D%5cu000A", false, false, null));
            } else {
                variants.add(new PayloadVariant(originalId + "\\u000D\\u000A", paramName + "=" + originalId + "\\u000D\\u000A", "orig\\u000D\\u000A", false, false, null));
            }
            if (isQuery) {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "%5cu000D%5cu000A", paramName + "=" + (originalId - 4) + "%5cu000D%5cu000A", "orig-4%5cu000D%5cu000A", false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "%5cu000D%5cu000A", paramName + "=" + (originalId - 10) + "%5cu000D%5cu000A", "orig-10%5cu000D%5cu000A", false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "%5cu000D%5cu000A", paramName + "=" + (originalId - 100) + "%5cu000D%5cu000A", "orig-100%5cu000D%5cu000A", false, false, null));
                }
            } else {
                if (originalId > 4) {
                    variants.add(new PayloadVariant((originalId - 4) + "\\u000D\\u000A", paramName + "=" + (originalId - 4) + "\\u000D\\u000A", "orig-4\\u000D\\u000A", false, false, null));
                }
                if (originalId > 10) {
                    variants.add(new PayloadVariant((originalId - 10) + "\\u000D\\u000A", paramName + "=" + (originalId - 10) + "\\u000D\\u000A", "orig-10\\u000D\\u000A", false, false, null));
                }
                if (originalId > 100) {
                    variants.add(new PayloadVariant((originalId - 100) + "\\u000D\\u000A", paramName + "=" + (originalId - 100) + "\\u000D\\u000A", "orig-100\\u000D\\u000A", false, false, null));
                }
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(originalIdStr)) {
                if (isQuery) {
                    variants.add(new PayloadVariant(originalIdStr + "%5cu000D%5cu000A", paramName + "=" + originalIdStr + "%5cu000D%5cu000A", "orig%5cu000D%5cu000A", false, false, null));
                } else {
                    variants.add(new PayloadVariant(originalIdStr + "\\u000D\\u000A", paramName + "=" + originalIdStr + "\\u000D\\u000A", "orig\\u000D\\u000A", false, false, null));
                }
                String dec4 = decrementStringNumber(originalIdStr, 4);
                String dec10 = decrementStringNumber(originalIdStr, 10);
                String dec100 = decrementStringNumber(originalIdStr, 100);
                if (isQuery) {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "%5cu000D%5cu000A", paramName + "=" + dec4 + "%5cu000D%5cu000A", "orig-4%5cu000D%5cu000A", false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "%5cu000D%5cu000A", paramName + "=" + dec10 + "%5cu000D%5cu000A", "orig-10%5cu000D%5cu000A", false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "%5cu000D%5cu000A", paramName + "=" + dec100 + "%5cu000D%5cu000A", "orig-100%5cu000D%5cu000A", false, false, null));
                    }
                } else {
                    if (dec4 != null && !dec4.startsWith("-")) {
                        variants.add(new PayloadVariant(dec4 + "\\u000D\\u000A", paramName + "=" + dec4 + "\\u000D\\u000A", "orig-4\\u000D\\u000A", false, false, null));
                    }
                    if (dec10 != null && !dec10.startsWith("-")) {
                        variants.add(new PayloadVariant(dec10 + "\\u000D\\u000A", paramName + "=" + dec10 + "\\u000D\\u000A", "orig-10\\u000D\\u000A", false, false, null));
                    }
                    if (dec100 != null && !dec100.startsWith("-")) {
                        variants.add(new PayloadVariant(dec100 + "\\u000D\\u000A", paramName + "=" + dec100 + "\\u000D\\u000A", "orig-100\\u000D\\u000A", false, false, null));
                    }
                }
            }
        }
        return variants;
    }

    public List<PayloadVariant> generateNonNumericUnicodeCRLFVariants(String originalValue, String paramName, boolean isQuery) {
        List<PayloadVariant> variants = new ArrayList<>();
        if (isQuery) {
            variants.add(new PayloadVariant(originalValue + "%5cu000D%5cu000A", paramName + "=" + originalValue + "%5cu000D%5cu000A", "orig%5cu000D%5cu000A", false, false, null));
        } else {
            variants.add(new PayloadVariant(originalValue + "\\u000D\\u000A", paramName + "=" + originalValue + "\\u000D\\u000A", "orig\\u000D\\u000A", false, false, null));
        }
        return variants;
    }

    // =============== JSON变体生成的辅助方法 ===============

    private List<JsonPayloadVariant> generateJsonZeroPrefixVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();
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
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%s", idStr)), "\"000orig\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%d", id - 4)), "\"000-4\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%d", id - 10)), "\"000-10\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(String.format("000%d", id - 100)), "\"000-100\""));
            } catch (NumberFormatException e) {
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

    private List<JsonPayloadVariant> generateJsonSuffixAVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "a"), "\"origa\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "a"), "\"-4a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "a"), "\"-10a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "a"), "\"-100a\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "a"), "\"origa\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "a"), "\"-4a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "a"), "\"-10a\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "a"), "\"-100a\""));
        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "a"), "\"origa\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "a"), "\"-4a\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "a"), "\"-10a\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "a"), "\"-100a\""));
            } catch (NumberFormatException e) {
                if (isValidDigitString(idStr)) {
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

    private List<JsonPayloadVariant> generateJsonDecimalVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 1) + 0.99999), "-1.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 5) + 0.99999), "-5.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 11) + 0.99999), "-11.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 101) + 0.99999), "-101.99999"));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 1) + 0.99999), "-1.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 5) + 0.99999), "-5.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 11) + 0.99999), "-11.99999"));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.numberNode((id - 101) + 0.99999), "-101.99999"));
        } else if (originalValue.isTextual() && isNumericId(originalValue.asText())) {
            String idStr = originalValue.asText();
            try {
                long id = Long.parseLong(idStr);
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 1) + ".99999"), "\"-1.99999\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 5) + ".99999"), "\"-5.99999\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 11) + ".99999"), "\"-11.99999\""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 101) + ".99999"), "\"-101.99999\""));
            } catch (NumberFormatException e) {
                if (isValidDigitString(idStr)) {
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
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + " "), "\"orig \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + id), "\" orig\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + " "), "\"orig-4 \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + " "), "\"orig-10 \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + " "), "\"orig-100 \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 4)), "\" orig-4\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 10)), "\" orig-10\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 100)), "\" orig-100\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + " "), "\"orig \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + id), "\" orig\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + " "), "\"orig-4 \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + " "), "\"orig-10 \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + " "), "\"orig-100 \""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 4)), "\" orig-4\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 10)), "\" orig-10\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 100)), "\" orig-100\""));
        } else if (originalValue.isTextual()) {
            String idStr = originalValue.asText();
            if (isNumericId(idStr)) {
                try {
                    long id = Long.parseLong(idStr);
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + " "), "\"orig \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + idStr), "\" orig\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + " "), "\"orig-4 \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + " "), "\"orig-10 \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + " "), "\"orig-100 \""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 4)), "\" orig-4\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 10)), "\" orig-10\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + (id - 100)), "\" orig-100\""));
                } catch (NumberFormatException e) {
                }
            } else {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + " "), "\"orig \""));
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(" " + idStr), "\" orig\""));
            }
        }
        return variants;
    }

    private List<JsonPayloadVariant> generateJsonUnicodeCRLFVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "\\u000D\\u000A"), "\"orig\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\\u000D\\u000A"), "\"orig-4\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\\u000D\\u000A"), "\"orig-10\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\\u000D\\u000A"), "\"orig-100\\\\u000D\\\\u000A\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + "\\u000D\\u000A"), "\"orig\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\\u000D\\u000A"), "\"orig-4\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\\u000D\\u000A"), "\"orig-10\\\\u000D\\\\u000A\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\\u000D\\u000A"), "\"orig-100\\\\u000D\\\\u000A\""));
        } else if (originalValue.isTextual()) {
            String idStr = originalValue.asText();
            if (isNumericId(idStr)) {
                try {
                    long id = Long.parseLong(idStr);
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "\\u000D\\u000A"), "\"orig\\\\u000D\\\\u000A\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + "\\u000D\\u000A"), "\"orig-4\\\\u000D\\\\u000A\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + "\\u000D\\u000A"), "\"orig-10\\\\u000D\\\\u000A\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + "\\u000D\\u000A"), "\"orig-100\\\\u000D\\\\u000A\""));
                } catch (NumberFormatException e) {
                }
            } else {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + "\\u000D\\u000A"), "\"orig\\\\u000D\\\\u000A\""));
            }
        }
        return variants;
    }

    private List<JsonPayloadVariant> generateJsonJsonSuffixVariants(JsonNode originalValue) {
        List<JsonPayloadVariant> variants = new ArrayList<>();
        if (originalValue.isInt()) {
            int id = originalValue.asInt();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + ".json"), "\"orig.json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + ".json"), "\"orig-4.json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + ".json"), "\"orig-10.json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + ".json"), "\"orig-100.json\""));
        } else if (originalValue.isLong()) {
            long id = originalValue.asLong();
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(id + ".json"), "\"orig.json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + ".json"), "\"orig-4.json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + ".json"), "\"orig-10.json\""));
            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + ".json"), "\"orig-100.json\""));
        } else if (originalValue.isTextual()) {
            String idStr = originalValue.asText();
            if (isNumericId(idStr)) {
                try {
                    long id = Long.parseLong(idStr);
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + ".json"), "\"orig.json\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 4) + ".json"), "\"orig-4.json\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 10) + ".json"), "\"orig-10.json\""));
                    variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode((id - 100) + ".json"), "\"orig-100.json\""));
                } catch (NumberFormatException e) {
                    if (isValidDigitString(idStr)) {
                        variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + ".json"), "\"orig.json\""));
                        String dec4 = decrementStringNumber(idStr, 4);
                        String dec10 = decrementStringNumber(idStr, 10);
                        String dec100 = decrementStringNumber(idStr, 100);
                        if (dec4 != null && !dec4.startsWith("-")) {
                            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(dec4 + ".json"), "\"orig-4.json\""));
                        }
                        if (dec10 != null && !dec10.startsWith("-")) {
                            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(dec10 + ".json"), "\"orig-10.json\""));
                        }
                        if (dec100 != null && !dec100.startsWith("-")) {
                            variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(dec100 + ".json"), "\"orig-100.json\""));
                        }
                    }
                }
            } else {
                variants.add(new JsonPayloadVariant(JsonNodeFactory.instance.textNode(idStr + ".json"), "\"orig.json\""));
            }
        }
        return variants;
    }

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

    // =============== 路径ID变体生成的辅助方法 ===============

    private List<PathIdVariant> generatePathIdJsonSuffixVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            variants.add(createPathVariant(originalPath, pathId, originalId + ".json", "orig.json"));
            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + ".json", "orig-4.json"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + ".json", "orig-10.json"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + ".json", "orig-100.json"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                variants.add(createPathVariant(originalPath, pathId, idStr + ".json", "orig.json"));
                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec4 + ".json", "orig-4.json"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec10 + ".json", "orig-10.json"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec100 + ".json", "orig-100.json"));
                }
            }
        }
        return variants;
    }

    private List<PathIdVariant> generatePathIdSlashSuffixVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            variants.add(createPathVariant(originalPath, pathId, originalId + "/", "orig/"));
            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "/", "orig-4/"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "/", "orig-10/"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "/", "orig-100/"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                variants.add(createPathVariant(originalPath, pathId, idStr + "/", "orig/"));
                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec4 + "/", "orig-4/"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec10 + "/", "orig-10/"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec100 + "/", "orig-100/"));
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
                variants.add(createPathVariant(originalPath, pathId, commaValue, "orig,orig-4"));
            }
            if (originalId > 10) {
                String commaValue = originalId + "," + (originalId - 10);
                variants.add(createPathVariant(originalPath, pathId, commaValue, "orig,orig-10"));
            }
            if (originalId > 100) {
                String commaValue = originalId + "," + (originalId - 100);
                variants.add(createPathVariant(originalPath, pathId, commaValue, "orig,orig-100"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, idStr + "," + dec4, "orig,orig-4"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, idStr + "," + dec10, "orig,orig-10"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, idStr + "," + dec100, "orig,orig-100"));
                }
            }
        }
        return variants;
    }

    private List<PathIdVariant> generatePathIdHashVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            variants.add(createPathVariant(originalPath, pathId, originalId + "%23", "orig%23"));
            if (originalId > 4) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 4) + "%23", "orig-4%23"));
            }
            if (originalId > 10) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 10) + "%23", "orig-10%23"));
            }
            if (originalId > 100) {
                variants.add(createPathVariant(originalPath, pathId, (originalId - 100) + "%23", "orig-100%23"));
            }
        } catch (NumberFormatException e) {
            if (isValidDigitString(idStr)) {
                variants.add(createPathVariant(originalPath, pathId, idStr + "%23", "orig%23"));
                String dec4 = decrementStringNumber(idStr, 4);
                String dec10 = decrementStringNumber(idStr, 10);
                String dec100 = decrementStringNumber(idStr, 100);
                if (dec4 != null && !dec4.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec4 + "%23", "orig-4%23"));
                }
                if (dec10 != null && !dec10.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec10 + "%23", "orig-10%23"));
                }
                if (dec100 != null && !dec100.startsWith("-")) {
                    variants.add(createPathVariant(originalPath, pathId, dec100 + "%23", "orig-100%23"));
                }
            }
        }
        return variants;
    }

    private List<PathIdVariant> generatePathIdZeroPrefixVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            String originalWithZeros = String.format("000%s", idStr);
            String minus4WithZeros = String.format("000%d", originalId - 4);
            String minus10WithZeros = String.format("000%d", originalId - 10);
            String minus100WithZeros = String.format("000%d", originalId - 100);
            variants.add(createPathVariant(originalPath, pathId, originalWithZeros, "000orig"));
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

    private List<PathIdVariant> generatePathIdSuffixAVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            String originalWithA = originalId + "a";
            variants.add(createPathVariant(originalPath, pathId, originalWithA, "origa"));
            String minus4WithA = (originalId - 4) + "a";
            String minus10WithA = (originalId - 10) + "a";
            String minus100WithA = (originalId - 100) + "a";
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
            if (isValidDigitString(idStr)) {
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

    private List<PathIdVariant> generatePathIdDecimalVariants(String originalPath, PathIdMatch pathId, String idStr) {
        List<PathIdVariant> variants = new ArrayList<>();
        try {
            long originalId = Long.parseLong(idStr);
            if (originalId > 1) {
                String minus1Decimal = (originalId - 1) + ".99999";
                variants.add(createPathVariant(originalPath, pathId, minus1Decimal, "-1.99999"));
            }
            String minus5Decimal = (originalId - 5) + ".99999";
            String minus11Decimal = (originalId - 11) + ".99999";
            String minus101Decimal = (originalId - 101) + ".99999";
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
            if (isValidDigitString(idStr)) {
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

    private List<PathIdVariant> generatePathIdNinesVariants(String originalPath, PathIdMatch pathId) {
        List<PathIdVariant> variants = new ArrayList<>();
        String ninesValue = "999999999999999999999";
        variants.add(createPathVariant(originalPath, pathId, ninesValue, "999s"));
        return variants;
    }
}