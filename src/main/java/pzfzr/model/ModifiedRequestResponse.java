package pzfzr.model;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.Serializable;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import java.awt.Color;

public class ModifiedRequestResponse implements Serializable {
    private final RequestResponseSaver requestResponseSaver;
    private final int id;
    private final Integer originalMessageId;
    private final String testType;
    private final String expression;
    private final String payloadAlias;
    private final String testParameterName;
    private int StatusCode = -1;
    private int ModifiedBodyLength = -1;
    private int ModifiedBodyLengthWithoutHeader = -1;

    // 缓存原始响应长度，用于计算 Len Diff
    private int cachedOriginalResponseLen = -1;

    // ========== 修改：保存实际的 diff 值用于颜色计算 ==========
    private int actualLenDiff = 0; // 实际的差值（带正负）

    // 缓存 Len Diff 的显示结果（只显示绝对值）
    private String cachedLenDiff = "Pending";

    private long ResponseTime = -1;
    private String ReflectType = null;
    private String contentType = null;

    // 预计算的渲染属性
    private Color payloadBackgroundColor = null;
    private Color lenDiffBackgroundColor = null;
    private Color lenDiffForegroundColor = null;
    private Color statusCodeBackgroundColor = null;
    private Color responseTimeBackgroundColor = null;

    private final Logging logging;

    // 颜色常量
    private static final Color CHAXX_BACKGROUND_COLOR = new Color(217, 217, 217);
    private static final Color NEW_GRAY_BACKGROUND_COLOR = new Color(230, 230, 230);
    private static final Color GREEN_FOREGROUND = new Color(0, 63, 0);
    private static final Color RED_FOREGROUND = new Color(79, 0, 0);
    private static final Color MEDIUM_GRAY = new Color(211, 211, 211);

    public ModifiedRequestResponse(int id, Integer originalMessageId,
                                   String testType, String expression,
                                   String payloadAlias, String testParameterName,
                                   RequestResponseSaver requestResponseSaver, Logging logging) {
        this.id = id;
        this.originalMessageId = originalMessageId;
        this.testType = testType;
        this.expression = expression;
        this.payloadAlias = payloadAlias;
        this.testParameterName = testParameterName;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = logging;

        // 预计算Payload列的背景色
        precomputePayloadBackground();
    }

    // Getters
    public int getId() { return id; }

    public HttpRequest getModifiedRequest() {
        try {
            ByteArray requestData = requestResponseSaver.loadData("ModReq_" + id + ".lz4");
            if (requestData != null) {
                return HttpRequest.httpRequest(requestData);
            }
        } catch (Exception e) {
            logging.logToError("[ModifiedRequestResponse] Failed to load modified request for ID " + id + ": " + e.getMessage());
            return null;
        }
        return null;
    }

    public HttpResponse getModifiedResponse() {
        try {
            ByteArray responseData = requestResponseSaver.loadData("ModResp_" + id + "_" + ResponseTime + ".lz4");
            if (responseData != null) {
                return HttpResponse.httpResponse(responseData);
            }
        } catch (Exception e) {
            logging.logToError("[ModifiedRequestResponse] Failed to load modified response for ID " + id + ": " + e.getMessage());
            return null;
        }
        return null;
    }

    public int getStatusCode() { return StatusCode; }
    public int getModifiedBodyLength() { return ModifiedBodyLength; }
    public String getReflectType() { return ReflectType; }
    public long getResponseTime() { return ResponseTime; }
    public Integer getOriginalMessageId() { return originalMessageId; }
    public String getTestType() { return testType; }
    public String getExpression() { return expression; }
    public String getPayloadAlias() { return payloadAlias; }
    public String getTestParameterName() { return testParameterName; }
    public String getContentType() { return contentType; }
    public int getModifiedBodyLengthWithoutHeader() { return ModifiedBodyLengthWithoutHeader; }
    public String getCachedLenDiff() { return cachedLenDiff; }

    // 获取预计算的渲染属性
    public Color getPayloadBackgroundColor() { return payloadBackgroundColor; }
    public Color getLenDiffBackgroundColor() { return lenDiffBackgroundColor; }
    public Color getLenDiffForegroundColor() { return lenDiffForegroundColor; }
    public Color getStatusCodeBackgroundColor() { return statusCodeBackgroundColor; }
    public Color getResponseTimeBackgroundColor() { return responseTimeBackgroundColor; }

    // ========== 新增：获取实际 diff 值用于排序 ==========
    public int getActualLenDiff() { return actualLenDiff; }

    // ========== 预计算方法 ==========

    private void precomputePayloadBackground() {
        if (payloadAlias == null || testType == null) {
            payloadBackgroundColor = null;
            return;
        }

        String testTypeLower = testType.toLowerCase();

        if ((testTypeLower.equals("route1") || testTypeLower.equals("route2") || testTypeLower.equals("route3"))) {
            if (isInSpecialAliases(payloadAlias)) {
                payloadBackgroundColor = CHAXX_BACKGROUND_COLOR;
                return;
            }
        }

        if (testTypeLower.equals("param") && isInParamSpecialAliases(payloadAlias)) {
            payloadBackgroundColor = CHAXX_BACKGROUND_COLOR;
            return;
        }

        if (testTypeLower.equals("route1") && isInRoute1SpecialAliases(payloadAlias)) {
            payloadBackgroundColor = CHAXX_BACKGROUND_COLOR;
            return;
        }

        if (testTypeLower.equals("param") && isInParamNewSpecialAliases(payloadAlias)) {
            payloadBackgroundColor = NEW_GRAY_BACKGROUND_COLOR;
            return;
        }

        if (testTypeLower.equals("route2") && isInRoute2NewSpecialAliases(payloadAlias)) {
            payloadBackgroundColor = NEW_GRAY_BACKGROUND_COLOR;
            return;
        }

        payloadBackgroundColor = null;
    }

    /**
     * ========== 修改：基于实际 diff 值计算前景色 ==========
     */
    private void precomputeLenDiffColors() {
        lenDiffBackgroundColor = payloadBackgroundColor;

        if (cachedLenDiff != null && !cachedLenDiff.equals("Pending")) {
            // 使用实际的 diff 值判断颜色
            if (actualLenDiff > 0) {
                lenDiffForegroundColor = GREEN_FOREGROUND;
            } else if (actualLenDiff < 0) {
                lenDiffForegroundColor = RED_FOREGROUND;
            } else {
                lenDiffForegroundColor = null; // 0 使用默认颜色
            }
        } else {
            lenDiffForegroundColor = null;
        }
    }

    private void precomputeStatusCodeBackground() {
        if (StatusCode == -1) {
            statusCodeBackgroundColor = null;
            return;
        }
        statusCodeBackgroundColor = TableModel.StatusCodeCellRenderer.getColorForStatusCode(StatusCode);
    }

    private void precomputeResponseTimeBackground() {
        if (ResponseTime > 7000) {
            responseTimeBackgroundColor = MEDIUM_GRAY;
        } else {
            responseTimeBackgroundColor = null;
        }
    }

    public void setModifiedResponseAndCalculateMetadata(Short StatusCode, int ModifiedBodyLength,
                                                        int ModifiedBodyWithoutHeaderLength, String ReflectType,
                                                        long responseTime, String contentType) {
        this.StatusCode = StatusCode;
        this.ModifiedBodyLength = ModifiedBodyLength;
        this.ModifiedBodyLengthWithoutHeader = ModifiedBodyWithoutHeaderLength;
        this.ResponseTime = responseTime;
        this.ReflectType = ReflectType;
        this.contentType = contentType;

        // 如果已经有原始响应长度,重新计算 Len Diff
        if (cachedOriginalResponseLen != -1 && ModifiedBodyWithoutHeaderLength != -1) {
            updateLenDiffInternal(cachedOriginalResponseLen);
        }

        // 预计算渲染相关的颜色
        precomputeStatusCodeBackground();
        precomputeResponseTimeBackground();
        // ========== 移除这里的 precomputeLenDiffColors(),因为 updateLenDiffInternal 中已经调用 ==========
    }

    public void updateLenDiff(int originalLen) {
        cachedOriginalResponseLen = originalLen;
        updateLenDiffInternal(originalLen);
    }

    /**
     * ========== 修改：只显示绝对值 ==========
     */
    /**
     * ========== 修改:只显示绝对值 ==========
     */
    private void updateLenDiffInternal(int originalLen) {
        if (originalLen != -1 && this.ModifiedBodyLengthWithoutHeader != -1) {
            int diff = this.ModifiedBodyLengthWithoutHeader - originalLen;

            // 保存实际的 diff 值(带正负)
            this.actualLenDiff = diff;

            // 显示绝对值
            this.cachedLenDiff = String.valueOf(Math.abs(diff));

            // ========== 关键修复:立即计算颜色 ==========
            precomputeLenDiffColors();
        } else {
            this.actualLenDiff = 0;
            this.cachedLenDiff = "Pending";
            // ========== 也要重新计算颜色 ==========
            precomputeLenDiffColors();
        }
    }

    public void cleanup() {
    }

    // ========== 辅助方法：检查特殊alias集合 ==========

    private static boolean isInSpecialAliases(String alias) {
        return "{path}\\..X8".equals(alias) ||
                "{path}%5c..X8".equals(alias) ||
                "{path}%2f..X8".equals(alias) ||
                "{path}/..X8".equals(alias) ||
                "{path}%252f..X8".equals(alias) ||
                "{path}/%2E%2EX8".equals(alias) ||
                "{path}%2F%2E%2EX8".equals(alias) ||
                "{path}//..X8".equals(alias) ||
                "{path}%2f%2f..X8".equals(alias) ||
                "{path}/..;X8".equals(alias);
    }

    private static boolean isInParamSpecialAliases(String alias) {
        return "{param}\\..X8".equals(alias) ||
                "{param}%5c..X8".equals(alias) ||
                "{param}%2f..X8".equals(alias) ||
                "{param}/..X8".equals(alias) ||
                "{param}%252f..X8".equals(alias) ||
                "{param}/%2E%2EX8".equals(alias) ||
                "{param}%2F%2E%2EX8".equals(alias) ||
                "{param}//..X8".equals(alias) ||
                "{param}%2f%2f..X8".equals(alias) ||
                "{param}/..;X8".equals(alias);
    }

    private static boolean isInRoute1SpecialAliases(String alias) {
        return "ng crlf".equals(alias) ||
                "ng crlf2".equals(alias) ||
                "ng crlf3".equals(alias);
    }

    private static boolean isInParamNewSpecialAliases(String alias) {
        return "{param}%2f..".equals(alias) ||
                "{param}/..".equals(alias) ||
                "{param}%252f..".equals(alias) ||
                "{param}/%2E%2E".equals(alias) ||
                "{param}%2F%2E%2E".equals(alias) ||
                "{param}//..".equals(alias) ||
                "{param}%2f%2f..".equals(alias) ||
                "{param}/..;".equals(alias) ||
                "{param}%5c..".equals(alias) ||
                "{param}\\..".equals(alias);
    }

    private static boolean isInRoute2NewSpecialAliases(String alias) {
        return "{path}%2f..".equals(alias) ||
                "{path}/..".equals(alias) ||
                "{path}%252f..".equals(alias) ||
                "{path}/%2E%2E".equals(alias) ||
                "{path}%2F%2E%2E".equals(alias) ||
                "{path}//..".equals(alias) ||
                "{path}%2f%2f..".equals(alias) ||
                "{path}/..;".equals(alias) ||
                "{path}%5c..".equals(alias) ||
                "{path}\\..".equals(alias);
    }
}