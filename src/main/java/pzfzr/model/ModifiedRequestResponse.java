package pzfzr.model;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.Serializable;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;

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

    // 新增：缓存 Len Diff 的计算结果（带符号的字符串）
    private String cachedLenDiff = "Pending";

    private long ResponseTime = -1;
    private String ReflectType = null;
    private String contentType = null;

    private final Logging logging;

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

    public int getStatusCode() {
        return StatusCode;
    }

    public int getModifiedBodyLength() {
        return ModifiedBodyLength;
    }

    public String getReflectType() {
        return ReflectType;
    }

    public long getResponseTime() {
        return ResponseTime;
    }

    public Integer getOriginalMessageId() { return originalMessageId; }

    public String getTestType() { return testType; }

    public String getExpression() {
        return expression;
    }

    public String getPayloadAlias() {
        return payloadAlias;
    }

    public String getTestParameterName() {
        return testParameterName;
    }

    public String getContentType() {
        return contentType;
    }

    public int getModifiedBodyLengthWithoutHeader() {
        return ModifiedBodyLengthWithoutHeader;
    }

    // 新增：获取缓存的 Len Diff
    public String getCachedLenDiff() {
        return cachedLenDiff;
    }

    // 修改：在设置响应时计算并缓存 Len Diff
    public void setModifiedResponseAndCalculateMetadata(Short StatusCode, int ModifiedBodyLength,
                                                        int ModifiedBodyWithoutHeaderLength, String ReflectType,
                                                        long responseTime, String contentType) {
        this.StatusCode = StatusCode;
        this.ModifiedBodyLength = ModifiedBodyLength;
        this.ModifiedBodyLengthWithoutHeader = ModifiedBodyWithoutHeaderLength;
        this.ResponseTime = responseTime;
        this.ReflectType = ReflectType;
        this.contentType = contentType;

        // 计算并缓存 Len Diff（需要传入 TableModel 引用或在 TableModel 中调用专门方法）
        // 这里先保持 Pending，由 TableModel 调用 updateLenDiff 方法更新
    }

    // 新增：由 TableModel 调用以更新 Len Diff
    public void updateLenDiff(int originalLen) {
        if (originalLen != -1 && this.ModifiedBodyLengthWithoutHeader != -1) {
            int diff = this.ModifiedBodyLengthWithoutHeader - originalLen;
            if (diff > 0) {
                this.cachedLenDiff = "+" + diff;
            } else {
                this.cachedLenDiff = String.valueOf(diff);
            }
        } else {
            this.cachedLenDiff = "Pending";
        }
    }

    public void cleanup() {
    }
}