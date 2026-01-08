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
    private final String expression; // 存储变体修改的参数表达式
    private final String payloadAlias; // 新增字段：payload别名
    private final String testParameterName; // 新增字段：当前测试参数的名称
    private int StatusCode = -1;
    private int ModifiedBodyLength = -1;
    private int ModifiedBodyLengthWithoutHeader = -1;

    private long ResponseTime = -1;
    private String ReflectType = null;
    private String contentType = null;

    private final Logging logging;

    // 修改构造函数，添加 payloadAlias 和 testParameterName 参数
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
                return HttpRequest.httpRequest(requestData); // 每次都返回新的 HttpRequest 对象
            }
        } catch (Exception e) {
            logging.logToError("[ModifiedRequestResponse] Failed to load modified request for ID " + id + ": " + e.getMessage());
            return null;
        }
        return null; // 加载失败或数据为空，返回 null
    }

    public HttpResponse getModifiedResponse() {
        try {
            ByteArray responseData = requestResponseSaver.loadData("ModResp_" + id + "_" + ResponseTime + ".lz4");
            if (responseData != null) {
                return HttpResponse.httpResponse(responseData); // 每次都返回新的 HttpResponse 对象
            }
        } catch (Exception e) {
            logging.logToError("[ModifiedRequestResponse] Failed to load modified response for ID " + id + ": " + e.getMessage());
            return null;
        }
        return null; // 加载失败或数据为空，返回 null
    }

    // 修改后的元数据 Getters，返回缓存值
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

    // 获取 expression
    public String getExpression() {
        return expression;
    }

    // 新增方法：获取 payloadAlias
    public String getPayloadAlias() {
        return payloadAlias;
    }

    // 新增方法：获取 testParameterName
    public String getTestParameterName() {
        return testParameterName;
    }
    public String getContentType() {
        return contentType;
    }

    // 设置 ModifiedResponse 并异步计算元数据
    public void setModifiedResponseAndCalculateMetadata(Short StatusCode, int ModifiedBodyLength,
                                                        int ModifiedBodyWithoutHeaderLength, String ReflectType,
                                                        long responseTime, String contentType) {
        this.StatusCode = StatusCode;
        this.ModifiedBodyLength = ModifiedBodyLength;
        this.ModifiedBodyLengthWithoutHeader = ModifiedBodyWithoutHeaderLength;
        this.ResponseTime = responseTime;
        this.ReflectType = ReflectType;
        this.contentType = contentType;
    }

    // 添加资源清理方法，关闭线程池
    public void cleanup() {
    }

    public int getModifiedBodyLengthWithoutHeader() {
        return ModifiedBodyLengthWithoutHeader;
    }
}