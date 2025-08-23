package pzfzr.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;

public class OriginalRequestResponse {
    private final Integer messageId;
    private final String originalMethod;
    private final String originalUrl;
    private int OriginalResponseLen = -1;
    private int OriginalResponseLenWithoutHeader = -1;

    private final RequestResponseSaver requestResponseSaver;
    // 移除 transient HttpRequest loadedOriginalRequest; 和 transient HttpResponse loadedOriginalResponse;
    private final Logging logging;

    public OriginalRequestResponse(String Method, String Url, Integer messageId, RequestResponseSaver requestResponseSaver, Logging logging) {
        this.messageId = messageId;
        this.originalMethod = Method;
        this.originalUrl = Url;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = logging;
    }

    // Getters
    // 修改 getOriginalRequest 方法，每次都重新加载
    public HttpRequest getOriginalRequest() {
        try {
            ByteArray requestData = requestResponseSaver.loadData("OrigReq_" + messageId + ".lz4");
            if (requestData != null) {
                return HttpRequest.httpRequest(requestData); // 每次都返回新的 HttpRequest 对象
            }
        } catch (Exception e) {
            logging.logToError("[OriginalRequestResponse] Failed to load original request for messageID " + messageId + ": " + e.getMessage());
            return null; // 加载失败返回 null
        }
        return null;
    }

    // 修改 getOriginalResponse 方法，每次都重新加载
    public HttpResponse getOriginalResponse() {
        try {
            ByteArray responseData = requestResponseSaver.loadData("OrigResp_" + messageId + ".lz4");
            if (responseData != null) {
                return HttpResponse.httpResponse(responseData); // 每次都返回新的 HttpResponse 对象
            }
        } catch (Exception e) {
            logging.logToError("[OriginalRequestResponse] Failed to load original response for messageID " + messageId + ": " + e.getMessage());
            return null; // 加载失败返回 null
        }
        return null;
    }

    public Integer getMessageId() { return messageId; }

    public void setOriginalResponse(HttpResponse originalResponse) {
        // 修改为使用完整响应长度减去Set-Cookie值的长度
        this.OriginalResponseLen = calculateResponseLengthWithoutSetCookieValues(originalResponse);
        this.OriginalResponseLenWithoutHeader = originalResponse.body().length(); // 直接设置长度
        requestResponseSaver.saveOriginalResponse(originalResponse, messageId);
    }

    public int getOriginalResponseLenWithoutHeader() {
        return OriginalResponseLenWithoutHeader;
    }
    public String getOriginalMethod() {
        return originalMethod; // 直接返回构造函数中初始化的值
    }

    public String getOriginalUrl() {
        return originalUrl; // 直接返回构造函数中初始化的值
    }

    public int getOriginalResponseLen() {
        return OriginalResponseLen;
    }

    /**
     * 计算响应长度，包括header，但排除Set-Cookie header的值部分
     * @param response HTTP响应
     * @return 计算后的长度
     */
    private int calculateResponseLengthWithoutSetCookieValues(HttpResponse response) {
        if (response == null) {
            return -1;
        }

        // 获取完整响应的原始字节数组
        byte[] fullResponse = response.toByteArray().getBytes();
        int totalLength = fullResponse.length;

        // 计算需要减去的Set-Cookie值的总长度
        int setCookieValuesLength = 0;

        for (HttpHeader header : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                // 只计算值的长度，不包括header名称和冒号空格
                setCookieValuesLength += header.value().length();
            }
        }

        return totalLength - setCookieValuesLength;
    }
}