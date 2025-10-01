package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.core.CookieChanger;
import pzfzr.core.NettyManager;
import pzfzr.core.NettyHelper;
import pzfzr.core.RateLimiter;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * ParamAdder - 参数添加器
 * 用于给请求的各种位置添加测试参数：URL参数、POST Body参数、JSON参数
 */
public class ParamAdder {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private volatile boolean isShuttingDown = false;
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;

    // 使用NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // 要添加的参数（可配置）
    private static final String PARAM_NAME_1 = "page";
    private static final String PARAM_VALUE_1 = "88";
    private static final String PARAM_NAME_2 = "size";
    private static final String PARAM_VALUE_2 = "88";

    public ParamAdder(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                      RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();
        this.nextModifiedId = nextModifiedId;

        // 使用NettyManager
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[ParamAdder] Initialization completed using NettyManager client");
    }

    /**
     * 主要的处理方法
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            String method = originalRequest.method().toUpperCase();

            if ("GET".equals(method)) {
                // GET请求：只添加URL参数
                addUrlParameters(originalRequest, messageId, host);
            } else if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                // POST/PUT/PATCH请求：根据Content-Type决定
                String contentType = originalRequest.headerValue("Content-Type");

                if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                    // JSON格式：添加URL参数 + JSON参数
                    addUrlParameters(originalRequest, messageId, host);
                    addJsonParameters(originalRequest, messageId, host);
                } else if (contentType != null && contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
                    // 表单格式：添加URL参数 + Body参数
                    addUrlParameters(originalRequest, messageId, host);
                    addBodyParameters(originalRequest, messageId, host);
                } else {
                    // 其他情况：只添加URL参数
                    addUrlParameters(originalRequest, messageId, host);
                }
            } else {
                // 其他HTTP方法：只添加URL参数
                addUrlParameters(originalRequest, messageId, host);
            }

        } catch (Exception e) {
            logging.logToError("[ParamAdder] processRequest error: " + e.getMessage());
        }
    }

    /**
     * 添加URL参数
     */
    private void addUrlParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 创建两个URL参数
            HttpParameter param1 = HttpParameter.urlParameter(PARAM_NAME_1, PARAM_VALUE_1);
            HttpParameter param2 = HttpParameter.urlParameter(PARAM_NAME_2, PARAM_VALUE_2);

            // 添加参数到请求
            HttpRequest modifiedRequest = originalRequest
                    .withAddedParameters(param1, param2);

            // 构建expression
            String expression = PARAM_NAME_1 + "=" + PARAM_VALUE_1 + "&" + PARAM_NAME_2 + "=" + PARAM_VALUE_2;

            // 发送请求
            sendTestRequest(modifiedRequest, messageId, host, expression, "URL");

        } catch (Exception e) {
            logging.logToError("[ParamAdder] addUrlParameters error: " + e.getMessage());
        }
    }

    /**
     * 添加POST Body参数（表单格式）
     */
    private void addBodyParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 创建两个Body参数
            HttpParameter param1 = HttpParameter.bodyParameter(PARAM_NAME_1, PARAM_VALUE_1);
            HttpParameter param2 = HttpParameter.bodyParameter(PARAM_NAME_2, PARAM_VALUE_2);

            // 添加参数到请求
            HttpRequest modifiedRequest = originalRequest
                    .withAddedParameters(param1, param2);

            // 构建expression
            String expression = PARAM_NAME_1 + "=" + PARAM_VALUE_1 + "&" + PARAM_NAME_2 + "=" + PARAM_VALUE_2;

            // 发送请求
            sendTestRequest(modifiedRequest, messageId, host, expression, "BODY");

        } catch (Exception e) {
            logging.logToError("[ParamAdder] addBodyParameters error: " + e.getMessage());
        }
    }

    /**
     * 添加JSON参数
     */
    private void addJsonParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            String bodyString = originalRequest.bodyToString();
            if (bodyString == null || bodyString.trim().isEmpty()) {
                return;
            }

            // 解析JSON
            JsonNode rootNode = objectMapper.readTree(bodyString);

            // 只处理最外层是对象的情况
            if (!rootNode.isObject()) {
                return;
            }

            // 添加参数到JSON对象
            ObjectNode modifiedJson = (ObjectNode) rootNode.deepCopy();
            modifiedJson.put(PARAM_NAME_1, Integer.parseInt(PARAM_VALUE_1));
            modifiedJson.put(PARAM_NAME_2, Integer.parseInt(PARAM_VALUE_2));

            // 转换回字符串
            String modifiedJsonString = objectMapper.writeValueAsString(modifiedJson);

            // 创建修改后的请求
            HttpRequest modifiedRequest = originalRequest.withBody(modifiedJsonString);

            // 构建expression（JSON格式）
            String expression = "\"" + PARAM_NAME_1 + "\":" + PARAM_VALUE_1 + ",\"" + PARAM_NAME_2 + "\":" + PARAM_VALUE_2;

            // 发送请求
            sendTestRequest(modifiedRequest, messageId, host, expression, "JSON");

        } catch (Exception e) {
            logging.logToError("[ParamAdder] addJsonParameters error: " + e.getMessage());
        }
    }

    /**
     * 发送测试请求
     */
    private void sendTestRequest(HttpRequest modifiedRequest, int messageId, String host,
                                 String expression, String paramType) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
            }

            // 获取令牌（阻塞直到获得令牌）
            rateLimiter.acquire(modifiedRequest.url().split("\\?")[0] + modifiedRequest.method());

            // 生成请求ID
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);

            // 创建ModifiedRequestResponse条目
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "PARAM-ADD",           // testType
                    expression,            // expression: 当前新增的参数和值
                    paramType,             // payloadAlias: URL/BODY/JSON
                    "",                    // parameterName: 留空
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(modifiedRequest, tempID, modifiedPair);

        } catch (Exception e) {
            logging.logToError("[ParamAdder] sendTestRequest error: " + e.getMessage());
        }
    }

    /**
     * 异步发送测试请求 - 使用NettyManager
     */
    private void sendTestRequestAsync(HttpRequest modifiedRequest, int tempID, ModifiedRequestResponse modifiedPair) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 使用NettyManager发送请求
            nettyManager.sendRequest(modifiedRequest, new NettyManager.ResponseCallback() {
                @Override
                public void onResponse(HttpResponse response, long responseTimeMs) {
                    try {
                        // 处理响应（解压等）
                        HttpResponse processedResponse = nettyHelper.processResponse(response);

                        // 调用RequestResponseSaver处理响应
                        requestResponseSaver.handleNettyResponse(processedResponse, tempID, responseTimeMs, modifiedPair);

                    } catch (Exception e) {
                        logging.logToError("[ParamAdder] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[ParamAdder] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });

        } catch (Exception e) {
            logging.logToError("[ParamAdder] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 设置关闭标志
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ParamAdder] Starting shutdown...");

            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作

            logging.logToOutput("[ParamAdder] Shutdown completed");
        }
    }
}