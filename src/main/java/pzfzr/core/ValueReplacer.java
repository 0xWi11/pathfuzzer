package pzfzr.core;
//headerreplacer换成valuereplacer，valuereplacer中三类漏洞分为三个独立的类，每个类各自发请求完成测试，每个类独立清理内存。
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.config.ConfigManager;
import pzfzr.config.KnownTestSets;
import pzfzr.config.SwitchState;
import pzfzr.fuzzer.JsonLister;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.RouteFuzzer;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

public class ValueReplacer {
    private final AtomicInteger nextModifiedId = new AtomicInteger(1);
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final ConfigManager configManager;
    private volatile boolean isShuttingDown = false;

    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int HASH_LENGTH = 5;
    // 定义需要提取值的header名称列表
    private static final Set<String> VALUE_EXTRACT_HEADERS = new HashSet<>(Arrays.asList(
            "vary",
            "access-control-allow-headers"//这里的都要用小写呀
            ,"access-control-expose-headers"
    ));
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging; // 添加 Logging
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger; // 添加 CookieChanger
    private final JsonLister jsonLister; // 添加 JsonLister
    private final RouteFuzzer routeFuzzer;
    private final ParamFuzzer paramFuzzer;



    public ValueReplacer(MontoyaApi api, TableModel tableModel, ConfigManager configManager,
                         RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter) {
        this.api = api;
        this.tableModel = tableModel;
        this.configManager = configManager;
        this.requestResponseSaver = requestResponseSaver; // 接收 RequestResponseSaver 实例
        this.logging = api.logging(); // 初始化 Logging
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance(); // 获取 CookieChanger 单例实例

        // 初始化 JsonLister
        this.jsonLister = new JsonLister(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);

        // 在 ValueReplacer 构造函数中 - 修复：传入nextModifiedId
        this.routeFuzzer = new RouteFuzzer(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);

        this.paramFuzzer = new ParamFuzzer(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);

    }

    /**
     * 获取ParamFuzzer实例，供UI组件使用
     * @return ParamFuzzer实例
     */
    public ParamFuzzer getParamFuzzer() {
        return this.paramFuzzer;
    }

    /**
     * 从请求URL中提取主机部分
     * @param url HTTP请求
     * @return 主机名
     */
    public String extractHostFromRequest(String url) {
//        String url = request.url();
        if (url == null || url.isEmpty()) {
            return "";
        }

        // Remove protocol prefix
        int protocolEnd = url.indexOf("://");
        if (protocolEnd >= 0) {
            url = url.substring(protocolEnd + 3);
        }

        // Extract host (remove path and query)
        int pathStart = url.indexOf('/');
        if (pathStart >= 0) {
            url = url.substring(0, pathStart);
        }

        // Remove port if present
        int portStart = url.indexOf(':');
        if (portStart >= 0) {
            url = url.substring(0, portStart);
        }

        return url;
    }

//    public void collectRequestHeaders(List<HttpHeader> headers) {
//        collectHeaders(headers, "request");
//    }
//
//    public void collectResponseHeaders(List<HttpHeader> headers) {
//        collectHeaders(headers, "response");
//    }
//
//    private void collectHeaders(List<HttpHeader> headers, String headerSource) {
//
//    }

    public void unifiedTest(HttpRequest originalRequest, SwitchState switchState, int messageId) {
        if (isShuttingDown) {
            return;
        }

        // 添加与TrafficHandler中相同的过滤逻辑
        if (configManager.shouldFilter(originalRequest.withBody(""))) {
            return;
        }

        String host = extractHostFromRequest(originalRequest.url());
        try {
            if (switchState.isJsonlisterSwitch()) {
                jsonLister.processRequest(originalRequest, messageId, host);
            }

            if (switchState.isRoutefuzzerSwitch()) {
                routeFuzzer.processRequest(originalRequest, messageId, host);
            }

            if (switchState.isParamfuzzerSwitch()) {
                paramFuzzer.processRequest(originalRequest, messageId, host);
            }
            if (switchState.isKnownSwitch()) {  // 新增
//                KnownTest(originalRequest, messageId, host);
            }
            host = null;
        } catch (Exception e) {
//            api.logging().logToError("Error in unifiedTest: " + e.getMessage());
        }
    }



    public void unifiedTestForContext(HttpRequest originalRequest, SwitchState switchState, int messageId) {
        if (isShuttingDown) {
            return;
        }
        String host = extractHostFromRequest(originalRequest.url());
        try {
            if (switchState.isJsonlisterSwitch()) {
                jsonLister.processRequest(originalRequest, messageId, host);
            }

            if (switchState.isRoutefuzzerSwitch()) {
                routeFuzzer.processRequest(originalRequest, messageId, host);
            }

            if (switchState.isParamfuzzerSwitch()) {
                paramFuzzer.processRequest(originalRequest, messageId, host);
            }
            if (switchState.isKnownSwitch()) {  // 新增
//                KnownTest(originalRequest, messageId, host);
            }
            host = null;
        } catch (Exception e) {
//            api.logging().logToError("Error in unifiedTest: " + e.getMessage());
        }
    }

    public void JsonListerTest(HttpRequest originalRequest, int messageId, String host) {
        jsonLister.processRequest(originalRequest, messageId, host);
    }

    public void RouteFuzzerTest(HttpRequest originalRequest, int messageId, String host) {
        routeFuzzer.processRequestWithoutDeduplication(originalRequest, messageId, host);
    }

    public void ParamFuzzerTest(HttpRequest originalRequest, int messageId, String host) {
        paramFuzzer.processRequest(originalRequest, messageId, host);
    }

    public void KnownTest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) { // 在方法开始处添加检查
            return;
        }
//        api.logging().logToOutput(" KnownTest testing!!!");
        try {

            // 遍历每个测试集
            for (KnownTestSets.TestSet testSet : KnownTestSets.TEST_SETS) {
                if (isShuttingDown) { // 在循环开始处添加检查
                    return;
                }
                try {
                    // 将测试集中的所有header转换为HttpHeader对象列表，并处理 {hash} 替换
                    List<HttpHeader> headers = testSet.getHeaders().entrySet().stream()
                            .map(entry -> {
                                String headerValue = entry.getValue();
                                // 检查 headerValue 中是否包含 {hash} 字符串
                                if (headerValue.contains("{hash}")) {
                                    // 生成随机hash值进行替换
                                    char[] hash = new char[HASH_LENGTH];
                                    for (int i = 0; i < HASH_LENGTH; i++) {
                                        hash[i] = HASH_CHARS.charAt(RANDOM.get().nextInt(HASH_CHARS.length()));  // 使用RANDOM.get()
                                    }
                                    headerValue = headerValue.replace("{hash}", new String(hash));
                                }
                                return HttpHeader.httpHeader(entry.getKey(), headerValue);
                            })
                            .collect(Collectors.toList());

                    // 使用withAddedHeaders一次性添加所有header
                    HttpRequest modifiedRequest = originalRequest.withRemovedHeaders(headers).withAddedHeaders(headers);

                    // 获取并添加认证相关的header
                    List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
                    if (authHeaders != null && !authHeaders.isEmpty()) {
                        modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
                    }

                    rateLimiter.acquire(modifiedRequest.url() + modifiedRequest.method());
                    // 发送修改后的请求
                    HttpRequestResponse modifiedResponse = api.http().sendRequest(modifiedRequest);
                    int tempID = nextModifiedId.getAndIncrement();
                    // 保存修改后的请求和响应
                    ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                            tempID,
                            messageId,
                            "KNOWN",
                            "",
                            "",
                            "",
                            requestResponseSaver, // 传递 requestResponseSaver
                            logging // 传递 logging
                    );
                    tableModel.addModifiedEntry(modifiedPair);
                    requestResponseSaver.saveModifiedRequest(modifiedRequest,tempID);
                    requestResponseSaver.handleDelayedModifiedResponse(modifiedResponse,tempID);
                    modifiedRequest = null;
                    headers = null;
                    modifiedResponse = null;
                } catch (Exception e) {
//                    api.logging().logToError("Error testing set " + testSet.getName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
//            api.logging().logToError("Error in KnownTest: " + e.getMessage());
        }
    }
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
    }
}