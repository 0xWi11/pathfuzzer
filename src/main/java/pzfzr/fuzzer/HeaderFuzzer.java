package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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

/**
 * HeaderFuzzer - Header模糊测试器
 * 测试当前请求的自定义header，替换掉自定义header的值为特定的payload
 */
public class HeaderFuzzer {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private volatile boolean isShuttingDown = false;
    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final PayloadManager payloadManager;

    // 使用NettyManager
    private final NettyManager nettyManager;
    private final NettyHelper nettyHelper;

    // Header黑名单 - 这些header不进行测试
    private static final Set<String> HEADER_BLACKLIST = new HashSet<>(Arrays.asList(
            "Host",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-Dest",
            "Accept-Encoding",
            "Accept-Language",
            "Priority",
            "Connection",
            "Access-Control-Allow-Origin",
            "Vary",
            "Access-Control-Allow-Credentials",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Date",
            "Content-Type",
            "X-Xss-Protection",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Alt-Svc",
            "Sec-Ch-Ua-Full-Version-List",
            "Sec-Ch-Ua-Platform",
            "Sec-Ch-Ua",
            "Sec-Ch-Ua-Bitness",
            "Sec-Ch-Ua-Model",
            "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Form-Factors",
            "Sec-Ch-Ua-Wow64",
            "Sec-Ch-Ua-Arch",
            "Sec-Ch-Ua-Full-Version",
            "Sec-Ch-Ua-Platform-Version",
            "Cache-Control",
            "P3p",
            "Cross-Origin-Resource-Policy",
            "Pragma",
            "Expires",
            "Content-Disposition",
            "Strict-Transport-Security",
            "Access-Control-Expose-Headers",
            "Set-Cookie",
            "Upgrade",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Accept",
            "Content-Security-Policy",
            "Accept-Ch",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Permissions-Policy",
            "Via",
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-User",
            "Etag",
            "If-None-Match",
            "Accept-Ranges",
            "Last-Modified",
            "Cross-Origin-Opener-Policy-Report-Only",
            "Age",
            "Referrer-Policy",
            "Content-Security-Policy-Report-Only",
            "Sec-Mesh-Client-Edge-Version",
            "Sec-Mesh-Client-Edge-Channel",
            "Sec-Mesh-Client-Os",
            "Sec-Mesh-Client-Os-Version",
            "Sec-Mesh-Client-Arch",
            "Sec-Mesh-Client-Webview",
            "sec-websocket-accept",
            "upgrade",
            "ETag",
            "Content-MD5",
            "P3P",
            "Sec-Ch-Prefers-Color-Scheme",
            "Alt-Used",
            "Keep-Alive",
            "Sec-CH-UA-Arch",
            "Sec-CH-UA-Bitness",
            "Sec-CH-UA-Full-Version",
            "Sec-CH-UA-Model",
            "Sec-CH-UA-WoW64",
            "Sec-CH-UA-Form-Factors",
            "Sec-CH-UA-Platform",
            "Content-Length",
            "Te",
            "If-Modified-Since",
            "If-Match",
            "If-Unmodified-Since",
            "Range",
            "proxy-connection",
            "Cookie",
            "\\",
            "Content-Encoding",
            "Access-Control-Allow-Method",
            "null",
            "Expect-Ct",
            "Cf-Cache-Status",
            "Cf-Ray",
            "Cf-Mitigated",
            "Cf-Chl-Ra",
            "Cf-Chl",
            "Cf-Chl-Gen",
            "Cf-Chl-Out-S",
            "Cf-Chl-Out",
            "accept-encoding",
            "x-timestamp",
            "Accept",
            "allow",
            "Sec-Fetch-Storage-Access",
            "referrer-policy",
            "vary",
            "content-type",
            "etag",
            "Allow",
            "if-modified-since",
            "if-none-match",
            "accept-language",
            "If-Range",
            "Content-Language",
            "access-control-allow-headers",
            "access-control-max-age",
            "access-control-allow-methods",
            "Cf-Bgj",
            "User-Agent",
            "Transfer-Encoding",
            "Server-Timing",
            "cache-control",
            "X-Goog-Stored-Content-Encoding",
            "X-Goog-Stored-Content-Length",
            "Authorization",
            "X-XSS-Protection",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-expose-headers",
            "last-modified",
            "expires",
            "set-cookie",
            "Content-Digest",
            "x-xss-protection",
            "content-length",
            "DNT",
            "Cf-Resized",
            "Cf-Ipcountry",
            "cf-cache-status",
            "CF-RAY",
            "Cf-Polished",
            "Cf-Edge-Cache",
            "authorization",
            "Mnpg-Session-Id",
            "X-Csrf-Token",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "via",
            "sec-ch-ua-platform",
            "sec-ch-ua-model",
            "sec-ch-ua-mobile",
            "sec-fetch-site",
            "accept",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "priority",
            "RSC",
            "Rsc",
            "access-control-request-method",
            "access-control-request-headers",
            "connection",
            "range",
            "Access-Control-Max-Age",
            "content-disposition",
            "X-Auth-Token",
            "X-Content-Options",
            "Content-Range",
            "Sec-WebSocket-Protocol",
            "X-Download-Options",
            "accept-ranges",
            "cross-origin-opener-policy",
            "content-language",
            "X-Amz-Cf-Pop",
            "X-Amz-Cf-Id",
            "traceparent",
            "Retry-After",
            "retry-after",
            "Cache-control",
            "content-encoding",
            "Link",
            "Location",
            "Content-Transfer-Encoding"
    ));

    public HeaderFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                        RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();

        this.nextModifiedId = nextModifiedId;
        this.payloadManager = PayloadManager.getInstance();

        // 使用NettyManager
        this.nettyManager = NettyManager.getInstance();
        this.nettyHelper = new NettyHelper(logging, api.utilities().compressionUtils(), nettyManager);

        logging.logToOutput("[HeaderFuzzer] Initialization completed using NettyManager client");
    }

    /**
     * 主要的测试方法
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            fuzzRequestHeaders(originalRequest, messageId, host);
        } catch (Exception e) {
            logging.logToError("[HeaderFuzzer] processRequest error: " + e.getMessage());
        }
    }

    /**
     * 对请求头进行模糊测试
     */
    private void fuzzRequestHeaders(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        // 获取原始请求的所有header
        List<HttpHeader> originalHeaders = originalRequest.headers();

        // 过滤出可以测试的header（不在黑名单中的）
        List<HttpHeader> testableHeaders = new ArrayList<>();
        for (HttpHeader header : originalHeaders) {
            if (!HEADER_BLACKLIST.contains(header.name())) {
                testableHeaders.add(header);
            }
        }

        // 使用PayloadManager获取启用的header payloads
        for (PayloadInfo payloadInfo : payloadManager.getEnabledHeaderPayloads()) {
            if (isShuttingDown) {
                return;
            }

            // 对每个可测试的header进行测试
            for (HttpHeader header : testableHeaders) {
                if (isShuttingDown) {
                    return;
                }

                try {
                    String processedPayload = processPayload(payloadInfo.payload, header.value());
                    sendTestRequestAsync(originalRequest, messageId, host, header.name(), processedPayload, payloadInfo.alias);
                } catch (Exception e) {
                    logging.logToError("[HeaderFuzzer] Error testing header '" + header.name() + "' with payload: " + payloadInfo.alias + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * 异步发送测试请求 - 使用NettyManager
     */
    private void sendTestRequestAsync(HttpRequest originalRequest, int messageId, String host,
                                      String headerName, String payload, String payloadAlias) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 创建修改后的请求，替换指定header的值
            HttpHeader modifiedHeader = HttpHeader.httpHeader(headerName, payload);
            HttpRequest modifiedRequest = originalRequest.withUpdatedHeader(modifiedHeader);

            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                modifiedRequest = modifiedRequest.withUpdatedHeaders(authHeaders);
            }

            // 获取令牌（阻塞直到获得令牌）
            rateLimiter.acquire(originalRequest.url() + modifiedRequest.method());

            // 生成请求ID
            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);

            // 创建ModifiedRequestResponse条目
            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "HEADERFUZZ",
                    headerName,        // expression为被替换的header名称
                    payloadAlias,      // payload别名
                    headerName,        // parameterName为header名称
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
                        // 处理响应（解压等）
                        HttpResponse processedResponse = nettyHelper.processResponse(response);

                        // 调用RequestResponseSaver处理响应
                        requestResponseSaver.handleNettyResponse(processedResponse, tempID, responseTimeMs, modifiedPair);

                    } catch (Exception e) {
                        logging.logToError("[HeaderFuzzer] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[HeaderFuzzer] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });

        } catch (Exception e) {
            logging.logToError("[HeaderFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 使用统一的PayloadConstants处理payload
     */
    private String processPayload(String payload, String headerValue) {
        // 使用统一的PayloadConstants.PayloadProcessor进行通用处理
        return PayloadConstants.PayloadProcessor.processCommonReplacements(payload, headerValue);
    }

    /**
     * 设置关闭标志
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[HeaderFuzzer] Starting shutdown...");

            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作

            logging.logToOutput("[HeaderFuzzer] Shutdown completed");
        }
    }
}