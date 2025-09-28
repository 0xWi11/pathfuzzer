package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
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
 * CookieFuzzer - Cookie模糊测试器
 * 测试当前请求的所有cookie，轮流替换单个cookie的值为特定的payload
 */
public class CookieFuzzer {
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

    // 可动态修改的参数数量限制
    private volatile int maxParameterCount = 30;

    // Cookie黑名单 - 这些cookie不进行测试
    private static final Set<String> COOKIE_BLACKLIST = new HashSet<>(Arrays.asList(
            "_ga",
            "aws-waf-token",
            "_fbp",
            "JSESSIONID",
            "PHPSESSID",
            "ASP.NET_SessionId",
            "CFID",
            "CFTOKEN",
            "connect.sid",
            "SESSION",
            "_csrf",
            "_token",
            "XSRF-TOKEN",
            "__RequestVerificationToken",
            "_gid",
            "_gat",
            "_gtm",
            "__utma",
            "__utmb",
            "__utmc",
            "__utmt",
            "__utmv",
            "__utmz",
            "_hjid",
            "_hjIncludedInSample",
            "_hjIncludedInPageviewSample",
            "intercom-id",
            "intercom-session",
            "_mkto_trk",
            "_gcl_au",
            "_gac_gb",
            "_dc_gtm",
            "_ym_uid",
            "_ym_d",
            "yandexuid",
            "_ym_isad",
            "_ym_visorc",
            "hubspotutk",
            "__hssrc",
            "__hstc",
            "__hssc",
            "_vwo_uuid",
            "_vis_opt_s",
            "_vis_opt_test_cookie",
            "_optimizelyEndUserId",
            "optimizelyBuckets",
            "optimizelySegments",
            "_derived_epik",
            "_pinterest_ct_ua",
            "_pin_unauth",
            "_routing_id",
            "personalization_id",
            "guest_id",
            "ct0",
            "_twitter_sess",
            "auth_token",
            "twid",
            "kdt",
            "eu_cn",
            "personalization_id",
            "guest_id_ads",
            "guest_id_marketing"
    ));

    public CookieFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
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

        logging.logToOutput("[CookieFuzzer] Initialization completed using NettyManager client");
    }

    /**
     * 设置最大参数数量限制
     */
    public void setMaxParameterCount(int maxParameterCount) {
        this.maxParameterCount = maxParameterCount;
    }

    /**
     * 获取当前的最大参数数量限制
     */
    public int getMaxParameterCount() {
        return this.maxParameterCount;
    }

    /**
     * 主要的测试方法
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }
        try {
            // 计算cookie数量
            int cookieCount = getCookieCount(originalRequest);

            // 如果cookie数量超过限制，只发送一个原请求
            if (cookieCount > maxParameterCount) {
                sendCookieTooManyRequest(originalRequest, messageId, host);
                return;
            }

            fuzzRequestCookies(originalRequest, messageId, host);
        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 计算请求中的cookie数量
     */
    private int getCookieCount(HttpRequest request) {
        List<ParsedHttpParameter> cookies = request.parameters(HttpParameterType.COOKIE);
        int count = 0;
        for (ParsedHttpParameter cookie : cookies) {
            if (!COOKIE_BLACKLIST.contains(cookie.name())) {
                count++;
            }
        }
        return count;
    }

    /**
     * 发送cookie数量过多的请求
     */
    private void sendCookieTooManyRequest(HttpRequest originalRequest, int messageId, String host) {
        try {
            // 获取并添加认证相关的header
            List<HttpHeader> authHeaders = cookieChanger.getHttpHeadersForHost(host);
            if (authHeaders != null && !authHeaders.isEmpty()) {
                originalRequest = originalRequest.withUpdatedHeaders(authHeaders);
            }

            rateLimiter.acquire(originalRequest.url() + originalRequest.method());

            int tempID = nextModifiedId.getAndIncrement();

            // 保存修改后的请求
            requestResponseSaver.saveModifiedRequest(originalRequest, tempID);

            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "COOKIEFUZZ",
                    "", // expression置空
                    "COOKIETOOMANY", // payloadAlias设置为COOKIETOOMANY
                    "", // parameterName置空
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(originalRequest, tempID, modifiedPair);

        } catch (Exception e) {
            // 静默错误处理
        }
    }

    /**
     * 对请求cookie进行模糊测试
     * 修改为按cookie分组：对每个cookie轮流使用所有payload进行测试
     */
    private void fuzzRequestCookies(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        // 获取原始请求的所有cookie
        List<ParsedHttpParameter> originalCookies = originalRequest.parameters(HttpParameterType.COOKIE);

        // 过滤出可以测试的cookie（不在黑名单中的）
        List<ParsedHttpParameter> testableCookies = new ArrayList<>();
        for (ParsedHttpParameter cookie : originalCookies) {
            if (!COOKIE_BLACKLIST.contains(cookie.name())) {
                testableCookies.add(cookie);
            }
        }

        // 修改：按cookie分组，对每个cookie轮流使用所有payload进行测试
        for (ParsedHttpParameter cookie : testableCookies) {
            if (isShuttingDown) {
                return;
            }

            // 使用PayloadManager获取启用的header payloads（与HeaderFuzzer共享payload）
            for (PayloadInfo payloadInfo : payloadManager.getEnabledHeaderPayloads()) {
                if (isShuttingDown) {
                    return;
                }

                try {
                    String processedPayload = processPayload(payloadInfo.payload, cookie.value());
                    sendTestRequestAsync(originalRequest, messageId, host, cookie.name(), processedPayload, payloadInfo.alias);
                } catch (Exception e) {
                    logging.logToError("[CookieFuzzer] Error testing cookie '" + cookie.name() + "' with payload: " + payloadInfo.alias + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * 异步发送测试请求 - 使用NettyManager
     */
    private void sendTestRequestAsync(HttpRequest originalRequest, int messageId, String host,
                                      String cookieName, String payload, String payloadAlias) {
        if (isShuttingDown) {
            return;
        }

        try {
            // 创建修改后的请求，替换指定cookie的值
            HttpParameter modifiedCookie = HttpParameter.cookieParameter(cookieName, payload);
            HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(modifiedCookie);

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
                    "COOKIEFUZZ",
                    cookieName,        // expression为被替换的cookie名称
                    payloadAlias,      // payload别名
                    cookieName,        // parameterName为cookie名称
                    requestResponseSaver,
                    logging
            );

            // 添加到表格模型
            tableModel.addModifiedEntry(modifiedPair);

            // 使用NettyManager发送请求
            sendTestRequestAsync(modifiedRequest, tempID, modifiedPair);

        } catch (Exception e) {
            logging.logToError("[CookieFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 实际发送请求的方法
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
                        logging.logToError("[CookieFuzzer] Error processing response for ID " + tempID + ": " + e.getMessage());
                    }
                }

                @Override
                public void onError(Throwable error) {
                    logging.logToError("[CookieFuzzer] Request failed for ID " + tempID + ": " + error.getMessage());
                }
            });

        } catch (Exception e) {
            logging.logToError("[CookieFuzzer] sendTestRequestAsync error: " + e.getMessage());
        }
    }

    /**
     * 使用统一的PayloadConstants处理payload
     */
    private String processPayload(String payload, String cookieValue) {
        // 使用统一的PayloadConstants.PayloadProcessor进行通用处理
        return PayloadConstants.PayloadProcessor.processCommonReplacements(payload, cookieValue);
    }

    /**
     * 设置关闭标志
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[CookieFuzzer] Starting shutdown...");

            // NettyManager会自动处理连接关闭
            // 不需要额外的清理工作

            logging.logToOutput("[CookieFuzzer] Shutdown completed");
        }
    }
}