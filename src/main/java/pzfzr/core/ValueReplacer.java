package pzfzr.core;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.config.ConfigManager;
import pzfzr.config.SwitchState;
import pzfzr.fuzzer.JsonLister;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
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
    private static final Set<String> VALUE_EXTRACT_HEADERS = new HashSet<>(Arrays.asList(
            "vary",
            "access-control-allow-headers",
            "access-control-expose-headers"
    ));

    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final JsonLister jsonLister;
    private final RouteFuzzer routeFuzzer;
    private final ParamFuzzer paramFuzzer;
    private final ParamDeleter paramDeleter; // 新增

    // 添加专门用于异步执行的线程池
    private final ExecutorService asyncExecutor = Executors.newFixedThreadPool(8);

    public ValueReplacer(MontoyaApi api, TableModel tableModel, ConfigManager configManager,
                         RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter) {
        this.api = api;
        this.tableModel = tableModel;
        this.configManager = configManager;
        this.requestResponseSaver = requestResponseSaver;
        this.logging = api.logging();
        this.rateLimiter = rateLimiter;
        this.cookieChanger = CookieChanger.getInstance();

        this.jsonLister = new JsonLister(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);
        this.routeFuzzer = new RouteFuzzer(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);
        this.paramFuzzer = new ParamFuzzer(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);
        this.paramDeleter = new ParamDeleter(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId); // 新增
    }

    public ParamFuzzer getParamFuzzer() {
        return this.paramFuzzer;
    }

    // 新增getter方法
    public ParamDeleter getParamDeleter() {
        return this.paramDeleter;
    }

    public String extractHostFromRequest(String url) {
        if (url == null || url.isEmpty()) {
            return "";
        }

        int protocolEnd = url.indexOf("://");
        if (protocolEnd >= 0) {
            url = url.substring(protocolEnd + 3);
        }

        int pathStart = url.indexOf('/');
        if (pathStart >= 0) {
            url = url.substring(0, pathStart);
        }

        int portStart = url.indexOf(':');
        if (portStart >= 0) {
            url = url.substring(0, portStart);
        }

        return url;
    }

    public void unifiedTest(HttpRequest originalRequest, SwitchState switchState, int messageId) {
        if (isShuttingDown) {
            return;
        }

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

            // 新增ParamDeleter支持
            if (switchState.isParamdeleterSwitch()) {
                paramDeleter.processRequest(originalRequest, messageId, host);
            }

            host = null;
        } catch (Exception e) {
            // api.logging().logToError("Error in unifiedTest: " + e.getMessage());
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
                routeFuzzer.processRequestWithoutDeduplication(originalRequest, messageId, host);
            }

            if (switchState.isParamfuzzerSwitch()) {
                paramFuzzer.processRequest(originalRequest, messageId, host);
            }

            // 新增ParamDeleter支持
            if (switchState.isParamdeleterSwitch()) {
                paramDeleter.processRequest(originalRequest, messageId, host);
            }

            host = null;
        } catch (Exception e) {
            // api.logging().logToError("Error in unifiedTestForContext: " + e.getMessage());
        }
    }

    /**
     * 异步版本的 unifiedTestForContext - 新增方法
     * 每个测试类型都在独立的异步任务中执行，避免相互阻塞
     */
    public CompletableFuture<Void> unifiedTestForContextAsync(HttpRequest originalRequest, SwitchState switchState, int messageId) {
        if (isShuttingDown) {
            return CompletableFuture.completedFuture(null);
        }

        String host = extractHostFromRequest(originalRequest.url());
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        try {
            // 为每个启用的测试类型创建独立的异步任务
            if (switchState.isJsonlisterSwitch()) {
                CompletableFuture<Void> jsonListerFuture = CompletableFuture.runAsync(() -> {
                    try {
                        jsonLister.processRequest(originalRequest, messageId, host);
                    } catch (Exception e) {
                        api.logging().logToError("Error in JsonLister async execution: " + e.getMessage());
                    }
                }, asyncExecutor);
                futures.add(jsonListerFuture);
            }

            if (switchState.isRoutefuzzerSwitch()) {
                CompletableFuture<Void> routeFuzzerFuture = CompletableFuture.runAsync(() -> {
                    try {
                        routeFuzzer.processRequestWithoutDeduplication(originalRequest, messageId, host);
                    } catch (Exception e) {
                        api.logging().logToError("Error in RouteFuzzer async execution: " + e.getMessage());
                    }
                }, asyncExecutor);
                futures.add(routeFuzzerFuture);
            }

            if (switchState.isParamfuzzerSwitch()) {
                CompletableFuture<Void> paramFuzzerFuture = CompletableFuture.runAsync(() -> {
                    try {
                        paramFuzzer.processRequest(originalRequest, messageId, host);
                    } catch (Exception e) {
                        api.logging().logToError("Error in ParamFuzzer async execution: " + e.getMessage());
                    }
                }, asyncExecutor);
                futures.add(paramFuzzerFuture);
            }

            // 新增ParamDeleter异步支持
            if (switchState.isParamdeleterSwitch()) {
                CompletableFuture<Void> paramDeleterFuture = CompletableFuture.runAsync(() -> {
                    try {
                        paramDeleter.processRequest(originalRequest, messageId, host);
                    } catch (Exception e) {
                        api.logging().logToError("Error in ParamDeleter async execution: " + e.getMessage());
                    }
                }, asyncExecutor);
                futures.add(paramDeleterFuture);
            }

            // 返回一个组合的 CompletableFuture，当所有任务完成时完成
            return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .whenComplete((result, throwable) -> {
                        if (throwable != null) {
                            api.logging().logToError("Error in unified test async execution: " + throwable.getMessage());
                        }
                        // 清理host变量
                        // host = null; // 注意：不能在这里设置为null，因为这是异步回调
                    });

        } catch (Exception e) {
            api.logging().logToError("Error setting up async unified test: " + e.getMessage());
            return CompletableFuture.completedFuture(null);
        }
    }

    /**
     * 异步版本的单独测试方法 - 新增
     */
    public CompletableFuture<Void> JsonListerTestAsync(HttpRequest originalRequest, int messageId, String host) {
        return CompletableFuture.runAsync(() -> {
            try {
                jsonLister.processRequest(originalRequest, messageId, host);
            } catch (Exception e) {
                api.logging().logToError("Error in JsonListerTestAsync: " + e.getMessage());
            }
        }, asyncExecutor);
    }

    public CompletableFuture<Void> RouteFuzzerTestAsync(HttpRequest originalRequest, int messageId, String host) {
        return CompletableFuture.runAsync(() -> {
            try {
                routeFuzzer.processRequestWithoutDeduplication(originalRequest, messageId, host);
            } catch (Exception e) {
                api.logging().logToError("Error in RouteFuzzerTestAsync: " + e.getMessage());
            }
        }, asyncExecutor);
    }

    public CompletableFuture<Void> ParamFuzzerTestAsync(HttpRequest originalRequest, int messageId, String host) {
        return CompletableFuture.runAsync(() -> {
            try {
                paramFuzzer.processRequest(originalRequest, messageId, host);
            } catch (Exception e) {
                api.logging().logToError("Error in ParamFuzzerTestAsync: " + e.getMessage());
            }
        }, asyncExecutor);
    }

    // 新增ParamDeleter异步测试方法
    public CompletableFuture<Void> ParamDeleterTestAsync(HttpRequest originalRequest, int messageId, String host) {
        return CompletableFuture.runAsync(() -> {
            try {
                paramDeleter.processRequest(originalRequest, messageId, host);
            } catch (Exception e) {
                api.logging().logToError("Error in ParamDeleterTestAsync: " + e.getMessage());
            }
        }, asyncExecutor);
    }

    // 保持原有的同步版本的单独测试方法
    public void JsonListerTest(HttpRequest originalRequest, int messageId, String host) {
        jsonLister.processRequest(originalRequest, messageId, host);
    }

    public void RouteFuzzerTest(HttpRequest originalRequest, int messageId, String host) {
        routeFuzzer.processRequestWithoutDeduplication(originalRequest, messageId, host);
    }

    public void ParamFuzzerTest(HttpRequest originalRequest, int messageId, String host) {
        paramFuzzer.processRequest(originalRequest, messageId, host);
    }

    // 新增ParamDeleter同步测试方法
    public void ParamDeleterTest(HttpRequest originalRequest, int messageId, String host) {
        paramDeleter.processRequest(originalRequest, messageId, host);
    }

    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ValueReplacer] 开始关闭所有组件...");

            // 首先设置所有子组件的关闭状态
            try {
                if (jsonLister != null) {
                    jsonLister.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] 关闭JsonLister时出错: " + e.getMessage());
            }

            try {
                if (routeFuzzer != null) {
                    routeFuzzer.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] 关闭RouteFuzzer时出错: " + e.getMessage());
            }

            try {
                if (paramFuzzer != null) {
                    paramFuzzer.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] 关闭ParamFuzzer时出错: " + e.getMessage());
            }

            // 新增ParamDeleter关闭逻辑
            try {
                if (paramDeleter != null) {
                    paramDeleter.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] 关闭ParamDeleter时出错: " + e.getMessage());
            }

            // 等待一段时间让子组件完成关闭
            try {
                Thread.sleep(2000); // 等待2秒，让子组件有时间完成关闭
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // 关闭异步执行器
            try {
                asyncExecutor.shutdown();

                // 等待执行器关闭（最多等待5秒）
                if (!asyncExecutor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                    logging.logToOutput("[ValueReplacer] 强制关闭异步执行器");
                    asyncExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                logging.logToError("[ValueReplacer] 关闭异步执行器时被中断");
                asyncExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] 关闭异步执行器时出错: " + e.getMessage());
            }

            logging.logToOutput("[ValueReplacer] 所有组件关闭完成");
        }
    }
}