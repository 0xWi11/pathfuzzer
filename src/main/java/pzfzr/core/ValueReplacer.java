package pzfzr.core;

import java.util.*;
import java.util.concurrent.*;
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
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer; // 新增：CookieFuzzer导入
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

public class ValueReplacer {
    private final AtomicInteger nextModifiedId = new AtomicInteger(1);
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final ConfigManager configManager;
    private volatile boolean isShuttingDown = false;
    // 添加关闭状态跟踪
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);
    private volatile boolean forceShutdownRequested = false;


    private final RequestResponseSaver requestResponseSaver;
    private final Logging logging;
    private final RateLimiter rateLimiter;
    private final CookieChanger cookieChanger;
    private final JsonLister jsonLister;
    private final RouteFuzzer routeFuzzer;
    private final ParamFuzzer paramFuzzer;
    private final ParamDeleter paramDeleter;
    private final HeaderFuzzer headerFuzzer;
    private final CookieFuzzer cookieFuzzer; // 新增：CookieFuzzer字段

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
        this.paramDeleter = new ParamDeleter(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);
        this.headerFuzzer = new HeaderFuzzer(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId);
        this.cookieFuzzer = new CookieFuzzer(api, tableModel, requestResponseSaver, rateLimiter, nextModifiedId); // 新增：初始化CookieFuzzer
    }

    public ParamFuzzer getParamFuzzer() {
        return this.paramFuzzer;
    }

    public ParamDeleter getParamDeleter() {
        return this.paramDeleter;
    }

    public HeaderFuzzer getHeaderFuzzer() {
        return this.headerFuzzer;
    }

    // 新增：CookieFuzzer的getter方法
    public CookieFuzzer getCookieFuzzer() {
        return this.cookieFuzzer;
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

            if (switchState.isParamdeleterSwitch()) {
                paramDeleter.processRequest(originalRequest, messageId, host);
            }

            if (switchState.isHeaderfuzzerSwitch()) {
                headerFuzzer.processRequest(originalRequest, messageId, host);
            }

            // 新增：CookieFuzzer支持
            if (switchState.isCookiefuzzerSwitch()) {
                cookieFuzzer.processRequest(originalRequest, messageId, host);
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

            if (switchState.isParamdeleterSwitch()) {
                paramDeleter.processRequest(originalRequest, messageId, host);
            }

            if (switchState.isHeaderfuzzerSwitch()) {
                headerFuzzer.processRequest(originalRequest, messageId, host);
            }

            // 新增：CookieFuzzer支持
            if (switchState.isCookiefuzzerSwitch()) {
                cookieFuzzer.processRequest(originalRequest, messageId, host);
            }

            host = null;
        } catch (Exception e) {
            // api.logging().logToError("Error in unifiedTestForContext: " + e.getMessage());
        }
    }

    /**
     * 异步版本的 unifiedTestForContext
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

            if (switchState.isHeaderfuzzerSwitch()) {
                CompletableFuture<Void> headerFuzzerFuture = CompletableFuture.runAsync(() -> {
                    try {
                        headerFuzzer.processRequest(originalRequest, messageId, host);
                    } catch (Exception e) {
                        api.logging().logToError("Error in HeaderFuzzer async execution: " + e.getMessage());
                    }
                }, asyncExecutor);
                futures.add(headerFuzzerFuture);
            }

            // 新增：CookieFuzzer异步支持
            if (switchState.isCookiefuzzerSwitch()) {
                CompletableFuture<Void> cookieFuzzerFuture = CompletableFuture.runAsync(() -> {
                    try {
                        cookieFuzzer.processRequest(originalRequest, messageId, host);
                    } catch (Exception e) {
                        api.logging().logToError("Error in CookieFuzzer async execution: " + e.getMessage());
                    }
                }, asyncExecutor);
                futures.add(cookieFuzzerFuture);
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


    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;

        if (shuttingDown) {
            logging.logToOutput("[ValueReplacer] Starting to shut down all components...");
            // 异步执行关闭过程，避免阻塞调用线程
            CompletableFuture.runAsync(this::performShutdown);
        }
    }

    private void performShutdown() {
        try {
            // 设置所有子组件的关闭状态
            shutdownSubComponents();

            // 等待异步任务完成或超时
            if (!forceShutdownRequested) {
                waitForTasksCompletion();
            }

            // 关闭线程池
            shutdownExecutors();

        } catch (Exception e) {
            logging.logToError("[ValueReplacer] Error during shutdown: " + e.getMessage());
        } finally {
            shutdownLatch.countDown();
            logging.logToOutput("[ValueReplacer] All components shut down completely");        }
    }

    private void shutdownSubComponents() {
        // 并行关闭子组件，提高效率
        List<CompletableFuture<Void>> shutdownFutures = new ArrayList<>();

        shutdownFutures.add(CompletableFuture.runAsync(() -> {
            try {
                if (jsonLister != null) {
                    jsonLister.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] Error shutting down JsonLister: " + e.getMessage());
            }
        }));

        shutdownFutures.add(CompletableFuture.runAsync(() -> {
            try {
                if (routeFuzzer != null) {
                    routeFuzzer.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] Error shutting down RouteFuzzer: " + e.getMessage());
            }
        }));

        shutdownFutures.add(CompletableFuture.runAsync(() -> {
            try {
                if (paramFuzzer != null) {
                    paramFuzzer.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] Error shutting down ParamFuzzer: " + e.getMessage());
            }
        }));

        shutdownFutures.add(CompletableFuture.runAsync(() -> {
            try {
                if (paramDeleter != null) {
                    paramDeleter.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] Error shutting down ParamDeleter: " + e.getMessage());
            }
        }));

        shutdownFutures.add(CompletableFuture.runAsync(() -> {
            try {
                if (headerFuzzer != null) {
                    headerFuzzer.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] Error shutting down HeaderFuzzer: " + e.getMessage());
            }
        }));

        // 新增：CookieFuzzer关闭
        shutdownFutures.add(CompletableFuture.runAsync(() -> {
            try {
                if (cookieFuzzer != null) {
                    cookieFuzzer.setShuttingDown(true);
                }
            } catch (Exception e) {
                logging.logToError("[ValueReplacer] Error shutting down CookieFuzzer: " + e.getMessage());
            }
        }));

        // 等待所有子组件关闭完成，最多等待5秒
        try {
            CompletableFuture.allOf(shutdownFutures.toArray(new CompletableFuture[0]))
                    .get(5, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            logging.logToOutput("[ValueReplacer] Sub-component shutdown timed out, proceeding with the rest of the shutdown process");
        } catch (Exception e) {
            logging.logToError("[ValueReplacer] Error while waiting for sub-components to shut down: " + e.getMessage());
        }
    }

    private void waitForTasksCompletion() {
        try {
            // 检查是否还有正在执行的任务
            if (asyncExecutor instanceof ThreadPoolExecutor) {
                ThreadPoolExecutor executor = (ThreadPoolExecutor) asyncExecutor;
                int maxWaitSeconds = 10;

                for (int i = 0; i < maxWaitSeconds; i++) {
                    if (executor.getActiveCount() == 0 && executor.getQueue().isEmpty()) {
                        logging.logToOutput("[ValueReplacer] All asynchronous tasks completed");
                        break;
                    }

                    if (forceShutdownRequested) {
                        logging.logToOutput("[ValueReplacer] Received force shutdown request, stopping wait");
                        break;
                    }

                    Thread.sleep(1000);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logging.logToOutput("[ValueReplacer] Waiting for tasks to complete was interrupted");
        }
    }

    private void shutdownExecutors() {
        try {
            asyncExecutor.shutdown();

            if (!asyncExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                logging.logToOutput("[ValueReplacer] Graceful shutdown timed out, force shutting down async executor");
                asyncExecutor.shutdownNow();

                if (!asyncExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                    logging.logToError("[ValueReplacer] Force shutdown of async executor failed");
                }
            }
        } catch (InterruptedException e) {
            logging.logToError("[ValueReplacer] Shutdown of async executor was interrupted");
            asyncExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            logging.logToError("[ValueReplacer] Error while shutting down async executor: " + e.getMessage());
        }
    }

    // 强制关闭方法
    public void forceShutdown() {
        forceShutdownRequested = true;

        if (asyncExecutor != null) {
            asyncExecutor.shutdownNow();
        }

        // 强制完成关闭过程
        shutdownLatch.countDown();
    }

    // 等待关闭完成
    public boolean awaitShutdown(long timeout, TimeUnit unit) {
        try {
            return shutdownLatch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}