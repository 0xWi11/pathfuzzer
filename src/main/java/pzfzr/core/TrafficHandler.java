package pzfzr.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import pzfzr.config.ConfigManager;
import pzfzr.config.SwitchManager;
import pzfzr.config.SwitchState;
import pzfzr.model.OriginalRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import burp.api.montoya.core.ToolType;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;

public class TrafficHandler implements HttpHandler {
    private final MontoyaApi api;
    private final ValueReplacer valueReplacer;
    private final TableModel tableModel;
    private final ConfigManager configManager;
    private final SwitchManager switchManager;
    // 线程池参数配置
    private static final int CORE_POOL_SIZE = 10;
    private static final int MAX_POOL_SIZE = 20;
    private static final long KEEP_ALIVE_TIME = 60L;
    // 使用单个ScheduledExecutorService处理所有任务
    private final ScheduledExecutorService executorService;
    private final Map<Integer, DelayedResponse> pendingResponses = new ConcurrentHashMap<>();
    private volatile boolean isShuttingDown = false;
    private final RequestDeduplicator requestDeduplicator; // 请求去重器实例
    private ThreadPoolMonitor threadPoolMonitor;


    private static class DelayedResponse {
        final HttpResponseReceived response;
        final long timestamp;
        int retryCount;
        final String url;

        DelayedResponse(HttpResponseReceived response) {
            this.response = response;
            this.timestamp = System.currentTimeMillis();
            this.retryCount = 0;
            this.url = response.initiatingRequest().url();
        }
    }
    private final RequestResponseSaver requestResponseSaver;


    public TrafficHandler(MontoyaApi api, ValueReplacer valueReplacer, TableModel tableModel, ConfigManager configManager, RequestResponseSaver requestResponseSaver) {
        this.api = api;
        this.valueReplacer = valueReplacer;
        this.tableModel = tableModel;
        this.configManager = configManager;
        this.switchManager = SwitchManager.getInstance();
        this.requestResponseSaver = requestResponseSaver; // 接收 RequestResponseSaver 实例
        this.requestDeduplicator = RequestDeduplicator.getInstance(api.logging()); // 初始化请求去重器

        // 创建自定义配置的线程池
        this.executorService = new ScheduledThreadPoolExecutor(
                CORE_POOL_SIZE,
                new ThreadFactory() {
                    private final AtomicInteger threadNumber = new AtomicInteger(1);

                    @Override
                    public Thread newThread(Runnable r) {
                        Thread thread = new Thread(r, "traffic-handler-thread-" + threadNumber.getAndIncrement());
                        thread.setDaemon(true);
                        return thread;
                    }
                }
        );

        // 配置线程池参数
        ((ScheduledThreadPoolExecutor) executorService).setMaximumPoolSize(MAX_POOL_SIZE);
        ((ScheduledThreadPoolExecutor) executorService).setKeepAliveTime(KEEP_ALIVE_TIME, TimeUnit.SECONDS);

        // 添加任务拒绝处理器
        ((ScheduledThreadPoolExecutor) executorService).setRejectedExecutionHandler(
                (r, executor) -> api.logging().logToError("[TrafficHandler] Task rejected: thread pool overloaded")
        );
        // 初始化并启动线程池监控
        this.threadPoolMonitor = new ThreadPoolMonitor(api, executorService);
        this.threadPoolMonitor.startMonitoring(); // 使用默认参数启动
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!requestToBeSent.toolSource().isFromTool(ToolType.PROXY)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        if (isShuttingDown) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        // 始终收集请求头
        if (!switchManager.isMasterSwitch()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
//        valueReplacer.collectRequestHeaders(requestToBeSent.headers());
        // 检查主开关状态
        if (configManager.shouldFilter(requestToBeSent.withBody(""))) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        // 请求去重检查
        if (requestDeduplicator.shouldSkipRequest(requestToBeSent.method(), requestToBeSent.url(),"request")) {
            return RequestToBeSentAction.continueWith(requestToBeSent); // 如果去重器判断应该跳过，则直接返回
        }
        if (requestToBeSent.toolSource().isFromTool(ToolType.PROXY)) {
            tableModel.createEntry(new OriginalRequestResponse(
                            requestToBeSent.method(),
                            requestToBeSent.url(),
                            requestToBeSent.messageId(),
                            requestResponseSaver, api.logging())
                    ,requestToBeSent.messageId());
            SwitchState currentState = switchManager.getCurrentState();
            executorService.execute(() -> {
                try {
                    // 创建原始请求记录
                    requestResponseSaver.saveOriginalRequest(requestToBeSent,requestToBeSent.messageId());
                    // 将请求和开关状态传入统一测试方法
                    valueReplacer.unifiedTest(requestToBeSent, currentState, requestToBeSent.messageId());
//                    api.logging().logToOutput("Created request entry for: " + requestToBeSent.url());
                } catch (Exception e) {
                    api.logging().logToError("[TrafficHandler] Error processing request: " + e.getMessage());
                }
            });
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        if (isShuttingDown) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        if (!switchManager.isMasterSwitch()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
//        valueReplacer.collectResponseHeaders(responseReceived.headers());

        if (configManager.shouldFilter(responseReceived.initiatingRequest())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        if (responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
            if (!(requestDeduplicator.shouldSkipRequest(responseReceived.initiatingRequest().method(),
                    responseReceived.initiatingRequest().url(),"response"))) {

                // 添加异常捕获 - 主要修改部分
                try {
                    OriginalRequestResponse original = tableModel.findByMessageId(responseReceived.messageId());
                    if (original != null) {
                        original.setOriginalResponse(responseReceived);
                    } else {
                        api.logging().logToError("[TrafficHandler] Cannot find OriginalRequestResponse entry for messageId: " +
                                responseReceived.messageId() + ", URL: " + responseReceived.initiatingRequest().url());
                    }
                } catch (NullPointerException e) {
                    api.logging().logToError("[TrafficHandler] NullPointerException when setting original response for messageId: " +
                            responseReceived.messageId() + ", URL: " + responseReceived.initiatingRequest().url() +
                            ", Error: " + e.getMessage());
                } catch (Exception e) {
                    api.logging().logToError("[TrafficHandler] Unexpected error when setting original response for messageId: " +
                            responseReceived.messageId() + ", URL: " + responseReceived.initiatingRequest().url() +
                            ", Error: " + e.getMessage());
                }
            }
//            processResponse(responseReceived);
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }
    // Add this method to the TrafficHandler class
    public void clearAllTasks() {
        try {
            // Get the queue from the executor service
            if (executorService instanceof ScheduledThreadPoolExecutor) {
                ScheduledThreadPoolExecutor executor = (ScheduledThreadPoolExecutor) executorService;
                int queueSize = executor.getQueue().size();
                executor.getQueue().clear();
                api.logging().logToOutput("[TrafficHandler] Cleared " + queueSize + " pending tasks from the queue");
            } else {
                api.logging().logToOutput("[TrafficHandler] The executorService is not a ScheduledThreadPoolExecutor, cannot clear tasks");
            }
        } catch (Exception e) {
            api.logging().logToError("[TrafficHandler] Error clearing tasks: " + e.getMessage());
        }
    }
    public void cancelActiveThreads() {
        try {
            if (executorService instanceof ScheduledThreadPoolExecutor) {
                ScheduledThreadPoolExecutor executor = (ScheduledThreadPoolExecutor) executorService;
                int activeCount = executor.getActiveCount();

                if (activeCount > 0) {
                    // Use reflection to access the workers field of ThreadPoolExecutor
                    Field workersField = ThreadPoolExecutor.class.getDeclaredField("workers");
                    workersField.setAccessible(true);

                    // Get the set of Worker objects
                    Set<?> workers = (Set<?>) workersField.get(executor);
                    int interruptedCount = 0;

                    if (workers != null) {
                        // Create a copy to avoid ConcurrentModificationException
                        Set<?> workersCopy = new HashSet<>(workers);

                        for (Object worker : workersCopy) {
                            // Access the thread field of the Worker class
                            Field threadField = worker.getClass().getDeclaredField("thread");
                            threadField.setAccessible(true);

                            // Get the thread and interrupt it if it's running
                            Thread thread = (Thread) threadField.get(worker);
                            if (thread != null && thread.getState() == Thread.State.RUNNABLE) {
                                thread.interrupt();
                                interruptedCount++;
                            }
                        }
                    }

                    api.logging().logToOutput("[TrafficHandler] Successfully interrupted " +
                            interruptedCount + " out of " + activeCount +
                            " active tasks. Queue will continue processing.");
                } else {
                    api.logging().logToOutput("[TrafficHandler] No active tasks to cancel.");
                }
            } else {
                api.logging().logToOutput("[TrafficHandler] The executorService is not a ScheduledThreadPoolExecutor, cannot cancel active tasks");
            }
        } catch (Exception e) {
            api.logging().logToError("[TrafficHandler] Error cancelling active tasks: " + e.getMessage() +
                    "\n" + e.getStackTrace()[0]);
        }
    }

    // 在插件卸载时调用此方法
    public void shutdown() {
        isShuttingDown = true;
        api.logging().logToOutput("[TrafficHandler] Traffic Handler starting shutdown process...");
        clearAllTasks();
        // 关闭监控器
        if (threadPoolMonitor != null) {
            threadPoolMonitor.shutdown();
        }
        // 关闭线程池
        executorService.shutdownNow(); //  更改为 shutdownNow 立即关闭
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) { //  等待一段时间，以便记录错误信息 (可选)
                api.logging().logToError("[TrafficHandler] Traffic Handler pool did not terminate in 5 seconds after shutdownNow.");
            }
        } catch (InterruptedException e) {
            api.logging().logToError("[TrafficHandler] Traffic Handler shutdown interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        // 清理剩余资源
        pendingResponses.clear();
        if (requestDeduplicator != null) { // 关闭请求去重器
            requestDeduplicator.shutdown();
        }

    }
}