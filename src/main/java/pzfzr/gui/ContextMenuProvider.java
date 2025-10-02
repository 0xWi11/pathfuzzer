package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import pzfzr.config.ConfigManager;
import pzfzr.config.FilterRule;
import pzfzr.config.PluginConfigManager;
import pzfzr.config.SwitchState;
import pzfzr.core.ParamCollector;
import pzfzr.core.ValueReplacer;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.model.OriginalRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class ContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final ValueReplacer valueReplacer;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final ConfigManager configManager;
    private final PluginConfigManager pluginConfigManager;
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    private final AtomicInteger messageIdGenerator = new AtomicInteger(5000000);

    // 添加任务管理相关字段
    private final TaskManager taskManager;
    private final AtomicLong taskIdGenerator = new AtomicLong(1);
    private final ParamCollector paramCollector;


    public ContextMenuProvider(MontoyaApi api, ValueReplacer valueReplacer, TableModel tableModel,
                               RequestResponseSaver requestResponseSaver, ParamCollector paramCollector) {
        this.api = api;
        this.valueReplacer = valueReplacer;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.configManager = ConfigManager.getInstance();
        this.pluginConfigManager = PluginConfigManager.getInstance();
        this.taskManager = new TaskManager(api, 5);
        this.paramCollector = paramCollector; // 新增
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 获取当前请求响应对象 - 支持两种上下文
        HttpRequestResponse requestResponse = null;
        List<HttpRequestResponse> allSelectedRequests = new ArrayList<>();

        // 首先检查消息编辑器上下文（请求包内右键）
        Optional<MessageEditorHttpRequestResponse> messageEditor = event.messageEditorRequestResponse();
        if (messageEditor.isPresent() && messageEditor.get().requestResponse() != null) {
            requestResponse = messageEditor.get().requestResponse();
            allSelectedRequests.add(requestResponse);
        }
        // 然后检查选择的请求响应列表（HTTP历史记录右键）
        else {
            List<HttpRequestResponse> selectedRequestResponses = event.selectedRequestResponses();
            if (!selectedRequestResponses.isEmpty()) {
                requestResponse = selectedRequestResponses.get(0);
                allSelectedRequests.addAll(selectedRequestResponses);
            }
        }

        // 如果没有找到有效的请求响应，不显示菜单
        if (requestResponse == null || requestResponse.request() == null) {
            return menuItems;
        }

        final List<HttpRequestResponse> finalAllSelectedRequests = new ArrayList<>(allSelectedRequests);

        // 创建子菜单 - 使用配置的名称
        String menuName = pluginConfigManager.getContextMenuName();
        JMenu headerIntruderMenu = new JMenu(menuName);

        // 获取当前任务状态信息
        int activeTasks = taskManager.getActiveTaskCount();
        int queuedTasks = taskManager.getQueuedTaskCount();

        // 如果有正在执行的任务，在菜单中显示状态
        if (activeTasks > 0 || queuedTasks > 0) {
            JMenuItem statusItem = new JMenuItem(String.format("Task Status: %d running, %d queued", activeTasks, queuedTasks));
            statusItem.setEnabled(false);
            headerIntruderMenu.add(statusItem);

            // 添加取消任务选项
            JMenuItem cancelItem = new JMenuItem("Cancel All Tasks");
            cancelItem.addActionListener(e -> {
                int result = JOptionPane.showConfirmDialog(
                        null,
                        String.format("取消 %d 个正在执行和 %d 个等待中的任务？", activeTasks, queuedTasks),
                        "取消任务",
                        JOptionPane.YES_NO_OPTION
                );
                if (result == JOptionPane.YES_OPTION) {
                    taskManager.cancelAllTasks();
                    api.logging().logToOutput("All tasks have been cancelled");
                }
            });
            headerIntruderMenu.add(cancelItem);
            headerIntruderMenu.addSeparator();
        }

        // 获取插件配置状态
        PluginConfigManager.SwitchConfigState configState = pluginConfigManager.getSwitchConfigState();

        // 添加各种测试选项 - 根据配置动态创建菜单
        // 1. 全部测试（但只包括配置启用的测试）
        if (hasAnyTestEnabled(configState)) {
            JMenuItem allTests = createTestMenuItem("Run All Tests", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState allEnabledState = createConfigBasedSwitchState(configState, true);
                        return valueReplacer.unifiedTestForContextAsync(request, allEnabledState, messageId);
                    });
            headerIntruderMenu.add(allTests);
        }

        // 添加过滤器菜单项 - 这个不需要异步，保持原有逻辑
        JMenuItem addFilterItem = new JMenuItem(String.format("Add Filter (%d 个已选择)", finalAllSelectedRequests.size()));
        addFilterItem.addActionListener(e -> addFiltersSync(finalAllSelectedRequests));
        headerIntruderMenu.add(addFilterItem);
        headerIntruderMenu.addSeparator();

        // 只在 ParamCollector 启用时才添加参数收集菜单项
        if (paramCollector != null) {
            JMenuItem collectParamsItem = new JMenuItem(String.format("Collect Parameters (%d 个已选择)", finalAllSelectedRequests.size()));
            collectParamsItem.addActionListener(e -> collectParameters(finalAllSelectedRequests));
            headerIntruderMenu.add(collectParamsItem);
        }

        headerIntruderMenu.addSeparator();


        // 2. 组合测试菜单
        if (isRouteTestAvailable(configState)) {
            JMenuItem routeTestCombo = createTestMenuItem("Run Route Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState routeTestState = new SwitchState(false,
                                configState.isJsonListerEnabled(),
                                configState.isRouteFuzzerEnabled(),
                                configState.isParamFuzzerEnabled(),
                                configState.isParamDeleterEnabled(),
                                configState.isParamAdderEnabled(), // 新增
                                false, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, routeTestState, messageId);
                    });
            headerIntruderMenu.add(routeTestCombo);
        }

        if (isOOBTestAvailable(configState)) {
            JMenuItem oobTestCombo = createTestMenuItem("Run OOB Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState oobTestState = new SwitchState(false, false, false, false, false, false,
                                configState.isHeaderFuzzerEnabled(),
                                configState.isCookieFuzzerEnabled(),
                                configState.isOOBParamFuzzerEnabled());
                        return valueReplacer.unifiedTestForContextAsync(request, oobTestState, messageId);
                    });
            headerIntruderMenu.add(oobTestCombo);
        }

        if (isRouteTestAvailable(configState) || isOOBTestAvailable(configState)) {
            headerIntruderMenu.addSeparator();
        }

        if (configState.isJsonListerEnabled()) {
            JMenuItem JsonListerTest = createTestMenuItem("JsonLister Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState jsonListerOnlyState = new SwitchState(false, true, false, false, false, false, false, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, jsonListerOnlyState, messageId);
                    });
            headerIntruderMenu.add(JsonListerTest);
        }

        if (configState.isRouteFuzzerEnabled()) {
            JMenuItem routeFuzzerTest = createTestMenuItem("RouteFuzzer Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState routeFuzzerOnlyState = new SwitchState(false, false, true, false, false, false, false, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, routeFuzzerOnlyState, messageId);
                    });
            headerIntruderMenu.add(routeFuzzerTest);
        }

        if (configState.isParamFuzzerEnabled()) {
            JMenuItem ParamFuzzerTest = createTestMenuItem("ParamFuzzer Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState paramFuzzerOnlyState = new SwitchState(false, false, false, true, false, false, false, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, paramFuzzerOnlyState, messageId);
                    });
            headerIntruderMenu.add(ParamFuzzerTest);
        }

        if (configState.isParamDeleterEnabled()) {
            JMenuItem ParamDeleterTest = createTestMenuItem("ParamDeleter Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState paramDeleterOnlyState = new SwitchState(false, false, false, false, true, false, false, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, paramDeleterOnlyState, messageId);
                    });
            headerIntruderMenu.add(ParamDeleterTest);
        }

        // 新增：ParamAdder测试菜单项
        if (configState.isParamAdderEnabled()) {
            JMenuItem ParamAdderTest = createTestMenuItem("ParamAdder Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState paramAdderOnlyState = new SwitchState(false, false, false, false, false, true, false, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, paramAdderOnlyState, messageId);
                    });
            headerIntruderMenu.add(ParamAdderTest);
        }

        if (configState.isHeaderFuzzerEnabled()) {
            JMenuItem HeaderFuzzerTest = createTestMenuItem("HeaderFuzzer Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState headerFuzzerOnlyState = new SwitchState(false, false, false, false, false, false, true, false, false);
                        return valueReplacer.unifiedTestForContextAsync(request, headerFuzzerOnlyState, messageId);
                    });
            headerIntruderMenu.add(HeaderFuzzerTest);
        }

        if (configState.isCookieFuzzerEnabled()) {
            JMenuItem CookieFuzzerTest = createTestMenuItem("CookieFuzzer Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState cookieFuzzerOnlyState = new SwitchState(false, false, false, false, false, false, false, true, false);
                        return valueReplacer.unifiedTestForContextAsync(request, cookieFuzzerOnlyState, messageId);
                    });
            headerIntruderMenu.add(CookieFuzzerTest);
        }

        if (configState.isOOBParamFuzzerEnabled()) {
            JMenuItem OOBParamFuzzerTest = createTestMenuItem("OOBParamFuzzer Test", finalAllSelectedRequests,
                    (request, messageId) -> {
                        SwitchState oobParamFuzzerOnlyState = new SwitchState(false, false, false, false, false, false, false, false, true);
                        return valueReplacer.unifiedTestForContextAsync(request, oobParamFuzzerOnlyState, messageId);
                    });
            headerIntruderMenu.add(OOBParamFuzzerTest);
        }

        // 添加子菜单到列表
        menuItems.add(headerIntruderMenu);

        return menuItems;
    }

    /**
     * 检查是否有任何测试被启用
     */
    private boolean hasAnyTestEnabled(PluginConfigManager.SwitchConfigState configState) {
        return configState.isJsonListerEnabled() || configState.isRouteFuzzerEnabled() ||
                configState.isParamFuzzerEnabled() || configState.isParamDeleterEnabled() ||
                configState.isParamAdderEnabled() || // 新增
                configState.isHeaderFuzzerEnabled() || configState.isCookieFuzzerEnabled() ||
                configState.isOOBParamFuzzerEnabled();
    }

    /**
     * 检查Route测试是否可用
     */
    private boolean isRouteTestAvailable(PluginConfigManager.SwitchConfigState configState) {
        return configState.isJsonListerEnabled() || configState.isRouteFuzzerEnabled() ||
                configState.isParamFuzzerEnabled() || configState.isParamDeleterEnabled();
    }

    /**
     * 检查OOB测试是否可用
     */
    private boolean isOOBTestAvailable(PluginConfigManager.SwitchConfigState configState) {
        return configState.isHeaderFuzzerEnabled() || configState.isCookieFuzzerEnabled() ||
                configState.isOOBParamFuzzerEnabled();
    }

    /**
     * 根据配置创建SwitchState
     */
    private SwitchState createConfigBasedSwitchState(PluginConfigManager.SwitchConfigState configState, boolean enableAll) {
        return new SwitchState(
                false, // masterSwitch一般设置为false
                enableAll && configState.isJsonListerEnabled(),
                enableAll && configState.isRouteFuzzerEnabled(),
                enableAll && configState.isParamFuzzerEnabled(),
                enableAll && configState.isParamDeleterEnabled(),
                enableAll && configState.isParamAdderEnabled(), // 新增
                enableAll && configState.isHeaderFuzzerEnabled(),
                enableAll && configState.isCookieFuzzerEnabled(),
                enableAll && configState.isOOBParamFuzzerEnabled()
        );
    }

    /**
     * 创建带任务管理的测试菜单项
     */
    private JMenuItem createTestMenuItem(String testName, List<HttpRequestResponse> requests, AsyncTestExecutor testExecutor) {
        String menuText = String.format("%s (%d 个已选择)", testName, requests.size());
        JMenuItem menuItem = new JMenuItem(menuText);

        menuItem.addActionListener(e -> {
            // 检查是否可以添加新任务
            if (taskManager.canAcceptNewTask()) {
                long taskId = taskIdGenerator.getAndIncrement();
                BatchTestTask task = new BatchTestTask(taskId, testName, requests, testExecutor);

                boolean submitted = taskManager.submitTask(task);
                if (submitted) {
                    // 改为日志输出，不显示弹窗
                    api.logging().logToOutput(String.format("[%s] Task submitted: %s, %d requests (Task ID: %d)",
                            pluginConfigManager.getContextMenuName(), testName, requests.size(), taskId));
                } else {
                    showTaskRejectedMessage(testName, "Task queue is full. Please wait for current tasks to finish.");
                }
            } else {
                showTaskRejectedMessage(testName, "Too many tasks are running. Please wait for current tasks to complete.");
            }
        });

        return menuItem;
    }

    /**
     * 同步版本的添加过滤器方法
     */
    private void addFiltersSync(List<HttpRequestResponse> requests) {
        // 原有的添加过滤器逻辑，保持同步执行
        try {
            int successCount = 0;
            int errorCount = 0;

            for (HttpRequestResponse reqRes : requests) {
                try {
                    if (reqRes != null && reqRes.request() != null) {
                        String fullUrl = reqRes.request().url();
                        String baseUrl = fullUrl.split("\\?")[0];

                        boolean ruleExists = configManager.getFilterRules().stream()
                                .anyMatch(rule -> rule.getValue().equals(baseUrl) &&
                                        rule.getType() == FilterRule.RuleType.URL &&
                                        rule.getMatchType() == FilterRule.RuleMatchType.CONTAINS);

                        if (!ruleExists) {
                            FilterRule filterRule = new FilterRule(
                                    baseUrl,
                                    FilterRule.RuleType.URL,
                                    FilterRule.RuleMatchType.CONTAINS
                            );

                            configManager.addFilterRule(filterRule);
                            successCount++;
                            api.logging().logToOutput(String.format("[%s] Added filter rule: %s",
                                    pluginConfigManager.getContextMenuName(), baseUrl));
                        }
                    }
                } catch (Exception ex) {
                    errorCount++;
                    api.logging().logToError(String.format("[%s] Error processing request: %s",
                            pluginConfigManager.getContextMenuName(), ex.getMessage()));
                }
            }

            showBatchResult("过滤器规则", requests.size(), successCount, errorCount);

        } catch (Exception ex) {
            api.logging().logToError(String.format("[%s] Error adding filter rule: %s",
                    pluginConfigManager.getContextMenuName(), ex.getMessage()));
            showErrorMessage("添加过滤器规则时发生错误: " + ex.getMessage());
        }
    }

    /**
     * 显示任务被拒绝消息
     */
    private void showTaskRejectedMessage(String testName, String reason) {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(
                    null,
                    String.format("无法启动 %s: %s", testName, reason),
                    "任务被拒绝",
                    JOptionPane.WARNING_MESSAGE
            );
        });
    }

    private void showBatchResult(String operation, int totalRequests, int successCount, int errorCount) {
        SwingUtilities.invokeLater(() -> {
            String message;
            int messageType;

            if (errorCount == 0) {
                if (successCount == totalRequests) {
                    message = String.format("成功处理了 %d 个%s", successCount, operation);
                } else {
                    int duplicateCount = totalRequests - successCount;
                    message = String.format("处理了 %d 个新%s。%d 个已经存在。",
                            successCount, operation, duplicateCount);
                }
                messageType = JOptionPane.INFORMATION_MESSAGE;
            } else {
                message = String.format("处理了 %d 个%s，发生 %d 个错误",
                        successCount, operation, errorCount);
                messageType = JOptionPane.WARNING_MESSAGE;
            }

            JOptionPane.showMessageDialog(null, message, operation + " 结果", messageType);
        });
    }

    private void showErrorMessage(String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(null, errorMessage, "错误", JOptionPane.ERROR_MESSAGE);
        });
    }
    private void collectParameters(List<HttpRequestResponse> requests) {
        // 显示确认对话框
        int result = JOptionPane.showConfirmDialog(
                null,
                String.format("开始收集 %d 个请求的参数？\n这可能需要一些时间。", requests.size()),
                "确认收集参数",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            // 异步执行收集
            paramCollector.collectParamsAsync(requests).thenRun(() -> {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                            null,
                            String.format("参数收集完成！\n总共收集了 %d 个参数。", paramCollector.getParamCount()),
                            "收集完成",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                });
            }).exceptionally(ex -> {
                api.logging().logToError("[ContextMenu] Error collecting parameters: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                            null,
                            "参数收集时发生错误: " + ex.getMessage(),
                            "错误",
                            JOptionPane.ERROR_MESSAGE
                    );
                });
                return null;
            });

            api.logging().logToOutput(String.format("[ContextMenu] Started collecting parameters from %d requests", requests.size()));
        }
    }
    public void shutdown() {
        taskManager.shutdown();
        executor.shutdown();
    }

    /**
     * 异步测试执行器接口
     */
    @FunctionalInterface
    private interface AsyncTestExecutor {
        CompletableFuture<Void> execute(burp.api.montoya.http.message.requests.HttpRequest request, int messageId);
    }

    /**
     * 批量测试任务类
     */
    private class BatchTestTask implements Runnable {
        private final long taskId;
        private final String testName;
        private final List<HttpRequestResponse> requests;
        private final AsyncTestExecutor testExecutor;
        private volatile boolean cancelled = false;

        public BatchTestTask(long taskId, String testName, List<HttpRequestResponse> requests, AsyncTestExecutor testExecutor) {
            this.taskId = taskId;
            this.testName = testName;
            this.requests = new ArrayList<>(requests); // 创建副本避免并发修改
            this.testExecutor = testExecutor;
        }

        @Override
        public void run() {
            if (cancelled) {
                return;
            }

            api.logging().logToOutput(String.format("[%s] [Task %d] Starting batch %s with %d requests",
                    pluginConfigManager.getContextMenuName(), taskId, testName, requests.size()));

            List<CompletableFuture<Void>> futures = new ArrayList<>();
            int processedCount = 0;
            int errorCount = 0;

            try {
                for (HttpRequestResponse reqRes : requests) {
                    if (cancelled) {
                        api.logging().logToOutput(String.format("[%s] [Task %d] Cancelled",
                                pluginConfigManager.getContextMenuName(), taskId));
                        return;
                    }

                    if (reqRes != null && reqRes.request() != null) {
                        try {
                            int messageId = messageIdGenerator.getAndIncrement();
                            OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                            reqRes.request().method(),
                                            reqRes.request().url(),
                                            messageId,
                                            requestResponseSaver, api.logging()),
                                    messageId);

                            if (original != null) {
                                // 异步发送原始请求
                                CompletableFuture<Void> originalRequestFuture = CompletableFuture.runAsync(() -> {
                                    try {
                                        HttpRequestResponse originalReqRes = api.http().sendRequest(reqRes.request());
                                        if (originalReqRes != null && originalReqRes.response() != null) {
                                            original.setOriginalResponse(originalReqRes.response());
                                        }
                                    } catch (Exception ex) {
                                        api.logging().logToError(String.format("[%s] [Task %d] Error sending original request: %s",
                                                pluginConfigManager.getContextMenuName(), taskId, ex.getMessage()));
                                    }
                                }, executor);

                                // 执行具体的测试
                                CompletableFuture<Void> testFuture = testExecutor.execute(reqRes.request(), messageId);

                                futures.add(CompletableFuture.allOf(originalRequestFuture, testFuture));
                                processedCount++;
                            }
                        } catch (Exception ex) {
                            errorCount++;
                            api.logging().logToError(String.format("[%s] [Task %d] Error processing request: %s",
                                    pluginConfigManager.getContextMenuName(), taskId, ex.getMessage()));
                        }
                    }
                }

                // 等待所有任务完成
                CompletableFuture<Void> allTasks = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
                allTasks.get(30, TimeUnit.MINUTES); // 设置30分钟超时

                // 改为日志输出，不显示弹窗
                if (!cancelled) {
                    api.logging().logToOutput(String.format("[%s] [Task %d] Task completed: %s - Processed %d requests, with %d errors",
                            pluginConfigManager.getContextMenuName(), taskId, testName, processedCount, errorCount));
                }

            } catch (TimeoutException e) {
                api.logging().logToError(String.format("[%s] [Task %d] %s timed out after 30 minutes",
                        pluginConfigManager.getContextMenuName(), taskId, testName));
            } catch (Exception e) {
                api.logging().logToError(String.format("[%s] [Task %d] Error during batch execution: %s",
                        pluginConfigManager.getContextMenuName(), taskId, e.getMessage()));
            }
        }

        public void cancel() {
            this.cancelled = true;
        }

        public long getTaskId() {
            return taskId;
        }
    }

    /**
     * 任务管理器
     */
    private static class TaskManager {
        private final ExecutorService taskExecutor;
        private final Semaphore taskSemaphore;
        private final MontoyaApi api;
        private final ConcurrentHashMap<Long, BatchTestTask> activeTasks = new ConcurrentHashMap<>();
        private final BlockingQueue<BatchTestTask> taskQueue = new ArrayBlockingQueue<>(10);

        public TaskManager(MontoyaApi api, int maxConcurrentTasks) {
            this.api = api;
            this.taskExecutor = Executors.newFixedThreadPool(maxConcurrentTasks);
            this.taskSemaphore = new Semaphore(maxConcurrentTasks);
        }

        public boolean canAcceptNewTask() {
            return taskSemaphore.availablePermits() > 0 || taskQueue.remainingCapacity() > 0;
        }

        public boolean submitTask(BatchTestTask task) {
            if (taskSemaphore.tryAcquire()) {
                // 可以立即执行
                activeTasks.put(task.getTaskId(), task);
                taskExecutor.submit(() -> {
                    try {
                        task.run();
                    } finally {
                        activeTasks.remove(task.getTaskId());
                        taskSemaphore.release();
                        // 检查队列中是否有等待的任务
                        processQueuedTask();
                    }
                });
                return true;
            } else if (taskQueue.remainingCapacity() > 0) {
                // 加入队列等待
                return taskQueue.offer(task);
            } else {
                // 无法接受更多任务
                return false;
            }
        }

        private void processQueuedTask() {
            BatchTestTask queuedTask = taskQueue.poll();
            if (queuedTask != null && taskSemaphore.tryAcquire()) {
                activeTasks.put(queuedTask.getTaskId(), queuedTask);
                taskExecutor.submit(() -> {
                    try {
                        queuedTask.run();
                    } finally {
                        activeTasks.remove(queuedTask.getTaskId());
                        taskSemaphore.release();
                        processQueuedTask(); // 递归处理下一个任务
                    }
                });
            }
        }

        public int getActiveTaskCount() {
            return activeTasks.size();
        }

        public int getQueuedTaskCount() {
            return taskQueue.size();
        }

        public void cancelAllTasks() {
            // 取消所有活动任务
            for (BatchTestTask task : activeTasks.values()) {
                task.cancel();
            }
            // 清空队列
            taskQueue.clear();
        }

        public void shutdown() {
            cancelAllTasks();
            taskExecutor.shutdown();
            try {
                if (!taskExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                    taskExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                taskExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}