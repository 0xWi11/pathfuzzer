package pzfzr;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import pzfzr.config.ConfigManager;
import pzfzr.config.PersistenceManager;
import pzfzr.config.PluginConfigManager;
import pzfzr.core.*;
import pzfzr.fuzzer.*;
import pzfzr.gui.MainPanel;
import pzfzr.gui.ContextMenuProvider;
import pzfzr.model.CSVExporter;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class PathFuzzer implements BurpExtension, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private TableModel tableModel;
    private TrafficHandler trafficHandler;
    private ValueReplacer valueReplacer;
    private PersistenceManager persistenceManager;
    private ContextMenuProvider contextMenuProvider;
    private RequestResponseSaver requestResponseSaver;
    private CSVExporter csvExporter;
    private RateLimiter rateLimiter;
    private CookieChanger cookieChanger;
    private NettyManager nettyManager;
    private PluginConfigManager pluginConfigManager;
    private ParamCollector paramCollector;
    private MainPanel mainPanel; // 新增：保存 UI 引用用于清理

    // 关闭控制
    private final AtomicBoolean isShuttingDown = new AtomicBoolean(false);

    public PathFuzzer() {
        // No need to instantiate TableModel here anymore
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // 初始化配置管理器
        this.pluginConfigManager = PluginConfigManager.getInstance();

        // 设置插件名称 - 使用配置的名称
        api.extension().setName(pluginConfigManager.getPluginName());

        ConfigManager configManager = ConfigManager.getInstance();

        // 初始化 CookieChanger 单例
        this.cookieChanger = CookieChanger.getInstance();
        api.logging().logToOutput(String.format("[%s] CookieChanger initialized", pluginConfigManager.getPluginName()));

        // 初始化核心组件
        this.tableModel = new TableModel(null, api.logging());
        this.requestResponseSaver = new RequestResponseSaver(api.logging(), tableModel);
        this.tableModel.setRequestResponseSaver(requestResponseSaver);

        // 根据配置决定是否初始化 ParamCollector
        if (pluginConfigManager.isParamCollectorEnabled()) {
            this.paramCollector = new ParamCollector(api.logging());
            api.logging().logToOutput(String.format("[%s] ParamCollector initialized (ENABLED)",
                    pluginConfigManager.getPluginName()));
        } else {
            this.paramCollector = null;
            api.logging().logToOutput(String.format("[%s] ParamCollector not initialized (DISABLED)",
                    pluginConfigManager.getPluginName()));
        }

        // 初始化CSV导出器
        this.csvExporter = new CSVExporter(api.logging(), tableModel, requestResponseSaver);
        this.rateLimiter = RateLimiter.getInstance(api.logging());

        // 使用新的NettyManager（已支持配置化端口）
        this.nettyManager = NettyManager.getInstance(api.logging(), api.utilities().compressionUtils());
        api.logging().logToOutput(String.format("[%s] Using NEW NettyManager for HTTP requests, Port: %d",
                pluginConfigManager.getPluginName(), pluginConfigManager.getNettyPort()));

        this.valueReplacer = new ValueReplacer(api, tableModel, configManager, requestResponseSaver, rateLimiter, paramCollector);
        this.trafficHandler = new TrafficHandler(api, valueReplacer, tableModel, configManager, requestResponseSaver);

        // 从ValueReplacer获取所有Fuzzer引用
        ParamFuzzer paramFuzzer = valueReplacer.getParamFuzzer();
        ParamDeleter paramDeleter = valueReplacer.getParamDeleter();
        HeaderFuzzer headerFuzzer = valueReplacer.getHeaderFuzzer();
        CookieFuzzer cookieFuzzer = valueReplacer.getCookieFuzzer();
        OOBParamFuzzer oobParamFuzzer = valueReplacer.getOOBParamFuzzer();

        // 注册UI - 保存引用用于后续清理
        this.mainPanel = new MainPanel(api, tableModel, configManager, requestResponseSaver, rateLimiter,
                trafficHandler, cookieChanger, paramFuzzer, paramDeleter, headerFuzzer, cookieFuzzer,
                oobParamFuzzer, paramCollector);

        api.userInterface().registerSuiteTab(pluginConfigManager.getPluginName(), mainPanel);

        // 注册上下文菜单 - 传入 paramCollector（可能为null）
        contextMenuProvider = new ContextMenuProvider(api, valueReplacer, tableModel,
                requestResponseSaver, paramCollector);
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

        // 注册流量处理器
        api.http().registerHttpHandler(trafficHandler);

        // 初始化持久化管理器并加载配置
        this.persistenceManager = new PersistenceManager(configManager);
        persistenceManager.loadConfig();

        // 注册卸载处理器
        api.extension().registerUnloadingHandler(this);

        // 记录启动日志 - 包含配置信息
        api.logging().logToOutput(
                String.format("[%s]%s - %s",
                        pluginConfigManager.getPluginName(),
                        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                        generateStartupMessage())
        );
    }

    /**
     * 生成启动消息，包含配置信息
     */
    private String generateStartupMessage() {
        PluginConfigManager.SwitchConfigState configState = pluginConfigManager.getSwitchConfigState();
        StringBuilder message = new StringBuilder();
        message.append(String.format(" %s extension loaded with Netty (Port: %d)",
                pluginConfigManager.getPluginName(), pluginConfigManager.getNettyPort()));

        message.append(" | Enabled modules: ");
        StringBuilder enabledModules = new StringBuilder();

        if (configState.isJsonListerEnabled()) {
            enabledModules.append("JsonLister, ");
        }
        if (configState.isRouteFuzzerEnabled()) {
            enabledModules.append("RouteFuzzer, ");
        }
        if (configState.isParamFuzzerEnabled()) {
            enabledModules.append("ParamFuzzer, ");
        }
        if (configState.isParamDeleterEnabled()) {
            enabledModules.append("ParamDeleter, ");
        }
        if (configState.isParamAdderEnabled()) {
            enabledModules.append("ParamAdder, ");
        }
        if (configState.isParamCollectorEnabled()) {
            enabledModules.append("ParamCollector, ");
        }
        if (configState.isHeaderFuzzerEnabled()) {
            enabledModules.append("HeaderFuzzer, ");
        }
        if (configState.isCookieFuzzerEnabled()) {
            enabledModules.append("CookieFuzzer, ");
        }
        if (configState.isOOBParamFuzzerEnabled()) {
            enabledModules.append("OOBParamFuzzer, ");
        }

        if (enabledModules.length() > 0) {
            // 移除最后的逗号和空格
            enabledModules.setLength(enabledModules.length() - 2);
            message.append(enabledModules);
        } else {
            message.append("None");
        }

        return message.toString();
    }

    @Override
    public void extensionUnloaded() {
        // 防止重复关闭
        if (!isShuttingDown.compareAndSet(false, true)) {
            api.logging().logToOutput(String.format("[%s] Shutdown already in progress", pluginConfigManager.getPluginName()));
            return;
        }

        api.logging().logToOutput(String.format("[%s] Starting extension unload process...", pluginConfigManager.getPluginName()));

        // 创建关闭任务执行器，避免关闭过程中的死锁
        ExecutorService shutdownExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, pluginConfigManager.getPluginName().toLowerCase() + "-shutdown");
            t.setDaemon(true);
            return t;
        });

        try {
            // 使用Future来控制关闭超时
            Future<?> shutdownFuture = shutdownExecutor.submit(() -> {
                performShutdown();
            });

            // 等待关闭完成，最多30秒
            shutdownFuture.get(30, TimeUnit.SECONDS);

        } catch (TimeoutException e) {
            api.logging().logToError(String.format("[%s] Shutdown timeout, forcing immediate shutdown", pluginConfigManager.getPluginName()));
            forceShutdown();
        } catch (Exception e) {
            api.logging().logToError(String.format("[%s] Error during shutdown: %s", pluginConfigManager.getPluginName(), e.getMessage()));
            forceShutdown();
        } finally {
            shutdownExecutor.shutdownNow();
        }

        api.logging().logToOutput(String.format("[%s] Extension unload completed", pluginConfigManager.getPluginName()));
    }

    private void performShutdown() {
        // 第一阶段：停止接收新请求
        api.logging().logToOutput(String.format("[%s] Phase 1 - Stopping new request processing...", pluginConfigManager.getPluginName()));
        if (trafficHandler != null) {
            trafficHandler.setShuttingDown(true);
        }

        if (valueReplacer != null) {
            valueReplacer.setShuttingDown(true);
        }

        // 等待当前请求处理完成
        api.logging().logToOutput(String.format("[%s] Phase 2 - Waiting for pending requests...", pluginConfigManager.getPluginName()));
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }

        // 第二阶段：关闭流量处理器（停止生成新任务）
        shutdownComponent("TrafficHandler", () -> {
            if (trafficHandler != null) {
                trafficHandler.shutdown();
            }
        });

        // 第三阶段：关闭ValueReplacer（停止处理任务）
        shutdownComponent("ValueReplacer", () -> {
            if (valueReplacer != null) {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });

        // 第四阶段：关闭网络客户端并等待完成
        api.logging().logToOutput(String.format("[%s] Phase 3 - Shutting down NettyManager...", pluginConfigManager.getPluginName()));
        shutdownComponent("NettyManager", () -> {
            if (nettyManager != null) {
                nettyManager.shutdown();
                // 等待NettyManager完全关闭
                boolean shutdownCompleted = nettyManager.awaitShutdown(10, TimeUnit.SECONDS);
                if (!shutdownCompleted) {
                    api.logging().logToError(String.format("[%s] NettyManager shutdown timeout", pluginConfigManager.getPluginName()));
                } else {
                    api.logging().logToOutput(String.format("[%s] NettyManager shutdown completed successfully", pluginConfigManager.getPluginName()));
                }
            }
        });

        // 第五阶段：关闭其他组件
        api.logging().logToOutput(String.format("[%s] Phase 4 - Shutting down remaining components...", pluginConfigManager.getPluginName()));

        // 新增：优先清理 UI 组件（停止所有 Timer）
        shutdownComponent("UI Components", () -> {
            if (mainPanel != null) {
                mainPanel.cleanup();
            }
        });

        shutdownComponent("RateLimiter", () -> {
            if (rateLimiter != null) {
                rateLimiter.shutdown();
            }
        });

        // 只在 ParamCollector 启用时才关闭
        if (paramCollector != null) {
            shutdownComponent("ParamCollector", () -> {
                paramCollector.shutdown();
            });
        }

        shutdownComponent("ContextMenuProvider", () -> {
            if (contextMenuProvider != null) {
                contextMenuProvider.shutdown();
            }
        });

        shutdownComponent("PersistenceManager", () -> {
            if (persistenceManager != null) {
                persistenceManager.shutdown();
            }
        });

        shutdownComponent("CSVExporter", () -> {
            if (csvExporter != null) {
                csvExporter.shutdown();
            }
        });

        shutdownComponent("RequestResponseSaver", () -> {
            if (requestResponseSaver != null) {
                requestResponseSaver.cleanupStorage();
            }
        });

        shutdownComponent("TableModel", () -> {
            if (tableModel != null) {
                tableModel.cleanup();
            }
        });

        api.logging().logToOutput(String.format("[%s] CookieChanger resources released", pluginConfigManager.getPluginName()));

        // 生成关闭消息，包含配置信息
        String shutdownMessage = generateShutdownMessage();
        api.logging().logToOutput(shutdownMessage);
    }

    /**
     * 生成关闭消息，包含配置信息
     */
    private String generateShutdownMessage() {
        PluginConfigManager.SwitchConfigState configState = pluginConfigManager.getSwitchConfigState();
        StringBuilder enabledModules = new StringBuilder();

        if (configState.isJsonListerEnabled()) {
            enabledModules.append("JsonLister, ");
        }
        if (configState.isRouteFuzzerEnabled()) {
            enabledModules.append("RouteFuzzer, ");
        }
        if (configState.isParamFuzzerEnabled()) {
            enabledModules.append("ParamFuzzer, ");
        }
        if (configState.isParamDeleterEnabled()) {
            enabledModules.append("ParamDeleter, ");
        }
        if (configState.isParamAdderEnabled()) {
            enabledModules.append("ParamAdder, ");
        }
        if (configState.isParamCollectorEnabled()) {
            enabledModules.append("ParamCollector, ");
        }
        if (configState.isHeaderFuzzerEnabled()) {
            enabledModules.append("HeaderFuzzer, ");
        }
        if (configState.isCookieFuzzerEnabled()) {
            enabledModules.append("CookieFuzzer, ");
        }
        if (configState.isOOBParamFuzzerEnabled()) {
            enabledModules.append("OOBParamFuzzer, ");
        }

        if (enabledModules.length() > 0) {
            enabledModules.setLength(enabledModules.length() - 2);
        } else {
            enabledModules.append("None");
        }

        return String.format(
                "\n" +
                        "############################################\n" +
                        "       %s plugin shutdown completed!\n" +
                        "############################################\n" +
                        "  Shutdown time: %s\n" +
                        "  All components safely stopped\n" +
                        "  Network connections cleared (Port: %d)\n" +
                        "  Thread pools fully terminated\n" +
                        "  Resources released\n" +
                        "  Enabled modules included in shutdown: %s\n" +
                        "############################################\n" +
                        "       Thank you for using %s!\n" +
                        "############################################\n",
                pluginConfigManager.getPluginName().toUpperCase(),
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                pluginConfigManager.getNettyPort(),
                enabledModules.toString(),
                pluginConfigManager.getPluginName().toUpperCase()
        );
    }

    private void shutdownComponent(String componentName, Runnable shutdownAction) {
        try {
            shutdownAction.run();
            api.logging().logToOutput(String.format("[%s] %s shutdown completed", pluginConfigManager.getPluginName(), componentName));
        } catch (Exception e) {
            api.logging().logToError(String.format("[%s] Error during %s shutdown: %s", pluginConfigManager.getPluginName(), componentName, e.getMessage()));
        }
    }

    private void forceShutdown() {
        api.logging().logToOutput(String.format("[%s] Performing force shutdown...", pluginConfigManager.getPluginName()));

        // 强制关闭所有组件
        try {
            if (nettyManager != null) {
                nettyManager.shutdown();
                // 给予短暂时间让NettyManager开始关闭
                nettyManager.awaitShutdown(3, TimeUnit.SECONDS);
            }
            if (trafficHandler != null) {
                trafficHandler.forceShutdown();
            }
            if (valueReplacer != null) {
                valueReplacer.forceShutdown();
            }
        } catch (Exception e) {
            api.logging().logToError(String.format("[%s] Error during force shutdown: %s", pluginConfigManager.getPluginName(), e.getMessage()));
        }
    }
}