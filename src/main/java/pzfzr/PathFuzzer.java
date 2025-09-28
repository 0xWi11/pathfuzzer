package pzfzr;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import pzfzr.config.ConfigManager;
import pzfzr.config.PersistenceManager;
import pzfzr.core.*;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer; // 新增：CookieFuzzer导入
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

    // 关闭控制
    private final AtomicBoolean isShuttingDown = new AtomicBoolean(false);

    public PathFuzzer() {
        // No need to instantiate TableModel here anymore
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Path Fuzzer");

        ConfigManager configManager = ConfigManager.getInstance();

        // 初始化 CookieChanger 单例
        this.cookieChanger = CookieChanger.getInstance();
        api.logging().logToOutput("[PathFuzzer] CookieChanger initialized");

        // 初始化核心组件
        // 正确的初始化顺序：先创建 TableModel，再创建 RequestResponseSaver 并传入 TableModel
        this.tableModel = new TableModel(null, api.logging()); // 初始化 TableModel，requestResponseSaver 暂时传入 null
        this.requestResponseSaver = new RequestResponseSaver(api.logging(), tableModel); // 初始化 RequestResponseSaver 并传入 TableModel 实例
        this.tableModel.setRequestResponseSaver(requestResponseSaver); // **重要**:  将 RequestResponseSaver 设置到 TableModel 中, 确保 TableModel 内部可以访问 RequestResponseSaver

        // 初始化CSV导出器
        this.csvExporter = new CSVExporter(api.logging(), tableModel, requestResponseSaver);
        this.rateLimiter = RateLimiter.getInstance(api.logging()); // 获取 RateLimiter 实例

        // 使用新的NettyManager
        this.nettyManager = NettyManager.getInstance(api.logging(), api.utilities().compressionUtils());
        api.logging().logToOutput("[PathFuzzer] Using NEW NettyManager for HTTP requests");

        this.valueReplacer = new ValueReplacer(api, tableModel, configManager, requestResponseSaver, rateLimiter); // 传递 *同一个* TableModel 和 RequestResponseSaver 和 RateLimiter 实例
        this.trafficHandler = new TrafficHandler(api, valueReplacer, tableModel, configManager, requestResponseSaver); // 传递 *同一个* TableModel 和 RequestResponseSaver 实例

        // 新增：从ValueReplacer获取所有Fuzzer引用（包括CookieFuzzer）
        ParamFuzzer paramFuzzer = valueReplacer.getParamFuzzer();
        ParamDeleter paramDeleter = valueReplacer.getParamDeleter();
        HeaderFuzzer headerFuzzer = valueReplacer.getHeaderFuzzer();
        CookieFuzzer cookieFuzzer = valueReplacer.getCookieFuzzer(); // 新增：获取CookieFuzzer引用

        // 注册UI - 修改：传入所有Fuzzer引用（包括CookieFuzzer）
        MainPanel mainPanel = new MainPanel(api, tableModel, configManager, requestResponseSaver, rateLimiter,
                trafficHandler, cookieChanger, paramFuzzer, paramDeleter, headerFuzzer, cookieFuzzer); // 新增：传递CookieFuzzer

        api.userInterface().registerSuiteTab("Path Fuzzer", mainPanel);

        // 注册上下文菜单
        ContextMenuProvider contextMenuProvider = new ContextMenuProvider(api, valueReplacer, tableModel, requestResponseSaver); // 传递 *同一个* TableModel 实例
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

        // 注册流量处理器
        api.http().registerHttpHandler(trafficHandler);

        // 初始化持久化管理器并加载配置
        this.persistenceManager = new PersistenceManager(configManager);
        persistenceManager.loadConfig();

        // 注册卸载处理器
        api.extension().registerUnloadingHandler(this);

        // 记录启动日志
        api.logging().logToOutput(
                String.format("[PathFuzzer]%s - %s",
                        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                        " Path Fuzzer extension loaded with Netty (including HeaderFuzzer and CookieFuzzer)") // 更新启动日志
        );
    }

    @Override
    public void extensionUnloaded() {
        // 防止重复关闭
        if (!isShuttingDown.compareAndSet(false, true)) {
            api.logging().logToOutput("[PathFuzzer] Shutdown already in progress");
            return;
        }

        api.logging().logToOutput("[PathFuzzer] Starting extension unload process...");

        // 创建关闭任务执行器，避免关闭过程中的死锁
        ExecutorService shutdownExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "pathfuzzer-shutdown");
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
            api.logging().logToError("[PathFuzzer] Shutdown timeout, forcing immediate shutdown");
            forceShutdown();
        } catch (Exception e) {
            api.logging().logToError("[PathFuzzer] Error during shutdown: " + e.getMessage());
            forceShutdown();
        } finally {
            shutdownExecutor.shutdownNow();
        }

        api.logging().logToOutput("[PathFuzzer] Extension unload completed");
    }

    private void performShutdown() {
        // 第一阶段：停止接收新请求
        api.logging().logToOutput("[PathFuzzer] Phase 1 - Stopping new request processing...");
        if (trafficHandler != null) {
            trafficHandler.setShuttingDown(true);
        }

        if (valueReplacer != null) {
            valueReplacer.setShuttingDown(true);
        }

        // 等待当前请求处理完成
        api.logging().logToOutput("[PathFuzzer] Phase 2 - Waiting for pending requests...");
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
                // ValueReplacer内部已经有关闭逻辑，这里只需要等待
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });

        // 第四阶段：关闭网络客户端并等待完成
        api.logging().logToOutput("[PathFuzzer] Phase 3 - Shutting down NettyManager...");
        shutdownComponent("NettyManager", () -> {
            if (nettyManager != null) {
                nettyManager.shutdown();
                // 等待NettyManager完全关闭
                boolean shutdownCompleted = nettyManager.awaitShutdown(10, TimeUnit.SECONDS);
                if (!shutdownCompleted) {
                    api.logging().logToError("[PathFuzzer] NettyManager shutdown timeout");
                } else {
                    api.logging().logToOutput("[PathFuzzer] NettyManager shutdown completed successfully");
                }
            }
        });

        // 第五阶段：关闭其他组件
        api.logging().logToOutput("[PathFuzzer] Phase 4 - Shutting down remaining components...");

        shutdownComponent("RateLimiter", () -> {
            if (rateLimiter != null) {
                rateLimiter.shutdown();
            }
        });

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

        api.logging().logToOutput("[PathFuzzer] CookieChanger resources released");
        String shutdownMessage = String.format(
                "\n" +
                        "############################################\n" +
                        "       PATH FUZZER plugin shutdown completed!\n" +
                        "############################################\n" +
                        "  Shutdown time: %s\n" +
                        "  All components safely stopped\n" +
                        "  Network connections cleared\n" +
                        "  Thread pools fully terminated\n" +
                        "  Resources released\n" +
                        "  HeaderFuzzer and CookieFuzzer included in shutdown\n" + // 更新关闭消息
                        "############################################\n" +
                        "       Thank you for using PATH FUZZER!\n" +
                        "############################################\n",
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
        );
        api.logging().logToOutput(shutdownMessage);
    }

    private void shutdownComponent(String componentName, Runnable shutdownAction) {
        try {
            shutdownAction.run();
            api.logging().logToOutput("[PathFuzzer] " + componentName + " shutdown completed");
        } catch (Exception e) {
            api.logging().logToError("[PathFuzzer] Error during " + componentName + " shutdown: " + e.getMessage());
        }
    }

    private void forceShutdown() {
        api.logging().logToOutput("[PathFuzzer] Performing force shutdown...");

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
            api.logging().logToError("[PathFuzzer] Error during force shutdown: " + e.getMessage());
        }
    }
}