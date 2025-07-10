package pzfzr;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import pzfzr.config.ConfigManager;
import pzfzr.config.PersistenceManager;
import pzfzr.core.RateLimiter;
import pzfzr.core.ValueReplacer;
import pzfzr.gui.MainPanel;
import pzfzr.gui.ContextMenuProvider;
import pzfzr.model.CSVExporter;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.core.TrafficHandler;
import pzfzr.core.CookieChanger;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

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
        api.logging().logToOutput("[PathFuzzer]: CookieChanger initialized");

        // 初始化核心组件
        // 正确的初始化顺序：先创建 TableModel，再创建 RequestResponseSaver 并传入 TableModel
        this.tableModel = new TableModel(null, api.logging()); // 初始化 TableModel，requestResponseSaver 暂时传入 null
        this.requestResponseSaver = new RequestResponseSaver(api.logging(), tableModel); // 初始化 RequestResponseSaver 并传入 TableModel 实例
        this.tableModel.setRequestResponseSaver(requestResponseSaver); // **重要**:  将 RequestResponseSaver 设置到 TableModel 中, 确保 TableModel 内部可以访问 RequestResponseSaver (如果 TableModel 中需要使用 RequestResponseSaver 的话，根据代码来看，TableModel 目前不需要直接使用RequestResponseSaver，这行代码可以删除，但为了代码的完整性和未来可能的扩展，建议保留)

        // 初始化CSV导出器
        this.csvExporter = new CSVExporter(api.logging(), tableModel, requestResponseSaver);
        this.rateLimiter = RateLimiter.getInstance(api.logging()); // 获取 RateLimiter 实例

        this.valueReplacer = new ValueReplacer(api, tableModel, configManager, requestResponseSaver, rateLimiter); // 传递 *同一个* TableModel 和 RequestResponseSaver 和 RateLimiter 实例
        this.trafficHandler = new TrafficHandler(api, valueReplacer, tableModel, configManager, requestResponseSaver); // 传递 *同一个* TableModel 和 RequestResponseSaver 实例

        // 注册UI
        MainPanel mainPanel = new MainPanel(api, tableModel, configManager, requestResponseSaver, rateLimiter, trafficHandler, cookieChanger); // 传递必要组件、RateLimiter 实例和 CookieChanger

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
                        " Path Fuzzer extension loaded")
        );
    }

    @Override
    public void extensionUnloaded() {
        api.logging().logToOutput("[PathFuzzer]: Starting extension unload process...");
        // 通知HeaderReplacer停止接受新请求
        if (rateLimiter != null) {
            rateLimiter.shutdown();
        }
        if (valueReplacer != null) {
            valueReplacer.setShuttingDown(true);
        }
        // 关闭流量处理器
        if (trafficHandler != null) {
            trafficHandler.shutdown();
        }
        // 关闭上下文菜单
        if (contextMenuProvider != null) {
            contextMenuProvider.shutdown();
        }
        // 关闭持久化管理器
        if (persistenceManager != null) {
            try {
                persistenceManager.shutdown();
                api.logging().logToOutput("[PathFuzzer]: Persistence manager shutdown completed");
            } catch (Exception e) {
                api.logging().logToError("[PathFuzzer]: Error during persistence manager shutdown: " + e.getMessage());
            }
        }
        // 关闭CSV导出器
        if (csvExporter != null) {
            csvExporter.shutdown();
        }
        if (requestResponseSaver != null) {
            requestResponseSaver.cleanupStorage();
        }
        if(tableModel != null) {
            tableModel.cleanup(); // 清理 TableModel 资源，会级联清理 ModifiedRequestResponse 资源
        }

        // CookieChanger 不需要特别的清理操作，但出于完整性在此添加记录
        api.logging().logToOutput("[PathFuzzer]: CookieChanger resources released");

        api.logging().logToOutput("Path Fuzzer: Extension unload completed");
    }
}