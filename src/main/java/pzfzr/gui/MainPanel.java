package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import pzfzr.config.ConfigManager;
import pzfzr.core.CookieChanger; // 新增：导入 CookieChanger
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import javax.swing.*;

public class MainPanel extends JSplitPane {
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final ControlPanel controlPanel;
    private final HistoryPanel historyPanel;
    // private final CookieChanger cookieChanger; // 可选：如果 MainPanel 将来需要直接使用 cookieChanger 实例，可以取消注释此行并赋值

    public MainPanel(MontoyaApi api, TableModel tableModel, ConfigManager configManager,
                     RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter,
                     TrafficHandler trafficHandler, CookieChanger cookieChanger,
                     ParamFuzzer paramFuzzer) { // 修改：添加 ParamFuzzer 参数
        super(JSplitPane.HORIZONTAL_SPLIT);
        this.api = api;
        this.tableModel = tableModel;
        // this.cookieChanger = cookieChanger; // 可选：在此处赋值

        // 创建控制面板 - 传入必要组件和 RateLimiter 实例，以及ParamFuzzer
        // ControlPanel 的构造函数不需要 CookieChanger，其内部的 CookieChangerPanel 会通过 CookieChanger.getInstance() 获取实例
        controlPanel = new ControlPanel(api, configManager, tableModel, requestResponseSaver,
                rateLimiter, trafficHandler, paramFuzzer);

        // 创建历史面板
        historyPanel = new HistoryPanel(tableModel,
                (original, modified) -> controlPanel.getRequestResponseViewer()
                        .updateViewers(original, modified));

        // 设置 RequestResponseViewer 的 historyPanel 引用
        controlPanel.getRequestResponseViewer().setHistoryPanel(historyPanel);

        // 设置分割面板的组件
        setLeftComponent(historyPanel);
        setRightComponent(controlPanel);
        setResizeWeight(0.90); // 您可以将此值调整为更适合您布局的值，例如0.5使左右面板均分，或0.3使历史面板更小
    }
}