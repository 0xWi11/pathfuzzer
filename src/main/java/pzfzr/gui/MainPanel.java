package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import pzfzr.config.ConfigManager;
import pzfzr.core.CookieChanger;
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer; // 新增：CookieFuzzer导入
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
                     ParamFuzzer paramFuzzer, ParamDeleter paramDeleter, HeaderFuzzer headerFuzzer,
                     CookieFuzzer cookieFuzzer) { // 修改：添加 CookieFuzzer 参数
        super(JSplitPane.VERTICAL_SPLIT); // 修改：改为垂直分割（上下结构）
        this.api = api;
        this.tableModel = tableModel;
        // this.cookieChanger = cookieChanger; // 可选：在此处赋值

        // 创建控制面板 - 传入必要组件和 RateLimiter 实例，以及所有Fuzzer组件（包括CookieFuzzer）
        // ControlPanel 的构造函数不需要 CookieChanger，其内部的 CookieChangerPanel 会通过 CookieChanger.getInstance() 获取实例
        controlPanel = new ControlPanel(api, configManager, tableModel, requestResponseSaver,
                rateLimiter, trafficHandler, paramFuzzer, paramDeleter, headerFuzzer, cookieFuzzer); // 新增：cookieFuzzer参数

        // 创建历史面板
        historyPanel = new HistoryPanel(tableModel,
                (original, modified) -> controlPanel.getRequestResponseViewer()
                        .updateViewers(original, modified));

        // 设置 RequestResponseViewer 的 historyPanel 引用
        controlPanel.getRequestResponseViewer().setHistoryPanel(historyPanel);

        // 设置分割面板的组件 - 修改：上面是historyPanel，下面是controlPanel
        setTopComponent(historyPanel);
        setBottomComponent(controlPanel);
        setResizeWeight(0.67); // 修改：history panel占2/3的高度
    }
}