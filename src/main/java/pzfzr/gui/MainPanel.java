package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import pzfzr.config.ConfigManager;
import pzfzr.core.CookieChanger;
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer;
import pzfzr.fuzzer.OOBParamFuzzer; // 新增：OOBParamFuzzer导入
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import javax.swing.*;

public class MainPanel extends JSplitPane {
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final ControlPanel controlPanel;
    private final HistoryPanel historyPanel;

    public MainPanel(MontoyaApi api, TableModel tableModel, ConfigManager configManager,
                     RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter,
                     TrafficHandler trafficHandler, CookieChanger cookieChanger,
                     ParamFuzzer paramFuzzer, ParamDeleter paramDeleter, HeaderFuzzer headerFuzzer,
                     CookieFuzzer cookieFuzzer, OOBParamFuzzer oobParamFuzzer) { // 修改：添加 OOBParamFuzzer 参数
        super(JSplitPane.VERTICAL_SPLIT);
        this.api = api;
        this.tableModel = tableModel;

        // 创建控制面板 - 传入必要组件和 RateLimiter 实例，以及所有Fuzzer组件（包括OOBParamFuzzer）
        controlPanel = new ControlPanel(api, configManager, tableModel, requestResponseSaver,
                rateLimiter, trafficHandler, paramFuzzer, paramDeleter, headerFuzzer, cookieFuzzer, oobParamFuzzer); // 新增：oobParamFuzzer参数

        // 创建历史面板
        historyPanel = new HistoryPanel(tableModel,
                (original, modified) -> controlPanel.getRequestResponseViewer()
                        .updateViewers(original, modified));

        // 设置 RequestResponseViewer 的 historyPanel 引用
        controlPanel.getRequestResponseViewer().setHistoryPanel(historyPanel);

        // 设置分割面板的组件
        setTopComponent(historyPanel);
        setBottomComponent(controlPanel);
        setResizeWeight(0.67);
    }
}