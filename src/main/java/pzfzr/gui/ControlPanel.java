package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import pzfzr.config.ConfigManager;
import pzfzr.core.ParamCollector;
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer;
import pzfzr.fuzzer.OOBParamFuzzer;

import javax.swing.*;
import java.awt.*;

public class ControlPanel extends JPanel {
    private final RequestResponseViewer requestResponseViewer;
    private final SettingsPanel settingsPanel;
    private final CookieChangerPanel cookieChangerPanel;

    public ControlPanel(MontoyaApi api, ConfigManager configManager, TableModel tableModel,
                        RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter,
                        TrafficHandler trafficHandler, ParamFuzzer paramFuzzer, ParamDeleter paramDeleter,
                        HeaderFuzzer headerFuzzer, CookieFuzzer cookieFuzzer, OOBParamFuzzer oobParamFuzzer,
                        ParamCollector paramCollector) {
        setLayout(new BorderLayout());

        // 创建标签页面板
        JTabbedPane tabbedPane = new JTabbedPane();

        // 初始化请求响应查看器
        requestResponseViewer = new RequestResponseViewer(api);

        // 初始化设置面板 - 传入 paramCollector
        settingsPanel = new SettingsPanel(configManager, api.logging(), tableModel, requestResponseSaver,
                rateLimiter, trafficHandler, paramFuzzer, paramDeleter, headerFuzzer, cookieFuzzer,
                oobParamFuzzer, paramCollector);

        // 初始化 Cookie 修改器面板
        cookieChangerPanel = new CookieChangerPanel(api);

        // 添加标签页
        tabbedPane.addTab("Request/Response Viewer", requestResponseViewer);
        tabbedPane.addTab("Settings", settingsPanel);
        tabbedPane.addTab("Cookie Changer", cookieChangerPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public RequestResponseViewer getRequestResponseViewer() {
        return requestResponseViewer;
    }

    public CookieChangerPanel getCookieChangerPanel() {
        return cookieChangerPanel;
    }

    /**
     * 清理资源
     */
    public void cleanup() {
        if (settingsPanel != null) {
            settingsPanel.cleanup();
        }
    }
}