package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import pzfzr.config.ConfigManager;
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;

import javax.swing.*;
import java.awt.*;

public class ControlPanel extends JPanel {
    private final RequestResponseViewer requestResponseViewer;
    private final SettingsPanel settingsPanel;
    private final CookieChangerPanel cookieChangerPanel;  // 新增 CookieChangerPanel 引用

    public ControlPanel(MontoyaApi api, ConfigManager configManager, TableModel tableModel, RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter, TrafficHandler trafficHandler) {
        setLayout(new BorderLayout());

        // 创建标签页面板
        JTabbedPane tabbedPane = new JTabbedPane();

        // 初始化请求响应查看器
        requestResponseViewer = new RequestResponseViewer(api);

        // 初始化设置面板 - 传入必要组件和 RateLimiter 实例
        settingsPanel = new SettingsPanel(configManager, api.logging(), tableModel, requestResponseSaver, rateLimiter, trafficHandler);

        // 初始化 Cookie 修改器面板 - 新增
        cookieChangerPanel = new CookieChangerPanel(api);

        // 添加标签页
        tabbedPane.addTab("Request/Response Viewer", requestResponseViewer);
        tabbedPane.addTab("Settings", settingsPanel);
        tabbedPane.addTab("Cookie Changer", cookieChangerPanel);  // 添加新的选项卡

        add(tabbedPane, BorderLayout.CENTER);
    }

    public RequestResponseViewer getRequestResponseViewer() {
        return requestResponseViewer;
    }

    // 获取 CookieChangerPanel 的 getter 方法
    public CookieChangerPanel getCookieChangerPanel() {
        return cookieChangerPanel;
    }
}