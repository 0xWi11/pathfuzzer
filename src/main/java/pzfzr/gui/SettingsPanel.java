package pzfzr.gui;

import pzfzr.config.ConfigChangeType;
import pzfzr.config.ConfigManager;
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;

public class SettingsPanel extends JPanel {
    private final SwitchPanel switchPanel;
    private final JTabbedPane listTabPane;
    private final PayloadManagerPanel payloadManagerPanel; // Add PayloadManagerPanel

    public SettingsPanel(ConfigManager configManager, Logging logging, TableModel tableModel, RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter, TrafficHandler trafficHandler) {
        setLayout(new BorderLayout());

        // 创建开关面板 - 传入logging实例和其他必要组件和 RateLimiter 实例
        switchPanel = new SwitchPanel(logging, tableModel, requestResponseSaver, rateLimiter, trafficHandler);

        // 创建底部面板
        listTabPane = new JTabbedPane();

        // Initialize PayloadManagerPanel
        payloadManagerPanel = new PayloadManagerPanel();

        // Add the new Payload Manager tab
        listTabPane.addTab("Payload Manager", payloadManagerPanel);
        listTabPane.addTab("Intercept Filter", new RequestFilterPanel(configManager));

        // 使用JSplitPane分割上下两个部分
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(switchPanel);
        splitPane.setBottomComponent(listTabPane);
        splitPane.setResizeWeight(0.3); // 设置分割比例

        add(splitPane, BorderLayout.CENTER);
    }

    // Getter method to access PayloadManagerPanel if needed
    public PayloadManagerPanel getPayloadManagerPanel() {
        return payloadManagerPanel;
    }
}