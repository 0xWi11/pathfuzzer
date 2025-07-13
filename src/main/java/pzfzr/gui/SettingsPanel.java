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

    public SettingsPanel(ConfigManager configManager, Logging logging, TableModel tableModel, RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter, TrafficHandler trafficHandler) {
        setLayout(new BorderLayout());

        // 创建开关面板 - 传入logging实例和其他必要组件和 RateLimiter 实例
        switchPanel = new SwitchPanel(logging, tableModel, requestResponseSaver, rateLimiter, trafficHandler);

        // 创建底部面板
        listTabPane = new JTabbedPane();
//        listTabPane.addTab("Payload List", new ListPanel("Payload List", ConfigChangeType.PAYLOAD, true));
//        listTabPane.addTab("Collected List", new ListPanel("Collected List", ConfigChangeType.COLLECTED, true));
//        listTabPane.addTab("Suspicious List", new ListPanel("Suspicious List", ConfigChangeType.SUSPICIOUS, true));
//        listTabPane.addTab("Black List", new ListPanel("Black List", ConfigChangeType.BLACKLIST, true));
//        listTabPane.addTab("Remove List", new ListPanel("Remove List", ConfigChangeType.REMOVE, true));
        listTabPane.addTab("Intercept Filter", new RequestFilterPanel(configManager));

        // 使用JSplitPane分割上下两个部分
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(switchPanel);
        splitPane.setBottomComponent(listTabPane);
        splitPane.setResizeWeight(0.3); // 设置分割比例

        add(splitPane, BorderLayout.CENTER);
    }
}