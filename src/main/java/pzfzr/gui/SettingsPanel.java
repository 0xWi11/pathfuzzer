package pzfzr.gui;

import pzfzr.config.ConfigManager;
import pzfzr.core.ParamCollector;
import pzfzr.core.RateLimiter;
import pzfzr.core.TrafficHandler;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import burp.api.montoya.logging.Logging;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
import pzfzr.fuzzer.ParamAdder;
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer;
import pzfzr.fuzzer.OOBParamFuzzer;

import javax.swing.*;
import java.awt.*;

public class SettingsPanel extends JPanel {
    private final SwitchPanel switchPanel;
    private final JTabbedPane listTabPane;
    private final PayloadManagerPanel payloadManagerPanel;
    private final ParamCollectorPanel paramCollectorPanel;

    public SettingsPanel(ConfigManager configManager, Logging logging, TableModel tableModel,
                         RequestResponseSaver requestResponseSaver, RateLimiter rateLimiter,
                         TrafficHandler trafficHandler, ParamFuzzer paramFuzzer, ParamDeleter paramDeleter,
                         ParamAdder paramAdder, HeaderFuzzer headerFuzzer, CookieFuzzer cookieFuzzer,
                         OOBParamFuzzer oobParamFuzzer, ParamCollector paramCollector) {
        setLayout(new BorderLayout());

        // 创建主要的水平分割面板（左右结构）
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // 创建左侧面板 - 功能控制区域
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("Function Controls"));

        // 创建开关面板 - 传入 paramAdder
        switchPanel = new SwitchPanel(logging, tableModel, requestResponseSaver, rateLimiter, trafficHandler,
                paramFuzzer, paramDeleter, paramAdder, headerFuzzer, cookieFuzzer, oobParamFuzzer);

        // 将switchPanel添加到一个滚动面板中以防内容过多
        JScrollPane switchScrollPane = new JScrollPane(switchPanel);
        switchScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        switchScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        leftPanel.add(switchScrollPane, BorderLayout.CENTER);

        // 创建右侧面板 - 配置管理区域
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("Configuration Management"));

        // 创建配置管理标签页面板
        listTabPane = new JTabbedPane();

        // Initialize PayloadManagerPanel
        payloadManagerPanel = new PayloadManagerPanel();

        // 只在 ParamCollector 启用时才创建 ParamCollectorPanel
        if (paramCollector != null) {
            paramCollectorPanel = new ParamCollectorPanel(paramCollector);
        } else {
            paramCollectorPanel = null;
        }

        // Add tabs
        listTabPane.addTab("Payload Manager", payloadManagerPanel);
        listTabPane.addTab("Intercept Filter", new RequestFilterPanel(configManager));

        // 只在 ParamCollector 启用时才添加标签页
        if (paramCollectorPanel != null) {
            listTabPane.addTab("Param Collector", paramCollectorPanel);
        }

        rightPanel.add(listTabPane, BorderLayout.CENTER);

        // 将左右面板添加到主分割面板
        mainSplitPane.setLeftComponent(leftPanel);
        mainSplitPane.setRightComponent(rightPanel);

        // 设置分割比例 - 左侧功能控制占40%，右侧配置管理占60%
        mainSplitPane.setResizeWeight(0.4);

        // 设置最小尺寸避免面板被压缩得太小
        leftPanel.setMinimumSize(new Dimension(300, 200));
        rightPanel.setMinimumSize(new Dimension(400, 200));

        add(mainSplitPane, BorderLayout.CENTER);

        // 可选：在顶部添加一个标题栏
        JLabel titleLabel = new JLabel("Settings & Configuration", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(titleLabel, BorderLayout.NORTH);
    }

    // Getter methods
    public PayloadManagerPanel getPayloadManagerPanel() {
        return payloadManagerPanel;
    }

    public SwitchPanel getSwitchPanel() {
        return switchPanel;
    }

    public ParamCollectorPanel getParamCollectorPanel() {
        return paramCollectorPanel;
    }

    /**
     * 清理资源
     */
    public void cleanup() {
        if (paramCollectorPanel != null) {
            paramCollectorPanel.cleanup();
        }
    }
}