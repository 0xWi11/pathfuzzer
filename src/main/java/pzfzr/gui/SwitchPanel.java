package pzfzr.gui;

import pzfzr.config.PluginConfigManager;
import pzfzr.config.SwitchManager;
import pzfzr.core.RateLimiter;
import pzfzr.core.RequestDeduplicator;
import pzfzr.core.TrafficHandler;
import pzfzr.fuzzer.*;
import pzfzr.model.CSVExporter;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Path;

public class SwitchPanel extends JPanel {
    private final JCheckBox masterSwitch;
    private final JCheckBox builtInSwitch;
    private final JCheckBox collectedSwitch;
    private final JCheckBox suspiciousSwitch;
    private final JCheckBox paramDeleterSwitch;
    private final JCheckBox paramAdderSwitch;
    private final JCheckBox headerFuzzerSwitch;
    private final JCheckBox cookieFuzzerSwitch;
    private final JCheckBox oobParamFuzzerSwitch;
    private final JCheckBox cacheFuzzerSwitch;
    private final JButton clearHashesButton;
    private final JButton exportCSVButton;
    private final JButton openFolderButton;
    private final JButton setRateToZeroButton; // 新增：速率设置为0按钮
    private final SwitchManager switchManager;
    private final PluginConfigManager pluginConfigManager;
    private final Logging logging;
    private final CSVExporter csvExporter;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final ParamFuzzer paramFuzzer;
    private final ParamDeleter paramDeleter;
    private final ParamAdder paramAdder;
    private final HeaderFuzzer headerFuzzer;
    private final CookieFuzzer cookieFuzzer;
    private final OOBParamFuzzer oobParamFuzzer;
    private final CacheFuzzer cacheFuzzer;

    private final JTextField newCapacityTextField;
    private final JTextField newRefillRateTextField;
    private final JTextField newUrlRateLimitTextField;
    private final JTextField newUrlExpireTimeTextField;
    private final JTextField newRefillIntervalTextField;
    private final JTextField maxHeadersPerBatchTextField;
    private final JTextField maxParameterCountTextField;
    private final JTextField maxParameterCountDeleterTextField;
    private final JTextField maxParameterCountCookieTextField;
    private final JTextField maxParameterCountOOBTextField;
    private final JTextField getBatchSizeTextField;
    private final JTextField postBatchSizeTextField;
    private final JTextField jsonBatchSizeTextField;
    private final JButton setRateLimitButton;
    private final JButton clearTasksButton;
    private final TrafficHandler trafficHandler;
    private final JLabel requestsPerHourLabel;
    private final JButton cancelActiveTasksButton;
    private final JLabel successMessageLabel;
    private Timer successMessageTimer;

    public SwitchPanel(Logging logging, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, TrafficHandler trafficHandler, ParamFuzzer paramFuzzer,
                       ParamDeleter paramDeleter, ParamAdder paramAdder, HeaderFuzzer headerFuzzer,
                       CookieFuzzer cookieFuzzer, OOBParamFuzzer oobParamFuzzer, CacheFuzzer cacheFuzzer) {
        this.switchManager = SwitchManager.getInstance();
        this.pluginConfigManager = PluginConfigManager.getInstance();
        this.logging = logging;
        this.requestResponseSaver = requestResponseSaver;
        this.csvExporter = new CSVExporter(logging, tableModel, requestResponseSaver);
        this.rateLimiter = rateLimiter;
        this.trafficHandler = trafficHandler;
        this.paramFuzzer = paramFuzzer;
        this.paramDeleter = paramDeleter;
        this.paramAdder = paramAdder;
        this.headerFuzzer = headerFuzzer;
        this.cookieFuzzer = cookieFuzzer;
        this.oobParamFuzzer = oobParamFuzzer;
        this.cacheFuzzer = cacheFuzzer;

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        JPanel wrapperPanel = new JPanel();
        wrapperPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JPanel switchesPanel = new JPanel();
        switchesPanel.setLayout(new BoxLayout(switchesPanel, BoxLayout.Y_AXIS));

        // 创建开关 - 根据配置决定是否启用
        masterSwitch = createSwitch("请求总开关",
                switchManager.isMasterSwitch(),
                selected -> {
                    switchManager.setMasterSwitch(selected);
                    updateSwitchStates();
                });

        // 根据配置创建和配置各个开关
        PluginConfigManager.SwitchConfigState configState = pluginConfigManager.getSwitchConfigState();

        builtInSwitch = createSwitch("JsonLister 测试开关",
                switchManager.isJsonListerSwitch(),
                selected -> switchManager.setJsonListerSwitch(selected));
        builtInSwitch.setEnabled(configState.isJsonListerEnabled());

        collectedSwitch = createSwitch("RouteFuzzer 测试开关",
                switchManager.isRoutefuzzerSwitch(),
                selected -> switchManager.setRoutefuzzerSwitch(selected));
        collectedSwitch.setEnabled(configState.isRouteFuzzerEnabled());

        suspiciousSwitch = createSwitch("ParamFuzzer 测试开关",
                switchManager.isParamfuzzerSwitch(),
                selected -> switchManager.setParamfuzzerSwitch(selected));
        suspiciousSwitch.setEnabled(configState.isParamFuzzerEnabled());

        paramDeleterSwitch = createSwitch("ParamDeleter 测试开关",
                switchManager.isParamdeleterSwitch(),
                selected -> switchManager.setParamdeleterSwitch(selected));
        paramDeleterSwitch.setEnabled(configState.isParamDeleterEnabled());

        paramAdderSwitch = createSwitch("ParamAdder 测试开关",
                switchManager.isParamadderSwitch(),
                selected -> switchManager.setParamadderSwitch(selected));
        paramAdderSwitch.setEnabled(configState.isParamAdderEnabled());

        headerFuzzerSwitch = createSwitch("HeaderFuzzer 测试开关",
                switchManager.isHeaderfuzzerSwitch(),
                selected -> switchManager.setHeaderfuzzerSwitch(selected));
        headerFuzzerSwitch.setEnabled(configState.isHeaderFuzzerEnabled());

        cookieFuzzerSwitch = createSwitch("CookieFuzzer 测试开关",
                switchManager.isCookiefuzzerSwitch(),
                selected -> switchManager.setCookiefuzzerSwitch(selected));
        cookieFuzzerSwitch.setEnabled(configState.isCookieFuzzerEnabled());

        oobParamFuzzerSwitch = createSwitch("OOBParamFuzzer 测试开关",
                switchManager.isOobparamfuzzerSwitch(),
                selected -> switchManager.setOobparamfuzzerSwitch(selected));
        oobParamFuzzerSwitch.setEnabled(configState.isOOBParamFuzzerEnabled());

        // 创建开关
        cacheFuzzerSwitch = createSwitch("CacheFuzzer 测试开关",
                switchManager.isCachefuzzerSwitch(),
                selected -> switchManager.setCachefuzzerSwitch(selected));
        cacheFuzzerSwitch.setEnabled(configState.isCacheFuzzerEnabled());

        // 根据配置设置开关是否可见
        if (!configState.isJsonListerEnabled()) {
            builtInSwitch.setVisible(false);
        }
        if (!configState.isRouteFuzzerEnabled()) {
            collectedSwitch.setVisible(false);
        }
        if (!configState.isParamFuzzerEnabled()) {
            suspiciousSwitch.setVisible(false);
        }
        if (!configState.isParamDeleterEnabled()) {
            paramDeleterSwitch.setVisible(false);
        }
        if (!configState.isParamAdderEnabled()) {
            paramAdderSwitch.setVisible(false);
        }
        if (!configState.isHeaderFuzzerEnabled()) {
            headerFuzzerSwitch.setVisible(false);
        }
        if (!configState.isCookieFuzzerEnabled()) {
            cookieFuzzerSwitch.setVisible(false);
        }
        if (!configState.isOOBParamFuzzerEnabled()) {
            oobParamFuzzerSwitch.setVisible(false);
        }
        // 根据配置设置可见性
        if (!configState.isCacheFuzzerEnabled()) {
            cacheFuzzerSwitch.setVisible(false);
        }



        // 创建清除哈希按钮
        clearHashesButton = new JButton("清除URL缓存");
        clearHashesButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        clearHashesButton.addActionListener(e -> {
            RequestDeduplicator deduplicator = RequestDeduplicator.getInstance(logging);
            int count = deduplicator.getHashCount();
            deduplicator.clearAllHashes();
            JOptionPane.showMessageDialog(
                    this,
                    "已清除 " + count + " 个URL缓存记录",
                    "清除成功",
                    JOptionPane.INFORMATION_MESSAGE
            );
        });

        // 创建导出CSV按钮
        exportCSVButton = new JButton("导出数据至CSV");
        exportCSVButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        exportCSVButton.addActionListener(e -> {
            csvExporter.exportToCSV();
            JOptionPane.showMessageDialog(
                    this,
                    "数据导出成功",
                    "导出CSV",
                    JOptionPane.INFORMATION_MESSAGE
            );
        });

        // 创建打开文件夹按钮
        openFolderButton = new JButton("打开存储文件夹");
        openFolderButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        openFolderButton.addActionListener(e -> {
            try {
                Path dailyStorageDir = requestResponseSaver.getDailyStorageDir();
                if (dailyStorageDir != null && dailyStorageDir.toFile().exists()) {
                    Desktop.getDesktop().open(dailyStorageDir.toFile());
                } else {
                    JOptionPane.showMessageDialog(
                            this,
                            "存储文件夹不存在",
                            "错误",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (IOException ex) {
                logging.logToError("Failed to open storage directory: " + ex.getMessage());
                JOptionPane.showMessageDialog(
                        this,
                        "无法打开存储文件夹: " + ex.getMessage(),
                        "错误",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        });

        // Create button to cancel active tasks
        cancelActiveTasksButton = new JButton("丢弃活跃任务");
        cancelActiveTasksButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        cancelActiveTasksButton.addActionListener(e -> {
            trafficHandler.cancelActiveThreads();
            JOptionPane.showMessageDialog(
                    this,
                    "已尝试丢弃所有活跃线程中正在执行的任务",
                    "操作完成",
                    JOptionPane.INFORMATION_MESSAGE
            );
        });

        // 创建清除任务按钮
        clearTasksButton = new JButton("清空待处理任务");
        clearTasksButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        clearTasksButton.addActionListener(e -> {
            trafficHandler.clearAllTasks();
            JOptionPane.showMessageDialog(
                    this,
                    "已清空所有待处理任务",
                    "清除成功",
                    JOptionPane.INFORMATION_MESSAGE
            );
        });

        // 创建全局速率限制面板
        JPanel globalRateLimitPanel = new JPanel();
        globalRateLimitPanel.setLayout(new BoxLayout(globalRateLimitPanel, BoxLayout.Y_AXIS));
        globalRateLimitPanel.setBorder(BorderFactory.createTitledBorder("全局速率限制"));

        // 第一行：容量和速率
        JPanel firstRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel capacityLabel = new JLabel("容量 (capacity):");
        newCapacityTextField = new JTextField(String.valueOf(rateLimiter.getCapacity()), 5);
        JLabel refillRateLabel = new JLabel("速率 (refillRate):");
        newRefillRateTextField = new JTextField(String.valueOf(rateLimiter.getRefillRate()), 5);
        firstRowPanel.add(capacityLabel);
        firstRowPanel.add(newCapacityTextField);
        firstRowPanel.add(refillRateLabel);
        firstRowPanel.add(newRefillRateTextField);

        // 第二行：添加间隔
        JPanel secondRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel refillIntervalLabel = new JLabel("添加间隔 (ms):");
        newRefillIntervalTextField = new JTextField(String.valueOf(rateLimiter.getRefillIntervalMillis()), 5);
        // 初始化标签显示当前refillRate对应的每小时请求数
        double requestsPerSecond = calculateRequestsPerSecond(rateLimiter.getRefillRate(), rateLimiter.getRefillIntervalMillis());
        int requestsPerHour = (int)(requestsPerSecond * 3600);
        requestsPerHourLabel = new JLabel(String.format("%d req/h | %.2f req/s", requestsPerHour, requestsPerSecond));
        Font smallerFont = new Font(requestsPerHourLabel.getFont().getName(), Font.PLAIN, 10);
        requestsPerHourLabel.setFont(smallerFont);
        secondRowPanel.add(refillIntervalLabel);
        secondRowPanel.add(newRefillIntervalTextField);
        secondRowPanel.add(requestsPerHourLabel);

        // 第三行：每批次最大header数量
        JPanel thirdRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel maxHeadersLabel = new JLabel("每批次最大Header数:");
        maxHeadersPerBatchTextField = new JTextField(String.valueOf(rateLimiter.getMaxHeadersPerBatch()), 5);
        thirdRowPanel.add(maxHeadersLabel);
        thirdRowPanel.add(maxHeadersPerBatchTextField);

        // 添加三行到主面板
        globalRateLimitPanel.add(firstRowPanel);
        globalRateLimitPanel.add(secondRowPanel);
        globalRateLimitPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建设置URL速率限制的UI元素
        JPanel urlRateLimitPanel = new JPanel();
        urlRateLimitPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        urlRateLimitPanel.setBorder(BorderFactory.createTitledBorder("URL速率限制"));

        JLabel urlRateLabel = new JLabel("URL限流 (req/s):");
        newUrlRateLimitTextField = new JTextField(String.valueOf(rateLimiter.getUrlRateLimit()), 5);
        JLabel urlExpireLabel = new JLabel("URL过期时间 (秒):");
        newUrlExpireTimeTextField = new JTextField(String.valueOf(rateLimiter.getUrlExpireTime() / 1000), 5);

        urlRateLimitPanel.add(urlRateLabel);
        urlRateLimitPanel.add(newUrlRateLimitTextField);
        urlRateLimitPanel.add(urlExpireLabel);
        urlRateLimitPanel.add(newUrlExpireTimeTextField);
        urlRateLimitPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建参数数量限制设置的UI元素 - 根据配置显示相关组件
        JPanel maxParameterPanel = new JPanel();
        maxParameterPanel.setLayout(new BoxLayout(maxParameterPanel, BoxLayout.Y_AXIS));
        maxParameterPanel.setBorder(BorderFactory.createTitledBorder("参数数量限制"));

        // ParamFuzzer参数数量限制
        if (configState.isParamFuzzerEnabled()) {
            JPanel paramFuzzerLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel maxParameterLabel = new JLabel("ParamFuzzer最大参数数量:");
            maxParameterCountTextField = new JTextField(String.valueOf(paramFuzzer.getMaxParameterCount()), 5);
            paramFuzzerLimitPanel.add(maxParameterLabel);
            paramFuzzerLimitPanel.add(maxParameterCountTextField);
            maxParameterPanel.add(paramFuzzerLimitPanel);
        } else {
            maxParameterCountTextField = new JTextField("0", 5);
        }

        // ParamDeleter参数数量限制
        if (configState.isParamDeleterEnabled()) {
            JPanel paramDeleterLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel maxParameterDeleterLabel = new JLabel("ParamDeleter最大参数数量:");
            maxParameterCountDeleterTextField = new JTextField(String.valueOf(paramDeleter.getMaxParameterCount()), 5);
            paramDeleterLimitPanel.add(maxParameterDeleterLabel);
            paramDeleterLimitPanel.add(maxParameterCountDeleterTextField);
            maxParameterPanel.add(paramDeleterLimitPanel);
        } else {
            maxParameterCountDeleterTextField = new JTextField("0", 5);
        }

        // ParamAdder批次大小限制
        if (configState.isParamAdderEnabled()) {
            JPanel paramAdderBatchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel getBatchSizeLabel = new JLabel("GET批次大小:");
            getBatchSizeTextField = new JTextField(String.valueOf(paramAdder.getGetBatchSize()), 5);
            JLabel postBatchSizeLabel = new JLabel("POST批次大小:");
            postBatchSizeTextField = new JTextField(String.valueOf(paramAdder.getPostBatchSize()), 5);
            JLabel jsonBatchSizeLabel = new JLabel("JSON批次大小:");
            jsonBatchSizeTextField = new JTextField(String.valueOf(paramAdder.getJsonBatchSize()), 5);
            paramAdderBatchPanel.add(getBatchSizeLabel);
            paramAdderBatchPanel.add(getBatchSizeTextField);
            paramAdderBatchPanel.add(postBatchSizeLabel);
            paramAdderBatchPanel.add(postBatchSizeTextField);
            paramAdderBatchPanel.add(jsonBatchSizeLabel);
            paramAdderBatchPanel.add(jsonBatchSizeTextField);
            maxParameterPanel.add(paramAdderBatchPanel);
        } else {
            getBatchSizeTextField = new JTextField("0", 5);
            postBatchSizeTextField = new JTextField("0", 5);
            jsonBatchSizeTextField = new JTextField("0", 5);
        }

        // CookieFuzzer参数数量限制
        if (configState.isCookieFuzzerEnabled()) {
            JPanel cookieFuzzerLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel maxParameterCookieLabel = new JLabel("CookieFuzzer最大参数数量:");
            maxParameterCountCookieTextField = new JTextField(String.valueOf(cookieFuzzer.getMaxParameterCount()), 5);
            cookieFuzzerLimitPanel.add(maxParameterCookieLabel);
            cookieFuzzerLimitPanel.add(maxParameterCountCookieTextField);
            maxParameterPanel.add(cookieFuzzerLimitPanel);
        } else {
            maxParameterCountCookieTextField = new JTextField("0", 5);
        }

        // OOBParamFuzzer参数数量限制
        if (configState.isOOBParamFuzzerEnabled()) {
            JPanel oobParamFuzzerLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel maxParameterOOBLabel = new JLabel("OOBParamFuzzer最大参数数量:");
            maxParameterCountOOBTextField = new JTextField(String.valueOf(oobParamFuzzer.getMaxParameterCount()), 5);
            oobParamFuzzerLimitPanel.add(maxParameterOOBLabel);
            oobParamFuzzerLimitPanel.add(maxParameterCountOOBTextField);
            maxParameterPanel.add(oobParamFuzzerLimitPanel);
        } else {
            maxParameterCountOOBTextField = new JTextField("0", 5);
        }

        maxParameterPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建设置按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        setRateLimitButton = new JButton("应用设置");

        // 新增：创建成功提示标签
        successMessageLabel = new JLabel();
        successMessageLabel.setForeground(new Color(0, 150, 0)); // 绿色
        successMessageLabel.setVisible(false); // 初始隐藏

        setRateLimitButton.addActionListener(e -> {
            try {
                int newCapacity = Integer.parseInt(newCapacityTextField.getText());
                int newRefillRate = Integer.parseInt(newRefillRateTextField.getText());
                int newUrlRateLimit = Integer.parseInt(newUrlRateLimitTextField.getText());
                long newUrlExpireTime = Long.parseLong(newUrlExpireTimeTextField.getText()) * 1000;
                long newRefillInterval = Long.parseLong(newRefillIntervalTextField.getText());
                int newMaxHeadersPerBatch = Integer.parseInt(maxHeadersPerBatchTextField.getText());

                // 只获取启用的组件的参数值
                int newMaxParameterCount = configState.isParamFuzzerEnabled() ?
                        Integer.parseInt(maxParameterCountTextField.getText()) : 0;
                int newMaxParameterCountDeleter = configState.isParamDeleterEnabled() ?
                        Integer.parseInt(maxParameterCountDeleterTextField.getText()) : 0;
                int newMaxParameterCountCookie = configState.isCookieFuzzerEnabled() ?
                        Integer.parseInt(maxParameterCountCookieTextField.getText()) : 0;
                int newMaxParameterCountOOB = configState.isOOBParamFuzzerEnabled() ?
                        Integer.parseInt(maxParameterCountOOBTextField.getText()) : 0;

                // 获取ParamAdder批次大小参数
                int newGetBatchSize = configState.isParamAdderEnabled() ?
                        Integer.parseInt(getBatchSizeTextField.getText()) : 0;
                int newPostBatchSize = configState.isParamAdderEnabled() ?
                        Integer.parseInt(postBatchSizeTextField.getText()) : 0;
                int newJsonBatchSize = configState.isParamAdderEnabled() ?
                        Integer.parseInt(jsonBatchSizeTextField.getText()) : 0;

                if (newCapacity > 0 && newRefillRate >= 0 && newUrlRateLimit >= 0 &&
                        newUrlExpireTime >= 0 && newRefillInterval > 0 && newMaxHeadersPerBatch > 0) {

                    rateLimiter.updateConfiguration(newCapacity, newRefillRate, newUrlRateLimit,
                            newUrlExpireTime, newRefillInterval, newMaxHeadersPerBatch);

                    // 只更新启用的组件
                    if (configState.isParamFuzzerEnabled() && newMaxParameterCount > 0) {
                        paramFuzzer.setMaxParameterCount(newMaxParameterCount);
                    }
                    if (configState.isParamDeleterEnabled() && newMaxParameterCountDeleter > 0) {
                        paramDeleter.setMaxParameterCount(newMaxParameterCountDeleter);
                    }
                    if (configState.isCookieFuzzerEnabled() && newMaxParameterCountCookie > 0) {
                        cookieFuzzer.setMaxParameterCount(newMaxParameterCountCookie);
                    }
                    if (configState.isOOBParamFuzzerEnabled() && newMaxParameterCountOOB > 0) {
                        oobParamFuzzer.setMaxParameterCount(newMaxParameterCountOOB);
                    }

                    // 更新ParamAdder批次大小
                    if (configState.isParamAdderEnabled()) {
                        if (newGetBatchSize > 0) {
                            paramAdder.setGetBatchSize(newGetBatchSize);
                        }
                        if (newPostBatchSize > 0) {
                            paramAdder.setPostBatchSize(newPostBatchSize);
                        }
                        if (newJsonBatchSize > 0) {
                            paramAdder.setJsonBatchSize(newJsonBatchSize);
                        }
                    }

                    // 更新每小时请求数显示
                    double updatedRequestsPerSecond = calculateRequestsPerSecond(newRefillRate, newRefillInterval);
                    int updatedRequestsPerHour = (int)(updatedRequestsPerSecond * 3600);
                    requestsPerHourLabel.setText(String.format("%d req/h | %.2f req/s", updatedRequestsPerHour, updatedRequestsPerSecond));

                    // 新增：显示成功提示而不是弹窗
                    showSuccessMessage("✓ 设置已成功更新");
                } else {
                    // 错误提示仍使用弹窗
                    JOptionPane.showMessageDialog(
                            this,
                            "容量、令牌添加间隔、每批次最大Header数必须大于0，其他参数不能为负数",
                            "错误",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (NumberFormatException ex) {
                // 错误提示仍使用弹窗
                JOptionPane.showMessageDialog(
                        this,
                        "请输入有效的数字",
                        "错误",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        });

        buttonPanel.add(setRateLimitButton);
        buttonPanel.add(successMessageLabel); // 新增：在按钮旁边添加提示标签
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建一个新的面板，包含所有速率限制相关的控件
        JPanel rateLimitingContainer = new JPanel();
        rateLimitingContainer.setLayout(new BoxLayout(rateLimitingContainer, BoxLayout.Y_AXIS));
        rateLimitingContainer.add(globalRateLimitPanel);
        rateLimitingContainer.add(urlRateLimitPanel);
        rateLimitingContainer.add(maxParameterPanel);
        rateLimitingContainer.add(buttonPanel);
        rateLimitingContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 新增：创建"速率设置为0"按钮（必须在 setRateLimitButton 和 newRefillRateTextField 初始化之后）
        setRateToZeroButton = new JButton("速率设置为0");
        setRateToZeroButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        setRateToZeroButton.addActionListener(e -> {
            // 将速率文本框设置为0
            newRefillRateTextField.setText("0");
            // 直接触发应用设置
            setRateLimitButton.doClick();
        });

        // 创建按钮布局面板
        JPanel buttonsContainer = new JPanel();
        buttonsContainer.setLayout(new BoxLayout(buttonsContainer, BoxLayout.Y_AXIS));
        buttonsContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 第一行
        JPanel firstButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        firstButtonRow.add(clearHashesButton);
        firstButtonRow.add(cancelActiveTasksButton);
        firstButtonRow.add(clearTasksButton);
        firstButtonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 第二行 - 新增"速率设置为0"按钮
        JPanel secondButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        secondButtonRow.add(exportCSVButton);
        secondButtonRow.add(openFolderButton);
        secondButtonRow.add(setRateToZeroButton); // 新增按钮
        secondButtonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        buttonsContainer.add(firstButtonRow);
        buttonsContainer.add(Box.createVerticalStrut(5));
        buttonsContainer.add(secondButtonRow);

        // 添加固定间距的开关和按钮
        switchesPanel.add(masterSwitch);
        if (configState.isJsonListerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(builtInSwitch);
        }
        if (configState.isRouteFuzzerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(collectedSwitch);
        }
        if (configState.isParamFuzzerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(suspiciousSwitch);
        }
        if (configState.isParamDeleterEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(paramDeleterSwitch);
        }
        if (configState.isParamAdderEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(paramAdderSwitch);
        }
        if (configState.isHeaderFuzzerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(headerFuzzerSwitch);
        }
        if (configState.isCookieFuzzerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(cookieFuzzerSwitch);
        }
        if (configState.isOOBParamFuzzerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(oobParamFuzzerSwitch);
        }
        // 在添加开关时：
        if (configState.isCacheFuzzerEnabled()) {
            switchesPanel.add(Box.createVerticalStrut(5));
            switchesPanel.add(cacheFuzzerSwitch);
        }

        switchesPanel.add(Box.createVerticalStrut(10));
        switchesPanel.add(buttonsContainer);
        switchesPanel.add(Box.createVerticalStrut(10));
        switchesPanel.add(rateLimitingContainer);

        wrapperPanel.add(switchesPanel);
        add(wrapperPanel);
        add(Box.createVerticalGlue());

        updateSwitchStates();
    }

    // 新增：显示成功消息的方法
    private void showSuccessMessage(String message) {
        // 如果有正在运行的定时器，先停止它
        if (successMessageTimer != null && successMessageTimer.isRunning()) {
            successMessageTimer.stop();
        }

        // 显示消息
        successMessageLabel.setText(message);
        successMessageLabel.setVisible(true);

        // 创建一个定时器，3秒后隐藏消息
        successMessageTimer = new Timer(3000, e -> {
            successMessageLabel.setVisible(false);
        });
        successMessageTimer.setRepeats(false); // 只执行一次
        successMessageTimer.start();
    }

    private JCheckBox createSwitch(String text, boolean initialState, SwitchChangeListener listener) {
        JCheckBox checkBox = new JCheckBox(text);
        checkBox.setSelected(initialState);
        checkBox.addActionListener(e -> listener.onSwitchChanged(checkBox.isSelected()));
        checkBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        return checkBox;
    }

    private void updateSwitchStates() {
        boolean masterState = masterSwitch.isSelected();
        PluginConfigManager.SwitchConfigState configState = pluginConfigManager.getSwitchConfigState();

        // 只有配置启用且主开关开启时，子开关才能操作
        if (configState.isJsonListerEnabled()) {
            builtInSwitch.setEnabled(masterState);
        }
        if (configState.isRouteFuzzerEnabled()) {
            collectedSwitch.setEnabled(masterState);
        }
        if (configState.isParamFuzzerEnabled()) {
            suspiciousSwitch.setEnabled(masterState);
        }
        if (configState.isParamDeleterEnabled()) {
            paramDeleterSwitch.setEnabled(masterState);
        }
        if (configState.isParamAdderEnabled()) {
            paramAdderSwitch.setEnabled(masterState);
        }
        if (configState.isHeaderFuzzerEnabled()) {
            headerFuzzerSwitch.setEnabled(masterState);
        }
        if (configState.isCookieFuzzerEnabled()) {
            cookieFuzzerSwitch.setEnabled(masterState);
        }
        if (configState.isOOBParamFuzzerEnabled()) {
            oobParamFuzzerSwitch.setEnabled(masterState);
        }
        if (configState.isCacheFuzzerEnabled()) {
            cacheFuzzerSwitch.setEnabled(masterState);
        }
    }

    private double calculateRequestsPerSecond(int refillRate, long refillIntervalMillis) {
        if (refillRate == 0) return 0;
        return (double) refillRate * (1000.0 / refillIntervalMillis);
    }

    @FunctionalInterface
    private interface SwitchChangeListener {
        void onSwitchChanged(boolean selected);
    }
}