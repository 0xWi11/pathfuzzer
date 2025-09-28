package pzfzr.gui;

import pzfzr.config.SwitchManager;
import pzfzr.core.RateLimiter;
import pzfzr.core.RequestDeduplicator;
import pzfzr.core.TrafficHandler;
import pzfzr.fuzzer.ParamFuzzer;
import pzfzr.fuzzer.ParamDeleter;
import pzfzr.fuzzer.HeaderFuzzer;
import pzfzr.fuzzer.CookieFuzzer;
import pzfzr.fuzzer.OOBParamFuzzer; // 新增：OOBParamFuzzer导入
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
    private final JCheckBox headerFuzzerSwitch;
    private final JCheckBox cookieFuzzerSwitch;
    private final JCheckBox oobParamFuzzerSwitch; // 新增：OOBParamFuzzer开关
    private final JButton clearHashesButton;
    private final JButton exportCSVButton;
    private final JButton openFolderButton;
    private final SwitchManager switchManager;
    private final Logging logging;
    private final CSVExporter csvExporter;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final ParamFuzzer paramFuzzer;
    private final ParamDeleter paramDeleter;
    private final HeaderFuzzer headerFuzzer;
    private final CookieFuzzer cookieFuzzer;
    private final OOBParamFuzzer oobParamFuzzer; // 新增：OOBParamFuzzer引用
    private final JTextField newCapacityTextField;
    private final JTextField newRefillRateTextField;
    private final JTextField newUrlRateLimitTextField;
    private final JTextField newUrlExpireTimeTextField;
    private final JTextField newRefillIntervalTextField;
    private final JTextField maxHeadersPerBatchTextField;
    private final JTextField maxParameterCountTextField;
    private final JTextField maxParameterCountDeleterTextField;
    private final JTextField maxParameterCountCookieTextField;
    private final JTextField maxParameterCountOOBTextField; // 新增：OOBParamFuzzer最大参数数量输入框
    private final JButton setRateLimitButton;
    private final JButton clearTasksButton;
    private final TrafficHandler trafficHandler;
    private final JLabel requestsPerHourLabel;
    private final JButton cancelActiveTasksButton;

    public SwitchPanel(Logging logging, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, TrafficHandler trafficHandler, ParamFuzzer paramFuzzer,
                       ParamDeleter paramDeleter, HeaderFuzzer headerFuzzer, CookieFuzzer cookieFuzzer,
                       OOBParamFuzzer oobParamFuzzer) { // 修改：添加OOBParamFuzzer参数
        this.switchManager = SwitchManager.getInstance();
        this.logging = logging;
        this.requestResponseSaver = requestResponseSaver;
        this.csvExporter = new CSVExporter(logging, tableModel, requestResponseSaver);
        this.rateLimiter = rateLimiter;
        this.trafficHandler = trafficHandler;
        this.paramFuzzer = paramFuzzer;
        this.paramDeleter = paramDeleter;
        this.headerFuzzer = headerFuzzer;
        this.cookieFuzzer = cookieFuzzer;
        this.oobParamFuzzer = oobParamFuzzer; // 新增：存储OOBParamFuzzer引用

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        JPanel wrapperPanel = new JPanel();
        wrapperPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JPanel switchesPanel = new JPanel();
        switchesPanel.setLayout(new BoxLayout(switchesPanel, BoxLayout.Y_AXIS));

        // 创建开关
        masterSwitch = createSwitch("请求总开关",
                switchManager.isMasterSwitch(),
                selected -> {
                    switchManager.setMasterSwitch(selected);
                    updateSwitchStates();
                });

        builtInSwitch = createSwitch("JsonLister 测试开关",
                switchManager.isJsonListerSwitch(),
                selected -> switchManager.setJsonListerSwitch(selected));

        collectedSwitch = createSwitch("RouteFuzzer 测试开关",
                switchManager.isRoutefuzzerSwitch(),
                selected -> switchManager.setRoutefuzzerSwitch(selected));

        suspiciousSwitch = createSwitch("ParamFuzzer 测试开关",
                switchManager.isParamfuzzerSwitch(),
                selected -> switchManager.setParamfuzzerSwitch(selected));

        paramDeleterSwitch = createSwitch("ParamDeleter 测试开关",
                switchManager.isParamdeleterSwitch(),
                selected -> switchManager.setParamdeleterSwitch(selected));

        headerFuzzerSwitch = createSwitch("HeaderFuzzer 测试开关",
                switchManager.isHeaderfuzzerSwitch(),
                selected -> switchManager.setHeaderfuzzerSwitch(selected));

        cookieFuzzerSwitch = createSwitch("CookieFuzzer 测试开关",
                switchManager.isCookiefuzzerSwitch(),
                selected -> switchManager.setCookiefuzzerSwitch(selected));

        // 新增：OOBParamFuzzer开关
        oobParamFuzzerSwitch = createSwitch("OOBParamFuzzer 测试开关",
                switchManager.isOobparamfuzzerSwitch(),
                selected -> switchManager.setOobparamfuzzerSwitch(selected));

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

        // 修改全局速率限制面板的布局
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
        // 将毫秒转换为秒显示
        newUrlExpireTimeTextField = new JTextField(String.valueOf(rateLimiter.getUrlExpireTime() / 1000), 5);

        urlRateLimitPanel.add(urlRateLabel);
        urlRateLimitPanel.add(newUrlRateLimitTextField);
        urlRateLimitPanel.add(urlExpireLabel);
        urlRateLimitPanel.add(newUrlExpireTimeTextField);
        urlRateLimitPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建参数数量限制设置的UI元素 - 修改为包含OOBParamFuzzer
        JPanel maxParameterPanel = new JPanel();
        maxParameterPanel.setLayout(new BoxLayout(maxParameterPanel, BoxLayout.Y_AXIS));
        maxParameterPanel.setBorder(BorderFactory.createTitledBorder("参数数量限制"));

        // ParamFuzzer参数数量限制
        JPanel paramFuzzerLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel maxParameterLabel = new JLabel("ParamFuzzer最大参数数量:");
        maxParameterCountTextField = new JTextField(String.valueOf(paramFuzzer.getMaxParameterCount()), 5);
        paramFuzzerLimitPanel.add(maxParameterLabel);
        paramFuzzerLimitPanel.add(maxParameterCountTextField);

        // ParamDeleter参数数量限制
        JPanel paramDeleterLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel maxParameterDeleterLabel = new JLabel("ParamDeleter最大参数数量:");
        maxParameterCountDeleterTextField = new JTextField(String.valueOf(paramDeleter.getMaxParameterCount()), 5);
        paramDeleterLimitPanel.add(maxParameterDeleterLabel);
        paramDeleterLimitPanel.add(maxParameterCountDeleterTextField);

        // CookieFuzzer参数数量限制
        JPanel cookieFuzzerLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel maxParameterCookieLabel = new JLabel("CookieFuzzer最大参数数量:");
        maxParameterCountCookieTextField = new JTextField(String.valueOf(cookieFuzzer.getMaxParameterCount()), 5);
        cookieFuzzerLimitPanel.add(maxParameterCookieLabel);
        cookieFuzzerLimitPanel.add(maxParameterCountCookieTextField);

        // 新增：OOBParamFuzzer参数数量限制
        JPanel oobParamFuzzerLimitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel maxParameterOOBLabel = new JLabel("OOBParamFuzzer最大参数数量:");
        maxParameterCountOOBTextField = new JTextField(String.valueOf(oobParamFuzzer.getMaxParameterCount()), 5);
        oobParamFuzzerLimitPanel.add(maxParameterOOBLabel);
        oobParamFuzzerLimitPanel.add(maxParameterCountOOBTextField);

        maxParameterPanel.add(paramFuzzerLimitPanel);
        maxParameterPanel.add(paramDeleterLimitPanel);
        maxParameterPanel.add(cookieFuzzerLimitPanel);
        maxParameterPanel.add(oobParamFuzzerLimitPanel); // 新增：添加OOBParamFuzzer限制面板
        maxParameterPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建设置按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        setRateLimitButton = new JButton("应用设置");
        setRateLimitButton.addActionListener(e -> {
            try {
                int newCapacity = Integer.parseInt(newCapacityTextField.getText());
                int newRefillRate = Integer.parseInt(newRefillRateTextField.getText());
                int newUrlRateLimit = Integer.parseInt(newUrlRateLimitTextField.getText());
                long newUrlExpireTime = Long.parseLong(newUrlExpireTimeTextField.getText()) * 1000; // 转换为毫秒
                long newRefillInterval = Long.parseLong(newRefillIntervalTextField.getText());
                int newMaxHeadersPerBatch = Integer.parseInt(maxHeadersPerBatchTextField.getText());
                int newMaxParameterCount = Integer.parseInt(maxParameterCountTextField.getText()); // ParamFuzzer最大参数数量
                int newMaxParameterCountDeleter = Integer.parseInt(maxParameterCountDeleterTextField.getText()); // ParamDeleter最大参数数量
                int newMaxParameterCountCookie = Integer.parseInt(maxParameterCountCookieTextField.getText()); // CookieFuzzer最大参数数量
                int newMaxParameterCountOOB = Integer.parseInt(maxParameterCountOOBTextField.getText()); // 新增：OOBParamFuzzer最大参数数量

                if (newCapacity > 0 && newRefillRate >= 0 && newUrlRateLimit >= 0 &&
                        newUrlExpireTime >= 0 && newRefillInterval > 0 && newMaxHeadersPerBatch > 0 &&
                        newMaxParameterCount > 0 && newMaxParameterCountDeleter > 0 && newMaxParameterCountCookie > 0 &&
                        newMaxParameterCountOOB > 0) { // 新增：验证OOBParamFuzzer参数
                    // 使用完整的参数列表调用更新方法
                    rateLimiter.updateConfiguration(newCapacity, newRefillRate, newUrlRateLimit,
                            newUrlExpireTime, newRefillInterval, newMaxHeadersPerBatch);

                    // 设置ParamFuzzer的最大参数数量
                    paramFuzzer.setMaxParameterCount(newMaxParameterCount);

                    // 设置ParamDeleter的最大参数数量
                    paramDeleter.setMaxParameterCount(newMaxParameterCountDeleter);

                    // 设置CookieFuzzer的最大参数数量
                    cookieFuzzer.setMaxParameterCount(newMaxParameterCountCookie);

                    // 新增：设置OOBParamFuzzer的最大参数数量
                    oobParamFuzzer.setMaxParameterCount(newMaxParameterCountOOB);

                    // 更新每小时请求数显示 - 使用更新后的值计算
                    double updatedRequestsPerSecond = calculateRequestsPerSecond(newRefillRate, newRefillInterval);
                    int updatedRequestsPerHour = (int)(updatedRequestsPerSecond * 3600);
                    requestsPerHourLabel.setText(String.format("%d req/h | %.2f req/s", updatedRequestsPerHour, updatedRequestsPerSecond));

                    JOptionPane.showMessageDialog(
                            this,
                            "速率限制和参数数量限制已更新",
                            "成功",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } else {
                    JOptionPane.showMessageDialog(
                            this,
                            "容量、令牌添加间隔、每批次最大Header数和最大参数数量必须大于0，其他参数不能为负数",
                            "错误",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(
                        this,
                        "请输入有效的数字",
                        "错误",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        });

        buttonPanel.add(setRateLimitButton);
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建一个新的面板，包含所有速率限制相关的控件
        JPanel rateLimitingContainer = new JPanel();
        rateLimitingContainer.setLayout(new BoxLayout(rateLimitingContainer, BoxLayout.Y_AXIS));
        rateLimitingContainer.add(globalRateLimitPanel);
        rateLimitingContainer.add(urlRateLimitPanel);
        rateLimitingContainer.add(maxParameterPanel);
        rateLimitingContainer.add(buttonPanel);
        rateLimitingContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 创建按钮布局面板
        JPanel buttonsContainer = new JPanel();
        buttonsContainer.setLayout(new BoxLayout(buttonsContainer, BoxLayout.Y_AXIS));
        buttonsContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 第一行：清除URL缓存（单独一行）
        JPanel firstButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        firstButtonRow.add(clearHashesButton);
        firstButtonRow.add(cancelActiveTasksButton);
        firstButtonRow.add(clearTasksButton);
        firstButtonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 第二行：丢弃活跃任务 + 清空待处理任务
        JPanel secondButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        secondButtonRow.add(exportCSVButton);
        secondButtonRow.add(openFolderButton);
        secondButtonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        buttonsContainer.add(firstButtonRow);
        buttonsContainer.add(Box.createVerticalStrut(5));
        buttonsContainer.add(secondButtonRow);

        // 添加固定间距的开关和按钮
        switchesPanel.add(masterSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(builtInSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(collectedSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(suspiciousSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(paramDeleterSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(headerFuzzerSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(cookieFuzzerSwitch);
        switchesPanel.add(Box.createVerticalStrut(5));
        switchesPanel.add(oobParamFuzzerSwitch); // 新增：添加OOBParamFuzzer开关
        switchesPanel.add(Box.createVerticalStrut(10));
        switchesPanel.add(buttonsContainer);
        switchesPanel.add(Box.createVerticalStrut(10));
        switchesPanel.add(rateLimitingContainer);

        wrapperPanel.add(switchesPanel);
        add(wrapperPanel);
        add(Box.createVerticalGlue());

        updateSwitchStates();
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
        builtInSwitch.setEnabled(masterState);
        collectedSwitch.setEnabled(masterState);
        suspiciousSwitch.setEnabled(masterState);
        paramDeleterSwitch.setEnabled(masterState);
        headerFuzzerSwitch.setEnabled(masterState);
        cookieFuzzerSwitch.setEnabled(masterState);
        oobParamFuzzerSwitch.setEnabled(masterState); // 新增：OOBParamFuzzer开关也受主开关控制
    }

    // 修正计算请求数的方法
    private double calculateRequestsPerSecond(int refillRate, long refillIntervalMillis) {
        // 如果refillRate为0，则返回0
        if (refillRate == 0) return 0;

        // 直接计算每秒请求数：refillRate 令牌每 refillIntervalMillis 毫秒
        return (double) refillRate * (1000.0 / refillIntervalMillis);
    }

    @FunctionalInterface
    private interface SwitchChangeListener {
        void onSwitchChanged(boolean selected);
    }
}