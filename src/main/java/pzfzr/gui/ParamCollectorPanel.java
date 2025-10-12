package pzfzr.gui;

import pzfzr.core.ParamCollector;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * ParamCollectorPanel - 参数收集器UI面板（带资源清理）
 */
public class ParamCollectorPanel extends JPanel {
    private final ParamCollector paramCollector;
    private final JTextArea textArea;
    private final JLabel countLabel;
    private final JLabel statusLabel;
    private final List<Timer> activeTimers = new ArrayList<>(); // 跟踪活动的 Timer

    public ParamCollectorPanel(ParamCollector paramCollector) {
        this.paramCollector = paramCollector;
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 顶部面板 - 显示参数数量和按钮
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        // 左侧：参数数量标签
        countLabel = new JLabel("Collected Parameters: 0");
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD, 14f));
        topPanel.add(countLabel, BorderLayout.WEST);

        // 右侧：按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));

        JButton syncButton = new JButton("Sync from Memory");
        syncButton.setToolTipText("Synchronize content from memory to text area");
        syncButton.addActionListener(e -> syncFromMemory());

        JButton updateButton = new JButton("Update to Memory");
        updateButton.setToolTipText("Update memory with current text content");
        updateButton.addActionListener(e -> updateToMemory());

        JButton clearButton = new JButton("Clear All");
        clearButton.setToolTipText("Clear all collected parameters");
        clearButton.addActionListener(e -> clearAll());

        buttonPanel.add(syncButton);
        buttonPanel.add(updateButton);
        buttonPanel.add(clearButton);

        topPanel.add(buttonPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);

        // 中间面板 - 文本区域
        textArea = new JTextArea();
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textArea.setLineWrap(false);
        textArea.setWrapStyleWord(false);

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Parameters (Format: url,position,type,key=value)"));

        add(scrollPane, BorderLayout.CENTER);

        // 底部面板 - 说明信息和状态
        JPanel bottomPanel = new JPanel(new BorderLayout());

        // 状态标签（用于显示错误信息）
        statusLabel = new JLabel(" ");
        statusLabel.setForeground(Color.RED);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        bottomPanel.add(statusLabel, BorderLayout.NORTH);

        // 说明信息
        JTextArea infoArea = new JTextArea(
                "Format: url,position,type,key=value | " +
                        "Position: get, post, post-json, resp-json, cookie | " +
                        "Type: string, number, boolean, null | " +
                        "Example: https://example.com/api,post-json,number,id=55"
        );
        infoArea.setEditable(false);
        infoArea.setBackground(getBackground());
        infoArea.setFont(new Font("Monospaced", Font.PLAIN, 10));
        infoArea.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        bottomPanel.add(infoArea, BorderLayout.CENTER);

        add(bottomPanel, BorderLayout.SOUTH);

        // 初始加载
        syncFromMemory();
    }

    /**
     * 从内存同步到文本区域
     */
    private void syncFromMemory() {
        SwingUtilities.invokeLater(() -> {
            String text = paramCollector.getAllParamsAsText();
            textArea.setText(text);
            updateCountLabel();
            clearStatus();
        });
    }

    /**
     * 从文本区域更新到内存（无弹窗）
     */
    private void updateToMemory() {
        String text = textArea.getText();
        String error = paramCollector.updateFromText(text);

        if (error != null) {
            // 显示错误（保留错误提示弹窗，因为这是验证性提示）
            JOptionPane.showMessageDialog(
                    this,
                    error,
                    "Update Error",
                    JOptionPane.ERROR_MESSAGE
            );
        } else {
            // 更新成功，显示状态
            updateCountLabel();
        }
    }

    /**
     * 清空所有参数（无确认弹窗）
     */
    private void clearAll() {
        textArea.setText("");
        paramCollector.updateFromText("");
        updateCountLabel();
        showStatus("All parameters cleared");
        // 2秒后清除消息
        scheduleStatusClear(2000);
    }

    /**
     * 更新参数数量标签
     */
    private void updateCountLabel() {
        int count = paramCollector.getParamCount();
        countLabel.setText("Collected Parameters: " + count);
    }

    /**
     * 显示状态信息
     */
    private void showStatus(String message) {
        statusLabel.setText(message);
    }

    /**
     * 清除状态信息
     */
    private void clearStatus() {
        statusLabel.setText(" ");
    }

    /**
     * 安排延迟清除状态（管理 Timer）
     */
    private void scheduleStatusClear(int delayMs) {
        Timer timer = new Timer(delayMs, e -> {
            clearStatus();
            activeTimers.remove(e.getSource()); // 从列表中移除
        });
        timer.setRepeats(false);
        activeTimers.add(timer);
        timer.start();
    }

    /**
     * 清理资源（在插件卸载时调用）
     */
    public void cleanup() {
        // 停止所有活动的 Timer
        for (Timer timer : activeTimers) {
            if (timer.isRunning()) {
                timer.stop();
            }
        }
        activeTimers.clear();
    }

    /**
     * 获取 ParamCollector 实例
     */
    public ParamCollector getParamCollector() {
        return paramCollector;
    }
}