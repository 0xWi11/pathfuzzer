package pzfzr.gui;

import pzfzr.core.ParamCollector;

import javax.swing.*;
import java.awt.*;

/**
 * ParamCollectorPanel - 参数收集器UI面板（无弹窗版本）
 */
public class ParamCollectorPanel extends JPanel {
    private final ParamCollector paramCollector;
    private final JTextArea textArea;
    private final JLabel countLabel;

    public ParamCollectorPanel(ParamCollector paramCollector) {
        this.paramCollector = paramCollector;
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 顶部面板 - 显示参数数量和按钮
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        // 参数数量标签
        countLabel = new JLabel("Collected Parameters: 0");
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD, 14f));
        topPanel.add(countLabel, BorderLayout.WEST);

        // 按钮面板
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
        scrollPane.setBorder(BorderFactory.createTitledBorder("Parameters (Format: position,type,key=value)"));

        add(scrollPane, BorderLayout.CENTER);

        // 底部面板 - 说明信息
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

        JTextArea infoArea = new JTextArea(
                "Position: get, post, post-json, resp-json, cookie\n" +
                        "Type: string, number, boolean, null\n" +
                        "Example: post-json,number,id=55"
        );
        infoArea.setEditable(false);
        infoArea.setBackground(getBackground());
        infoArea.setFont(new Font("Monospaced", Font.PLAIN, 10));
        infoArea.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        infoPanel.add(infoArea, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.SOUTH);

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
        });
    }

    /**
     * 从文本区域更新到内存
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
            // 更新成功 - 移除成功弹窗，只更新界面
            updateCountLabel();
        }
    }

    /**
     * 清空所有参数（无确认弹窗）
     */
    private void clearAll() {
        // 直接清空，无需确认
        textArea.setText("");
        paramCollector.updateFromText("");
        updateCountLabel();
    }

    /**
     * 更新参数数量标签
     */
    private void updateCountLabel() {
        int count = paramCollector.getParamCount();
        countLabel.setText("Collected Parameters: " + count);
    }

    /**
     * 获取 ParamCollector 实例
     */
    public ParamCollector getParamCollector() {
        return paramCollector;
    }
}