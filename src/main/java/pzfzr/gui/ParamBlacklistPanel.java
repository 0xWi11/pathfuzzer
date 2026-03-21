package pzfzr.gui;

import pzfzr.core.ParamBlacklist;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

/**
 * 参数黑名单配置面板
 */
public class ParamBlacklistPanel extends JPanel implements ParamBlacklist.BlacklistChangeListener {
    private final ParamBlacklist blacklist;
    private final JTextArea textArea;
    private final JLabel countLabel;
    private final JLabel statusLabel;
    private final JCheckBox autoSyncCheckBox;
    private final JButton applyButton;
    private final JButton clearButton;
    private boolean isUpdatingFromBlacklist = false;

    public ParamBlacklistPanel() {
        this.blacklist = ParamBlacklist.getInstance();

        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        textArea = new JTextArea(15, 40);
        textArea.setLineWrap(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textArea.setText(blacklist.toText());

        countLabel = new JLabel("当前项数: 0");
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD));

        statusLabel = new JLabel("就绪");
        statusLabel.setForeground(new Color(0, 128, 0));

        autoSyncCheckBox = new JCheckBox("自动同步", true);
        autoSyncCheckBox.setToolTipText("勾选后，文本框内容会实时同步到黑名单");
        autoSyncCheckBox.addActionListener(e -> {
            if (autoSyncCheckBox.isSelected()) {
                syncToBlacklist();
                setStatus("已启用自动同步", new Color(0, 128, 0));
            } else {
                setStatus("已禁用自动同步，点击\"应用黑名单\"按钮生效", new Color(255, 140, 0));
            }
        });

        applyButton = new JButton("应用黑名单");
        applyButton.setToolTipText("将文本框内容应用到黑名单");
        applyButton.addActionListener(e -> applyBlacklist());

        clearButton = new JButton("清空全部");
        clearButton.setToolTipText("清空所有黑名单项");
        clearButton.addActionListener(e -> clearBlacklist());

        textArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { onTextChanged(); }
            @Override public void removeUpdate(DocumentEvent e)  { onTextChanged(); }
            @Override public void changedUpdate(DocumentEvent e) { onTextChanged(); }
        });

        JPanel infoPanel = createInfoPanel();
        add(infoPanel, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("黑名单项（每行一个）"));
        add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = createBottomPanel();
        add(bottomPanel, BorderLayout.SOUTH);

        blacklist.addListener(this);
        updateCount();
    }

    private JPanel createInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        // ★ 说明文字中 JSON 参数示例统一加 $ 前缀
        JTextArea infoText = new JTextArea(
                "参数黑名单：跳过指定参数的测试\n" +
                        "• JSON参数：使用 $ 开头的 JSONPath 格式（如：$.user.info.name 或 $.data.items[0].id）\n" +
                        "• URL/Body参数：使用参数名（如：username 或 id）\n" +
                        "• 前缀匹配：支持跳过整个对象（如：$.tasks[0] 会跳过 $.tasks[0].task_id、$.tasks[0].payload 等所有子参数）\n" +
                        "• 匹配规则：完全匹配 + 前缀匹配（区分大小写）\n" +
                        "• 注意：黑名单仅在当前会话有效，不会持久化保存"
        );
        infoText.setEditable(false);
        infoText.setBackground(panel.getBackground());
        infoText.setFont(infoText.getFont().deriveFont(Font.PLAIN, 11f));
        infoText.setWrapStyleWord(true);
        infoText.setLineWrap(true);
        infoText.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200)),
                new EmptyBorder(5, 5, 5, 5)
        ));

        panel.add(infoText, BorderLayout.CENTER);

        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        statsPanel.add(countLabel);
        statsPanel.add(new JSeparator(SwingConstants.VERTICAL));
        statsPanel.add(new JLabel("状态:"));
        statsPanel.add(statusLabel);
        panel.add(statsPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        leftPanel.add(autoSyncCheckBox);
        panel.add(leftPanel, BorderLayout.WEST);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        buttonPanel.add(applyButton);
        buttonPanel.add(clearButton);

        JButton refreshButton = new JButton("刷新显示");
        refreshButton.setToolTipText("从黑名单重新加载文本");
        refreshButton.addActionListener(e -> refreshDisplay());
        buttonPanel.add(refreshButton);

        panel.add(buttonPanel, BorderLayout.EAST);
        return panel;
    }

    private void onTextChanged() {
        if (isUpdatingFromBlacklist) return;
        if (autoSyncCheckBox.isSelected()) {
            syncToBlacklist();
        } else {
            setStatus("文本已修改，点击\"应用黑名单\"生效", new Color(255, 140, 0));
        }
    }

    private void syncToBlacklist() {
        blacklist.setFromText(textArea.getText());
        setStatus("已同步", new Color(0, 128, 0));
    }

    private void applyBlacklist() {
        String text = textArea.getText();
        if (text == null || text.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "文本框为空，请输入黑名单项。", "没有输入", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        blacklist.setFromText(text);
        setStatus("应用成功", new Color(0, 128, 0));
        JOptionPane.showMessageDialog(this,
                String.format("黑名单已更新\n当前项数: %d", blacklist.size()),
                "更新成功", JOptionPane.INFORMATION_MESSAGE);
    }

    private void clearBlacklist() {
        if (blacklist.isEmpty()) {
            JOptionPane.showMessageDialog(this, "黑名单已经是空的。", "已为空", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this,
                String.format("确定要清空全部 %d 个黑名单项吗？", blacklist.size()),
                "确认清空", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            blacklist.clear();
            refreshDisplay();
            setStatus("已清空", new Color(0, 128, 0));
            JOptionPane.showMessageDialog(this, "黑名单已清空。", "清空成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void refreshDisplay() {
        isUpdatingFromBlacklist = true;
        textArea.setText(blacklist.toText());
        isUpdatingFromBlacklist = false;
        updateCount();
        setStatus("已刷新", new Color(0, 128, 0));
    }

    private void updateCount() {
        int count = blacklist.size();
        countLabel.setText(String.format("当前项数: %d", count));
        if (count == 0)       countLabel.setForeground(Color.GRAY);
        else if (count < 10)  countLabel.setForeground(new Color(0, 128, 0));
        else if (count < 50)  countLabel.setForeground(new Color(255, 140, 0));
        else                  countLabel.setForeground(new Color(220, 20, 60));
    }

    private void setStatus(String text, Color color) {
        statusLabel.setText(text);
        statusLabel.setForeground(color);
    }

    @Override
    public void onBlacklistChanged() {
        SwingUtilities.invokeLater(() -> {
            updateCount();
            if (!isUpdatingFromBlacklist && autoSyncCheckBox.isSelected()) {
                isUpdatingFromBlacklist = true;
                textArea.setText(blacklist.toText());
                isUpdatingFromBlacklist = false;
            }
        });
    }

    public void cleanup() {
        blacklist.removeListener(this);
    }
}