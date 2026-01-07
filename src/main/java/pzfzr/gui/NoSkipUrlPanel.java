package pzfzr.gui;

import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * URL 正则表达式配置面板
 * 用于配置不跳过去重机制的 URL 正则表达式
 */
public class NoSkipUrlPanel extends JPanel {
    private final DefaultListModel<String> listModel;
    private final JList<String> regexList;
    private final JTextField regexInputField;
    private final JButton addButton;
    private final JButton addWildcardButton;  // 新增：通配符添加按钮
    private final JButton deleteButton;
    private final JLabel statusLabel;
    private Timer statusTimer;

    public NoSkipUrlPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 创建顶部说明面板
        JPanel descriptionPanel = createDescriptionPanel();
        add(descriptionPanel, BorderLayout.NORTH);

        // 创建中心列表面板
        JPanel centerPanel = createCenterPanel();
        add(centerPanel, BorderLayout.CENTER);

        // 创建底部输入面板
        JPanel bottomPanel = createBottomPanel();
        add(bottomPanel, BorderLayout.SOUTH);

        // 初始化列表模型和列表
        listModel = new DefaultListModel<>();
        regexList = new JList<>(listModel);
        regexList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        regexList.setFont(new Font("Monospaced", Font.PLAIN, 12));

        // 添加默认的 graphql 正则（不区分大小写）
        addRegexToList("(?i).*graphql.*");

        JScrollPane scrollPane = new JScrollPane(regexList);
        scrollPane.setPreferredSize(new Dimension(500, 300));
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        // 创建输入字段
        regexInputField = new JTextField(30);
        regexInputField.setFont(new Font("Monospaced", Font.PLAIN, 12));

        // 添加回车键监听
        regexInputField.addActionListener(e -> addRegex());

        // 创建按钮
        addButton = new JButton("Add");
        addWildcardButton = new JButton("Add Wildcard");  // 新增：通配符按钮
        deleteButton = new JButton("Delete");

        addButton.addActionListener(e -> addRegex());
        addWildcardButton.addActionListener(e -> addWildcardRegex());  // 新增：通配符按钮事件
        deleteButton.addActionListener(e -> deleteSelectedRegex());

        // 状态标签
        statusLabel = new JLabel(" ");
        statusLabel.setForeground(new Color(0, 128, 0));

        // 组装底部面板
        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        inputPanel.add(new JLabel("Regex Pattern:"));
        inputPanel.add(regexInputField);
        inputPanel.add(addButton);
        inputPanel.add(addWildcardButton);  // 新增：添加通配符按钮到面板
        inputPanel.add(deleteButton);

        bottomPanel.add(inputPanel, BorderLayout.NORTH);
        bottomPanel.add(statusLabel, BorderLayout.SOUTH);
    }

    /**
     * 创建说明面板
     */
    private JPanel createDescriptionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Description"));

        JTextArea descArea = new JTextArea(
                "Configure URL regex patterns that should NOT skip the deduplication mechanism.\n" +
                        "When a URL matches any of these patterns AND the source is NOT 'RouteFuzzer', " +
                        "the request will be tested.\n" +
                        "Example: (?i).*graphql.* (case-insensitive match for 'graphql')\n" +
                        "Use 'Add Wildcard' button to automatically wrap text with .* (e.g., '123' becomes '.*123.*')"
        );
        descArea.setEditable(false);
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setBackground(panel.getBackground());
        descArea.setFont(descArea.getFont().deriveFont(Font.PLAIN, 11f));

        panel.add(descArea, BorderLayout.CENTER);
        return panel;
    }

    /**
     * 创建中心列表面板
     */
    private JPanel createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Regex Patterns"));
        return panel;
    }

    /**
     * 创建底部输入面板
     */
    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Add/Delete Patterns"));
        return panel;
    }

    /**
     * 添加正则表达式
     */
    private void addRegex() {
        String regex = regexInputField.getText().trim();

        if (regex.isEmpty()) {
            showStatus("Please enter a regex pattern", false);
            return;
        }

        // 验证正则表达式
        if (!isValidRegex(regex)) {
            showStatus("Invalid regex pattern: " + regex, false);
            return;
        }

        // 检查是否已存在
        if (listModel.contains(regex)) {
            showStatus("Pattern already exists", false);
            return;
        }

        // 添加到列表
        addRegexToList(regex);
        regexInputField.setText("");
        showStatus("Pattern added successfully", true);
    }

    /**
     * 新增：添加通配符正则表达式
     * 将输入的文本转换为 .*文本.* 格式
     */
    private void addWildcardRegex() {
        String input = regexInputField.getText().trim();

        if (input.isEmpty()) {
            showStatus("Please enter text for wildcard pattern", false);
            return;
        }

        // 转换为通配符格式
        String regex = ".*" + input + ".*";

        // 验证正则表达式
        if (!isValidRegex(regex)) {
            showStatus("Invalid regex pattern: " + regex, false);
            return;
        }

        // 检查是否已存在
        if (listModel.contains(regex)) {
            showStatus("Pattern already exists", false);
            return;
        }

        // 添加到列表
        addRegexToList(regex);
        regexInputField.setText("");
        showStatus("Wildcard pattern added: " + regex, true);
    }

    /**
     * 添加正则到列表（内部方法）
     */
    private void addRegexToList(String regex) {
        listModel.addElement(regex);
    }

    /**
     * 删除选中的正则表达式
     */
    private void deleteSelectedRegex() {
        int selectedIndex = regexList.getSelectedIndex();

        if (selectedIndex == -1) {
            showStatus("Please select a pattern to delete", false);
            return;
        }

        String removedRegex = listModel.getElementAt(selectedIndex);
        listModel.remove(selectedIndex);
        showStatus("Pattern deleted: " + removedRegex, true);

        // 选中下一个项目
        if (listModel.getSize() > 0) {
            int newIndex = Math.min(selectedIndex, listModel.getSize() - 1);
            regexList.setSelectedIndex(newIndex);
        }
    }

    /**
     * 验证正则表达式是否有效
     */
    private boolean isValidRegex(String regex) {
        try {
            Pattern.compile(regex);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    /**
     * 显示状态消息
     */
    private void showStatus(String message, boolean success) {
        statusLabel.setText(message);
        statusLabel.setForeground(success ? new Color(0, 128, 0) : new Color(200, 0, 0));

        // 停止现有的定时器
        if (statusTimer != null && statusTimer.isRunning()) {
            statusTimer.stop();
        }

        // 3秒后清除消息
        statusTimer = new Timer(3000, e -> statusLabel.setText(" "));
        statusTimer.setRepeats(false);
        statusTimer.start();
    }

    /**
     * 获取所有正则表达式列表
     */
    public List<String> getAllRegexPatterns() {
        List<String> patterns = new ArrayList<>();
        for (int i = 0; i < listModel.getSize(); i++) {
            patterns.add(listModel.getElementAt(i));
        }
        return patterns;
    }

    /**
     * 设置正则表达式列表（用于加载配置）
     */
    public void setRegexPatterns(List<String> patterns) {
        listModel.clear();
        if (patterns != null && !patterns.isEmpty()) {
            for (String pattern : patterns) {
                if (isValidRegex(pattern)) {
                    listModel.addElement(pattern);
                }
            }
        }
        // 如果列表为空，添加默认值
        if (listModel.isEmpty()) {
            addRegexToList("(?i).*graphql.*");
        }
    }

    /**
     * 清理资源
     */
    public void cleanup() {
        if (statusTimer != null && statusTimer.isRunning()) {
            statusTimer.stop();
        }
    }
}