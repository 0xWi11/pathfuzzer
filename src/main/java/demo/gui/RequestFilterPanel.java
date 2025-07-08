package demo.gui;

import demo.config.FilterRule;
import demo.config.ConfigManager;
import demo.config.ConfigChangeType;
import demo.config.ConfigChangeListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Objects;

public class RequestFilterPanel extends JPanel implements ConfigChangeListener {
    private final JList<FilterRule> ruleList;
    private final DefaultListModel<FilterRule> ruleModel;
    private final ConfigManager configManager;

    public RequestFilterPanel(ConfigManager configManager) {
        this.configManager = configManager;
        setLayout(new BorderLayout(10, 10));

        configManager.addListener(this);

        // Rule List
        ruleModel = new DefaultListModel<>();
        ruleList = new JList<>(ruleModel);
        ruleList.setCellRenderer(new RuleListCellRenderer());
        JScrollPane ruleScroll = new JScrollPane(ruleList);
        ruleScroll.setBorder(BorderFactory.createTitledBorder("Filter Rules"));

        // Buttons Panel
        JPanel buttonPanel = new JPanel();
        JButton addButton = new JButton("Add Rule");
        JButton removeButton = new JButton("Remove Rule");
        JButton editButton = new JButton("Edit Rule");

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(editButton);

        add(ruleScroll, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // Add Rule Button Action
        addButton.addActionListener(this::showAddRuleDialog);

        // Remove Rule Button Action
        removeButton.addActionListener(e -> {
            FilterRule selectedRule = ruleList.getSelectedValue();
            if (selectedRule != null) {
                int selectedIndex = ruleList.getSelectedIndex();
                ruleModel.removeElement(selectedRule);
                configManager.removeFilterRule(selectedRule);  // 使用新的方法名

                if (ruleModel.size() > 0) {
                    int newIndex = selectedIndex < ruleModel.size() ? selectedIndex : ruleModel.size() - 1;
                    ruleList.setSelectedIndex(newIndex);
                }
            }
        });

        // Edit Rule Button Action
        editButton.addActionListener(e -> {
            FilterRule selectedRule = ruleList.getSelectedValue();
            if (selectedRule != null) {
                showEditRuleDialog(selectedRule);
            }
        });

        refreshRuleList();
    }
    @Override
    public void onConfigChanged(ConfigChangeType type) {
        // 当过滤规则发生变化时刷新列表
        if (type == ConfigChangeType.FILTER_RULES) {
            refreshRuleList();
        }
    }
    private void showAddRuleDialog(ActionEvent e) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Add Rule", true);
        dialog.setLayout(new BorderLayout(10, 10));

        // 设置对话框大小和位置
        dialog.setSize(400, 300);
        dialog.setLocationRelativeTo(this);

        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Rule Type Selection
        JComboBox<FilterRule.RuleType> typeCombo = new JComboBox<>(FilterRule.RuleType.values());
        JComboBox<FilterRule.RuleMatchType> matchTypeCombo = new JComboBox<>(FilterRule.RuleMatchType.values());

        // 动态输入面板
        JPanel valueInputPanel = new JPanel(new CardLayout());

        // 文本输入
        JTextField textValueField = new JTextField(20);

        // Tool Source 下拉框

        // In Scope 单选按钮
        JPanel inScopePanel = new JPanel();
        ButtonGroup scopeGroup = new ButtonGroup();
        JRadioButton inScopeTrue = new JRadioButton("True");
        JRadioButton inScopeFalse = new JRadioButton("False");
        scopeGroup.add(inScopeTrue);
        scopeGroup.add(inScopeFalse);
        inScopePanel.add(inScopeTrue);
        inScopePanel.add(inScopeFalse);
        inScopeTrue.setSelected(true);

        // HTTP Method 下拉框
        JComboBox<FilterRule.HttpMethod> httpMethodCombo = new JComboBox<>(FilterRule.HttpMethod.values());

        // 添加到卡片布局
        valueInputPanel.add(textValueField, "TEXT");
        valueInputPanel.add(inScopePanel, "SCOPE");
        valueInputPanel.add(httpMethodCombo, "METHOD");

        // 添加规则类型选择的监听器
        typeCombo.addActionListener(evt -> {
            CardLayout cl = (CardLayout) valueInputPanel.getLayout();
            FilterRule.RuleType selectedType = (FilterRule.RuleType) typeCombo.getSelectedItem();

            switch (Objects.requireNonNull(selectedType)) {

                case IN_SCOPE:
                    cl.show(valueInputPanel, "SCOPE");
                    matchTypeCombo.setEnabled(false);
                    break;
                case HTTP_METHOD:
                    cl.show(valueInputPanel, "METHOD");
                    matchTypeCombo.setEnabled(false);
                    break;
                default:
                    cl.show(valueInputPanel, "TEXT");
                    matchTypeCombo.setEnabled(true);
                    break;
            }
        });

        // 布局组件
        gbc.gridx = 0; gbc.gridy = 0;
        inputPanel.add(new JLabel("Rule Type:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(typeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        inputPanel.add(new JLabel("Match Type:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(matchTypeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        inputPanel.add(new JLabel("Value:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(valueInputPanel, gbc);

        // Buttons
        JPanel buttonPanel = new JPanel();
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);

        okButton.addActionListener(evt -> {
            FilterRule.RuleType selectedType = (FilterRule.RuleType) typeCombo.getSelectedItem();
            String value;

            switch (Objects.requireNonNull(selectedType)) {
                case IN_SCOPE:
                    value = String.valueOf(inScopeTrue.isSelected());
                    break;
                case HTTP_METHOD:
                    value = ((FilterRule.HttpMethod) httpMethodCombo.getSelectedItem()).name();
                    break;
                default:
                    value = textValueField.getText();
            }

            FilterRule rule = new FilterRule(
                    value,
                    selectedType,
                    (FilterRule.RuleMatchType) matchTypeCombo.getSelectedItem()
            );

            configManager.addFilterRule(rule);
            dialog.dispose();
        });

        cancelButton.addActionListener(evt -> dialog.dispose());

        dialog.add(inputPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setVisible(true);
    }

    private void showEditRuleDialog(FilterRule rule) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Edit Rule", true);
        dialog.setLayout(new BorderLayout(10, 10));

        // 设置对话框大小和位置
        dialog.setSize(400, 300);
        dialog.setLocationRelativeTo(this);

        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Rule Type Selection
        JComboBox<FilterRule.RuleType> typeCombo = new JComboBox<>(FilterRule.RuleType.values());
        typeCombo.setSelectedItem(rule.getType());

        JComboBox<FilterRule.RuleMatchType> matchTypeCombo = new JComboBox<>(FilterRule.RuleMatchType.values());
        matchTypeCombo.setSelectedItem(rule.getMatchType());

        // Dynamic input panel
        JPanel valueInputPanel = new JPanel(new CardLayout());

        // Text input
        JTextField textValueField = new JTextField(rule.getValue(), 20);

        // Tool Source dropdown


        // In Scope radio buttons
        JPanel inScopePanel = new JPanel();
        ButtonGroup scopeGroup = new ButtonGroup();
        JRadioButton inScopeTrue = new JRadioButton("True");
        JRadioButton inScopeFalse = new JRadioButton("False");
        scopeGroup.add(inScopeTrue);
        scopeGroup.add(inScopeFalse);
        inScopePanel.add(inScopeTrue);
        inScopePanel.add(inScopeFalse);

        if (rule.getType() == FilterRule.RuleType.IN_SCOPE) {
            boolean isInScope = Boolean.parseBoolean(rule.getValue());
            inScopeTrue.setSelected(isInScope);
            inScopeFalse.setSelected(!isInScope);
        }

        // HTTP Method combo
        JComboBox<FilterRule.HttpMethod> httpMethodCombo = new JComboBox<>(FilterRule.HttpMethod.values());
        if (rule.getType() == FilterRule.RuleType.HTTP_METHOD) {
            httpMethodCombo.setSelectedItem(FilterRule.HttpMethod.valueOf(rule.getValue()));
        }

        // Add to card layout
        valueInputPanel.add(textValueField, "TEXT");
        valueInputPanel.add(inScopePanel, "SCOPE");
        valueInputPanel.add(httpMethodCombo, "METHOD");

        // Show the correct input panel based on rule type
        CardLayout cl = (CardLayout) valueInputPanel.getLayout();
        switch (rule.getType()) {

            case IN_SCOPE:
                cl.show(valueInputPanel, "SCOPE");
                matchTypeCombo.setEnabled(false);
                break;
            case HTTP_METHOD:
                cl.show(valueInputPanel, "METHOD");
                matchTypeCombo.setEnabled(false);
                break;
            default:
                cl.show(valueInputPanel, "TEXT");
                matchTypeCombo.setEnabled(true);
                break;
        }

        // Add type selection listener
        typeCombo.addActionListener(evt -> {
            FilterRule.RuleType selectedType = (FilterRule.RuleType) typeCombo.getSelectedItem();
            switch (Objects.requireNonNull(selectedType)) {

                case IN_SCOPE:
                    cl.show(valueInputPanel, "SCOPE");
                    matchTypeCombo.setEnabled(false);
                    break;
                case HTTP_METHOD:
                    cl.show(valueInputPanel, "METHOD");
                    matchTypeCombo.setEnabled(false);
                    break;
                default:
                    cl.show(valueInputPanel, "TEXT");
                    matchTypeCombo.setEnabled(true);
                    break;
            }
        });

        // Layout components
        gbc.gridx = 0; gbc.gridy = 0;
        inputPanel.add(new JLabel("Rule Type:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(typeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        inputPanel.add(new JLabel("Match Type:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(matchTypeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        inputPanel.add(new JLabel("Value:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(valueInputPanel, gbc);

        // Buttons
        JPanel buttonPanel = new JPanel();
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);

        okButton.addActionListener(evt -> {
            FilterRule.RuleType selectedType = (FilterRule.RuleType) typeCombo.getSelectedItem();
            String value;

            switch (Objects.requireNonNull(selectedType)) {
                case IN_SCOPE:
                    value = String.valueOf(inScopeTrue.isSelected());
                    break;
                case HTTP_METHOD:
                    value = ((FilterRule.HttpMethod) httpMethodCombo.getSelectedItem()).name();
                    break;
                default:
                    value = textValueField.getText();
            }

            FilterRule updatedRule = new FilterRule(
                    value,
                    selectedType,
                    (FilterRule.RuleMatchType) matchTypeCombo.getSelectedItem()
            );

            configManager.updateFilterRule(rule, updatedRule);
            dialog.dispose();
        });

        cancelButton.addActionListener(evt -> dialog.dispose());

        dialog.add(inputPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setVisible(true);
    }

    private void refreshRuleList() {
        ruleModel.clear();
        configManager.getFilterRules().forEach(ruleModel::addElement);
    }


    private static class RuleListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            if (value instanceof FilterRule) {
                FilterRule rule = (FilterRule) value;
                setText(String.format("%s [%s] %s", rule.getType(), rule.getMatchType(), rule.getValue()));
            }

            return this;
        }
    }
}