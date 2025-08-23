package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.core.CookieChanger;
import pzfzr.core.CookieChanger.HeaderEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * 用于管理 CookieChanger 中请求头条目的面板
 */
public class CookieChangerPanel extends JPanel {

    private final MontoyaApi api;
    private final Logging logging;
    private final CookieChanger cookieChanger;
    private final JTable headerTable;
    private final HeaderTableModel tableModel;

    public CookieChangerPanel(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.cookieChanger = CookieChanger.getInstance();

        // 为主面板使用 BorderLayout 布局
        setLayout(new BorderLayout());

        // 可选：添加标题
        JLabel titleLabel = new JLabel("Cookie & Header Manager", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 10, 5));
        add(titleLabel, BorderLayout.NORTH);

        // 创建一个面板来容纳现有的表格和按钮
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createTitledBorder("Header Entries"));

        // 创建表格模型和表格
        tableModel = new HeaderTableModel();
        headerTable = new JTable(tableModel);

        // 设置表格外观
        headerTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        headerTable.setAutoCreateRowSorter(true);

        // 单元格文本居中对齐
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        for (int i = 0; i < headerTable.getColumnCount(); i++) {
            headerTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }

        // 设置列宽
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(200); // 主机
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(150); // 请求头名称
        headerTable.getColumnModel().getColumn(2).setPreferredWidth(250); // 请求头值

        // 为表格创建滚动面板
        JScrollPane scrollPane = new JScrollPane(headerTable);

        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton deleteButton = new JButton("Delete");
        JButton clearAllButton = new JButton("Clear All");
        JButton refreshButton = new JButton("Refresh");

        // 设置按钮样式保持一致
        Dimension buttonSize = new Dimension(80, 25);
        addButton.setPreferredSize(buttonSize);
        editButton.setPreferredSize(buttonSize);
        deleteButton.setPreferredSize(buttonSize);
        clearAllButton.setPreferredSize(buttonSize);
        refreshButton.setPreferredSize(buttonSize);

        // 为按钮添加动作监听器
        addButton.addActionListener(this::addHeaderEntry);
        editButton.addActionListener(this::editHeaderEntry);
        deleteButton.addActionListener(this::deleteHeaderEntry);
        clearAllButton.addActionListener(this::clearAllEntries);
        refreshButton.addActionListener(e -> refreshTable());

        // 将按钮添加到面板
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(clearAllButton);
        buttonPanel.add(refreshButton);

        // 将滚动面板（表格）和按钮面板添加到主面板
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // 将主面板添加到中心区域
        add(mainPanel, BorderLayout.CENTER);

        // 初始表格刷新
        refreshTable();
    }

    /**
     * 使用 CookieChanger 的最新数据刷新表格
     */
    public void refreshTable() {
        tableModel.refreshData();
    }

    /**
     * 添加新的请求头条目
     */
    private void addHeaderEntry(ActionEvent e) {
        HeaderEntryDialog dialog = new HeaderEntryDialog(SwingUtilities.getWindowAncestor(this), "Add Header Entry");
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            HeaderEntry entry = dialog.getHeaderEntry();
            cookieChanger.storeHeaderEntry(entry);
            refreshTable();
            logging.logToOutput("[CookieChanger] Added new header entry: " + entry.getHost() + " - " + entry.getHeaderName());
        }
    }

    /**
     * 编辑现有的请求头条目
     */
    private void editHeaderEntry(ActionEvent e) {
        int selectedRow = headerTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a header entry to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 将视图索引转换为模型索引，以防表格被排序
        int modelRow = headerTable.convertRowIndexToModel(selectedRow);
        HeaderEntry oldEntry = tableModel.getEntryAt(modelRow);

        HeaderEntryDialog dialog = new HeaderEntryDialog(SwingUtilities.getWindowAncestor(this), "Edit Header Entry", oldEntry);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            HeaderEntry newEntry = dialog.getHeaderEntry();
            cookieChanger.updateHeaderEntry(oldEntry, newEntry);
            refreshTable();
            logging.logToOutput("[CookieChanger] Updated header entry: " + newEntry.getHost() + " - " + newEntry.getHeaderName());
        }
    }

    /**
     * 删除请求头条目
     */
    private void deleteHeaderEntry(ActionEvent e) {
        int selectedRow = headerTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a header entry to delete.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 将视图索引转换为模型索引，以防表格被排序
        int modelRow = headerTable.convertRowIndexToModel(selectedRow);
        HeaderEntry entry = tableModel.getEntryAt(modelRow);

        int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete this header entry?\nHost: " + entry.getHost() + "\nHeader: " + entry.getHeaderName(),
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            cookieChanger.deleteHeaderEntry(entry);
            refreshTable();
            logging.logToOutput("[CookieChanger] Deleted header entry: " + entry.getHost() + " - " + entry.getHeaderName());
        }
    }

    /**
     * 清除所有请求头条目
     */
    private void clearAllEntries(ActionEvent e) {
        int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to clear all header entries?",
                "Confirm Clear All",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            cookieChanger.clearAll();
            refreshTable();
            logging.logToOutput("[CookieChanger] Cleared all header entries");
        }
    }

    /**
     * 请求头条目的表格模型
     */
    private class HeaderTableModel extends AbstractTableModel {
        private final String[] COLUMN_NAMES = {"Host", "Header Name", "Header Value"};
        private List<HeaderEntry> entries = new ArrayList<>();

        public void refreshData() {
            entries = cookieChanger.getAllHeaderEntries();
            fireTableDataChanged();
        }

        public HeaderEntry getEntryAt(int rowIndex) {
            return entries.get(rowIndex);
        }

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            HeaderEntry entry = entries.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    return entry.getHost();
                case 1:
                    return entry.getHeaderName();
                case 2:
                    return entry.getHeaderValue();
                default:
                    return null;
            }
        }
    }

    /**
     * 用于添加或编辑请求头条目的对话框
     */
    private static class HeaderEntryDialog extends JDialog {
        private final JTextField hostField;
        private final JTextField headerNameField;
        private final JTextField headerValueField;
        private boolean confirmed = false;

        public HeaderEntryDialog(Window owner, String title) {
            super(owner, title, ModalityType.APPLICATION_MODAL);

            hostField = new JTextField(30);
            headerNameField = new JTextField(30);
            headerValueField = new JTextField(30);

            initializeDialog();
        }

        public HeaderEntryDialog(Window owner, String title, HeaderEntry entry) {
            super(owner, title, ModalityType.APPLICATION_MODAL);

            hostField = new JTextField(entry.getHost(), 30);
            headerNameField = new JTextField(entry.getHeaderName(), 30);
            headerValueField = new JTextField(entry.getHeaderValue(), 30);

            initializeDialog();
        }

        private void initializeDialog() {
            JPanel panel = new JPanel(new GridBagLayout());
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.insets = new Insets(5, 5, 5, 5);

            // 主机字段
            constraints.gridx = 0;
            constraints.gridy = 0;
            panel.add(new JLabel("Host:"), constraints);

            constraints.gridx = 1;
            constraints.weightx = 1.0;
            panel.add(hostField, constraints);

            // 请求头名称字段
            constraints.gridx = 0;
            constraints.gridy = 1;
            constraints.weightx = 0.0;
            panel.add(new JLabel("Header Name:"), constraints);

            constraints.gridx = 1;
            constraints.weightx = 1.0;
            panel.add(headerNameField, constraints);

            // 请求头值字段
            constraints.gridx = 0;
            constraints.gridy = 2;
            constraints.weightx = 0.0;
            panel.add(new JLabel("Header Value:"), constraints);

            constraints.gridx = 1;
            constraints.weightx = 1.0;
            panel.add(headerValueField, constraints);

            // 按钮
            JButton okButton = new JButton("OK");
            JButton cancelButton = new JButton("Cancel");

            okButton.addActionListener(e -> {
                if (validateFields()) {
                    confirmed = true;
                    dispose();
                }
            });

            cancelButton.addActionListener(e -> dispose());

            JPanel buttonPanel = new JPanel();
            buttonPanel.add(okButton);
            buttonPanel.add(cancelButton);

            constraints.gridx = 0;
            constraints.gridy = 3;
            constraints.gridwidth = 2;
            constraints.weightx = 1.0;
            panel.add(buttonPanel, constraints);

            getContentPane().add(panel);
            pack();
            setLocationRelativeTo(getOwner());
        }

        private boolean validateFields() {
            if (hostField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Host field cannot be empty.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            if (headerNameField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Header Name field cannot be empty.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            return true;
        }

        public boolean isConfirmed() {
            return confirmed;
        }

        public HeaderEntry getHeaderEntry() {
            return new HeaderEntry(
                    hostField.getText().trim(),
                    headerNameField.getText().trim(),
                    headerValueField.getText().trim()
            );
        }
    }
}