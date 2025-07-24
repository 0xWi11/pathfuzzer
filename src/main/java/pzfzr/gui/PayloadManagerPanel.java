// PayloadManagerPanel.java - 管理载荷的UI面板
package pzfzr.gui;

import pzfzr.fuzzer.PayloadInfo;
import pzfzr.fuzzer.PayloadManager;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * 管理载荷启用/禁用状态的UI面板
 */
public class PayloadManagerPanel extends JPanel implements PayloadManager.PayloadChangeListener {
    private final PayloadManager payloadManager;
    private final PayloadTableModel paramTableModel;
    private final PayloadTableModel routeTableModel;
    private final JTable paramTable;
    private final JTable routeTable;

    public PayloadManagerPanel() {
        this.payloadManager = PayloadManager.getInstance();
        this.paramTableModel = new PayloadTableModel(PayloadManager.PayloadType.PARAM);
        this.routeTableModel = new PayloadTableModel(PayloadManager.PayloadType.ROUTE);

        setLayout(new BorderLayout());

        // 为参数和路由载荷创建选项卡面板
        JTabbedPane tabbedPane = new JTabbedPane();

        // 参数载荷选项卡
        paramTable = createPayloadTable(paramTableModel);
        JPanel paramPanel = createPayloadPanel(paramTable, PayloadManager.PayloadType.PARAM);
        tabbedPane.addTab("Param Payloads", paramPanel);

        // 路由载荷选项卡
        routeTable = createPayloadTable(routeTableModel);
        JPanel routePanel = createPayloadPanel(routeTable, PayloadManager.PayloadType.ROUTE);
        tabbedPane.addTab("Route Payloads", routePanel);

        add(tabbedPane, BorderLayout.CENTER);

        // 注册为监听器
        payloadManager.addListener(this);
    }

    private JTable createPayloadTable(PayloadTableModel tableModel) {
        JTable table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowHeight(25);

        // 设置复选框列
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getColumnModel().getColumn(0).setCellRenderer(new CheckBoxRenderer());
        table.getColumnModel().getColumn(0).setCellEditor(new CheckBoxEditor());

        // 设置其他列
        table.getColumnModel().getColumn(1).setPreferredWidth(150);
        table.getColumnModel().getColumn(2).setPreferredWidth(300);

        return table;
    }

    private JPanel createPayloadPanel(JTable table, PayloadManager.PayloadType type) {
        JPanel panel = new JPanel(new BorderLayout());

        // 在滚动面板中添加表格
        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);

        // 添加控制按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton enableAllButton = new JButton("Enable All");
        JButton disableAllButton = new JButton("Disable All");

        enableAllButton.addActionListener(e -> {
            if (type == PayloadManager.PayloadType.PARAM) {
                payloadManager.setAllParamPayloadsEnabled(true);
            } else {
                payloadManager.setAllRoutePayloadsEnabled(true);
            }
        });

        disableAllButton.addActionListener(e -> {
            if (type == PayloadManager.PayloadType.PARAM) {
                payloadManager.setAllParamPayloadsEnabled(false);
            } else {
                payloadManager.setAllRoutePayloadsEnabled(false);
            }
        });

        buttonPanel.add(enableAllButton);
        buttonPanel.add(disableAllButton);

        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    @Override
    public void onPayloadChanged(PayloadManager.PayloadType type) {
        SwingUtilities.invokeLater(() -> {
            if (type == PayloadManager.PayloadType.PARAM) {
                paramTableModel.fireTableDataChanged();
            } else {
                routeTableModel.fireTableDataChanged();
            }
        });
    }

    // 载荷管理的表格模型
    private class PayloadTableModel extends AbstractTableModel {
        private final PayloadManager.PayloadType type;
        private final String[] columnNames = {"Enabled", "Alias", "Payload"};

        public PayloadTableModel(PayloadManager.PayloadType type) {
            this.type = type;
        }

        @Override
        public int getRowCount() {
            return type == PayloadManager.PayloadType.PARAM
                    ? payloadManager.getParamPayloads().size()
                    : payloadManager.getRoutePayloads().size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) {
                return Boolean.class;
            }
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0; // 只有复选框列可编辑
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            List<PayloadInfo> payloads = type == PayloadManager.PayloadType.PARAM
                    ? payloadManager.getParamPayloads()
                    : payloadManager.getRoutePayloads();

            if (rowIndex >= payloads.size()) return null;

            PayloadInfo payload = payloads.get(rowIndex);

            switch (columnIndex) {
                case 0: return payload.isEnabled();
                case 1: return payload.alias;
                case 2: return payload.payload;
                default: return null;
            }
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && value instanceof Boolean) {
                boolean enabled = (Boolean) value;
                if (type == PayloadManager.PayloadType.PARAM) {
                    payloadManager.setParamPayloadEnabled(rowIndex, enabled);
                } else {
                    payloadManager.setRoutePayloadEnabled(rowIndex, enabled);
                }
            }
        }
    }

    // 自定义复选框渲染器
    private class CheckBoxRenderer extends JCheckBox implements TableCellRenderer {
        public CheckBoxRenderer() {
            setHorizontalAlignment(JLabel.CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            setSelected(value != null && (Boolean) value);

            if (isSelected) {
                setBackground(table.getSelectionBackground());
                setForeground(table.getSelectionForeground());
            } else {
                setBackground(table.getBackground());
                setForeground(table.getForeground());
            }

            return this;
        }
    }

    // 自定义复选框编辑器
    private class CheckBoxEditor extends DefaultCellEditor {
        private JCheckBox checkBox;

        public CheckBoxEditor() {
            super(new JCheckBox());
            checkBox = (JCheckBox) getComponent();
            checkBox.setHorizontalAlignment(JLabel.CENTER);
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value,
                                                     boolean isSelected, int row, int column) {
            checkBox.setSelected(value != null && (Boolean) value);
            return checkBox;
        }

        @Override
        public Object getCellEditorValue() {
            return checkBox.isSelected();
        }
    }
}