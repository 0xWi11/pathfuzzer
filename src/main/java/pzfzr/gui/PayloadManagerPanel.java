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
    private final PayloadTableModel headerTableModel; // 新增：Header载荷表格模型
    private final JTable paramTable;
    private final JTable routeTable;
    private final JTable headerTable; // 新增：Header载荷表格

    public PayloadManagerPanel() {
        this.payloadManager = PayloadManager.getInstance();
        this.paramTableModel = new PayloadTableModel(PayloadManager.PayloadType.PARAM);
        this.routeTableModel = new PayloadTableModel(PayloadManager.PayloadType.ROUTE);
        this.headerTableModel = new PayloadTableModel(PayloadManager.PayloadType.HEADER); // 新增

        setLayout(new BorderLayout());

        // 为参数、路由和Header载荷创建选项卡面板
        JTabbedPane tabbedPane = new JTabbedPane();

        // 参数载荷选项卡
        paramTable = createPayloadTable(paramTableModel);
        JPanel paramPanel = createPayloadPanel(paramTable, PayloadManager.PayloadType.PARAM);
        tabbedPane.addTab("Param Payloads", paramPanel);

        // 路由载荷选项卡
        routeTable = createPayloadTable(routeTableModel);
        JPanel routePanel = createPayloadPanel(routeTable, PayloadManager.PayloadType.ROUTE);
        tabbedPane.addTab("Route Payloads", routePanel);

        // 新增：Header载荷选项卡
        headerTable = createPayloadTable(headerTableModel);
        JPanel headerPanel = createPayloadPanel(headerTable, PayloadManager.PayloadType.HEADER);
        tabbedPane.addTab("Header Payloads", headerPanel);

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
            switch (type) {
                case PARAM:
                    payloadManager.setAllParamPayloadsEnabled(true);
                    break;
                case ROUTE:
                    payloadManager.setAllRoutePayloadsEnabled(true);
                    break;
                case HEADER: // 新增：Header类型处理
                    payloadManager.setAllHeaderPayloadsEnabled(true);
                    break;
            }
        });

        disableAllButton.addActionListener(e -> {
            switch (type) {
                case PARAM:
                    payloadManager.setAllParamPayloadsEnabled(false);
                    break;
                case ROUTE:
                    payloadManager.setAllRoutePayloadsEnabled(false);
                    break;
                case HEADER: // 新增：Header类型处理
                    payloadManager.setAllHeaderPayloadsEnabled(false);
                    break;
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
            switch (type) {
                case PARAM:
                    paramTableModel.fireTableDataChanged();
                    break;
                case ROUTE:
                    routeTableModel.fireTableDataChanged();
                    break;
                case HEADER: // 新增：Header类型处理
                    headerTableModel.fireTableDataChanged();
                    break;
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
            switch (type) {
                case PARAM:
                    return payloadManager.getParamPayloads().size();
                case ROUTE:
                    return payloadManager.getRoutePayloads().size();
                case HEADER: // 新增：Header类型处理
                    return payloadManager.getHeaderPayloads().size();
                default:
                    return 0;
            }
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
            List<PayloadInfo> payloads;
            switch (type) {
                case PARAM:
                    payloads = payloadManager.getParamPayloads();
                    break;
                case ROUTE:
                    payloads = payloadManager.getRoutePayloads();
                    break;
                case HEADER: // 新增：Header类型处理
                    payloads = payloadManager.getHeaderPayloads();
                    break;
                default:
                    return null;
            }

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
                switch (type) {
                    case PARAM:
                        payloadManager.setParamPayloadEnabled(rowIndex, enabled);
                        break;
                    case ROUTE:
                        payloadManager.setRoutePayloadEnabled(rowIndex, enabled);
                        break;
                    case HEADER: // 新增：Header类型处理
                        payloadManager.setHeaderPayloadEnabled(rowIndex, enabled);
                        break;
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