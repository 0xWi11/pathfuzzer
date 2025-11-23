package pzfzr.gui;

import pzfzr.model.OriginalRequestResponse;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.TableModel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.util.function.BiConsumer;
import javax.swing.table.TableRowSorter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.ArrayList;
import java.util.Comparator;

public class HistoryPanel extends JPanel {
    private final TableModel tableModel;
    private final BiConsumer<OriginalRequestResponse, ModifiedRequestResponse> selectionCallback;
    private JTabbedPane tabbedPane;
    private JTable currentTable;

    public HistoryPanel(TableModel tableModel,
                        BiConsumer<OriginalRequestResponse, ModifiedRequestResponse> selectionCallback) {
        this.tableModel = tableModel;
        this.selectionCallback = selectionCallback;

        setLayout(new BorderLayout());
        createTabbedPane();
    }

    private void createTabbedPane() {
        tabbedPane = new JTabbedPane();

        // 为每个标签页创建独立的表格 - 现在有12个标签页
        JTable allTable = createTable();
        JTable jsonTable = createTable();
        JTable paramTable = createTable();
        JTable paramAddTable = createTable();
        JTable paramDelTable = createTable();
        JTable route1Table = createTable();
        JTable route2Table = createTable();
        JTable generalFuzzTable = createTable();  // 新增：GENERALFUZZ表格
        JTable oobparamTable = createTable();
        JTable cookieTable = createTable();
        JTable headerTable = createTable();

        currentTable = allTable;
        tableModel.setAssociatedTable(currentTable);

        // 添加标签页 - GENERALFUZZ 放在 ROUTE2 之后
        tabbedPane.addTab("All Requests", new JScrollPane(allTable));
        tabbedPane.addTab("JSON", new JScrollPane(jsonTable));
        tabbedPane.addTab("PARAM DEL", new JScrollPane(paramDelTable));
        tabbedPane.addTab("PARAM ADD", new JScrollPane(paramAddTable));
        tabbedPane.addTab("PARAM", new JScrollPane(paramTable));
        tabbedPane.addTab("ROUTE1", new JScrollPane(route1Table));
        tabbedPane.addTab("ROUTE2", new JScrollPane(route2Table));
        tabbedPane.addTab("GENERALFUZZ", new JScrollPane(generalFuzzTable));  // 新增
        tabbedPane.addTab("OOBPARAM", new JScrollPane(oobparamTable));
        tabbedPane.addTab("COOKIE", new JScrollPane(cookieTable));
        tabbedPane.addTab("HEADER", new JScrollPane(headerTable));

        // 添加标签切换监听器 - 更新为11个标签页
        tabbedPane.addChangeListener(e -> {
            int selectedIndex = tabbedPane.getSelectedIndex();
            // 更新当前表格
            currentTable = (JTable) ((JScrollPane) tabbedPane.getSelectedComponent()).getViewport().getView();
            tableModel.setAssociatedTable(currentTable);

            switch (selectedIndex) {
                case 0:
                    tableModel.setFilter("ALL");
                    break;
                case 1:
                    tableModel.setFilter("JSON");
                    break;
                case 2:
                    tableModel.setFilter("PARAM_DELETE");
                    break;
                case 3:
                    tableModel.setFilter("PARAM-ADD");
                    break;
                case 4:
                    tableModel.setFilter("PARAM");
                    break;
                case 5:
                    tableModel.setFilter("ROUTE1");
                    break;
                case 6:
                    tableModel.setFilter("ROUTE2");
                    break;
                case 7:
                    tableModel.setFilter("OOB-GENERALFUZZ");  // 新增
                    break;
                case 8:
                    tableModel.setFilter("PARAM-OOB");
                    break;
                case 9:
                    tableModel.setFilter("COOKIE");
                    break;
                case 10:
                    tableModel.setFilter("HEADER");
                    break;
            }
        });

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JTable createTable() {
        JTable table = new JTable(tableModel) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        // 关闭表格的自动调整模式，使用固定列宽
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // 将表格行高从20像素减少到16像素（4/5）
        table.setRowHeight(16);

        // 设置表头高度为18像素
        table.getTableHeader().setPreferredSize(new Dimension(0, 18));

        // 创建一个TableRowSorter并设置给表格
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        // 使用优化后的排序设置
        tableModel.setupSorter(table);
        // 应用自定义渲染器
        tableModel.setupTableRenderers(table);

        // 保存每列的排序状态，0=不排序，1=升序，2=降序
        final int[] columnStates = new int[tableModel.getColumnCount()];
        // 保存排序列的顺序，列表中的索引表示排序优先级
        final List<Integer> sortedColumns = new ArrayList<>();

        // 设置自定义的排序器
        for (int i = 0; i < tableModel.getColumnCount(); i++) {
            final int column = i;
            sorter.setComparator(column, (Comparator<Object>) (o1, o2) -> {
                if (o1 == null && o2 == null) return 0;
                if (o1 == null) return -1;
                if (o2 == null) return 1;

                if (o1 instanceof Number && o2 instanceof Number) {
                    return Double.compare(((Number) o1).doubleValue(), ((Number) o2).doubleValue());
                }
                return o1.toString().compareTo(o2.toString());
            });
        }

        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() != MouseEvent.BUTTON1) {
                    return;
                }

                int column = table.columnAtPoint(e.getPoint());
                if (column != -1) {
                    // 切换当前列的排序状态
                    columnStates[column] = (columnStates[column] + 1) % 3;

                    // 根据当前列状态更新排序列表
                    sortedColumns.remove(Integer.valueOf(column)); // 先移除当前列（如果存在）

                    if (columnStates[column] > 0) {
                        // 如果不是不排序状态，将列添加到排序列表的开头（最高优先级）
                        sortedColumns.add(0, column);
                    }

                    // 根据排序列表和各列状态创建排序键
                    List<RowSorter.SortKey> sortKeys = new ArrayList<>();
                    for (Integer sortedColumn : sortedColumns) {
                        if (columnStates[sortedColumn] == 1) {
                            sortKeys.add(new RowSorter.SortKey(sortedColumn, SortOrder.ASCENDING));
                        } else if (columnStates[sortedColumn] == 2) {
                            sortKeys.add(new RowSorter.SortKey(sortedColumn, SortOrder.DESCENDING));
                        }
                    }

                    // 应用排序键
                    if (sortKeys.isEmpty()) {
                        sorter.setSortKeys(null);
                    } else {
                        sorter.setSortKeys(sortKeys);
                    }
                }
            }
        });

        // 增加最大排序键数量，允许多列排序
        sorter.setMaxSortKeys(tableModel.getColumnCount());

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelection(table);
            }
        });

        // 设置列宽 - 使用固定宽度，防止被拉伸
        if (table.getColumnModel().getColumnCount() >= 13) {
            // 辅助方法：设置固定列宽
            setFixedColumnWidth(table, 0, 38);     // ID
            setFixedColumnWidth(table, 1, 38);     // Method
            setFixedColumnWidth(table, 2, 800);    // URL
            setFixedColumnWidth(table, 3, 88);     // Test Type
            setFixedColumnWidth(table, 4, 113);    // Param - 设置为113像素
            setFixedColumnWidth(table, 5, 115);    // Payload - 设置为115像素
            setFixedColumnWidth(table, 6, 38);     // modif status - 保持30像素
            setFixedColumnWidth(table, 7, 60);     // Len Diff - 设置为60像素
            setFixedColumnWidth(table, 8, 60);     // modif len(withoutheader) - 设置为60像素
            setFixedColumnWidth(table, 9, 60);     // modif len+(withheader) - 设置为60像素
            setFixedColumnWidth(table, 10, 60);    // origin len(withoutheader) - 设置为60像素
            setFixedColumnWidth(table, 11, 72);    // Modif. Time
            setFixedColumnWidth(table, 12, 80);    // Reflect
        }

        return table;
    }

    /**
     * 设置列宽（设置首选宽度和最小宽度，允许用户手动调整）
     * @param table 表格对象
     * @param columnIndex 列索引
     * @param width 宽度（像素）
     */
    private void setFixedColumnWidth(JTable table, int columnIndex, int width) {
        TableColumn column = table.getColumnModel().getColumn(columnIndex);
        column.setPreferredWidth(width);
        column.setMinWidth(width);
        // 不设置 setMaxWidth，允许用户手动拖动调整列宽
    }

    private void updateSelection(JTable table) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
            // 将视图索引转换为模型索引
            int modelRow = table.convertRowIndexToModel(selectedRow);

            ModifiedRequestResponse modifiedEntry = tableModel.getModifiedEntry(modelRow);
            if (modifiedEntry != null) {
                OriginalRequestResponse original =
                        tableModel.findByMessageId(modifiedEntry.getOriginalMessageId());
                selectionCallback.accept(original, modifiedEntry);
            }
        }
    }

    public void selectPrevious() {
        if (currentTable != null) {
            int currentRow = currentTable.getSelectedRow();
            if (currentRow > 0) {
                currentTable.setRowSelectionInterval(currentRow - 1, currentRow - 1);
                currentTable.scrollRectToVisible(currentTable.getCellRect(currentRow - 1, 0, true));
                // 使用修改后的 updateSelection
                updateSelection(currentTable);
            }
        }
    }

    public void selectNext() {
        if (currentTable != null) {
            int currentRow = currentTable.getSelectedRow();
            if (currentRow < currentTable.getRowCount() - 1) {
                currentTable.setRowSelectionInterval(currentRow + 1, currentRow + 1);
                currentTable.scrollRectToVisible(currentTable.getCellRect(currentRow + 1, 0, true));
                // 使用修改后的 updateSelection
                updateSelection(currentTable);
            }
        }
    }

    public boolean hasPrevious() {
        return currentTable != null && currentTable.getSelectedRow() > 0;
    }

    public boolean hasNext() {
        return currentTable != null &&
                currentTable.getSelectedRow() < currentTable.getRowCount() - 1 &&
                currentTable.getSelectedRow() != -1;
    }
}