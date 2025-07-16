package pzfzr.gui;

import pzfzr.model.OriginalRequestResponse;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.TableModel;

import javax.swing.*;
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
    private JTable currentTable; // 保存当前活动的表格

    public HistoryPanel(TableModel tableModel,
                        BiConsumer<OriginalRequestResponse, ModifiedRequestResponse> selectionCallback) {
        this.tableModel = tableModel;
        this.selectionCallback = selectionCallback;

        setLayout(new BorderLayout());
        createTabbedPane();
    }
    private void createTabbedPane() {
        tabbedPane = new JTabbedPane();

        // 为每个标签页创建独立的表格
        JTable allTable = createTable();
        JTable protoTable = createTable();
        JTable collectedTable = createTable();
        JTable suspiciousTable = createTable();
        JTable knownTable = createTable();  // 新增

        // 设置初始的当前表格
        currentTable = allTable;
        tableModel.setAssociatedTable(currentTable);

        // 添加标签页，每个标签页使用独立的滚动面板
        tabbedPane.addTab("All Requests", new JScrollPane(allTable));
        tabbedPane.addTab("Proto Test", new JScrollPane(protoTable));
        tabbedPane.addTab("Collected Test", new JScrollPane(collectedTable));
        tabbedPane.addTab("Suspicious Test", new JScrollPane(suspiciousTable));
        tabbedPane.addTab("Known Test", new JScrollPane(knownTable));  // 新增

        // 添加标签切换监听器
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
                    tableModel.setFilter("PROTO");
                    break;
                case 2:
                    tableModel.setFilter("COLLECTED");
                    break;
                case 3:
                    tableModel.setFilter("SUSPICIOUS");
                    break;
                case 4:  // 新增
                    tableModel.setFilter("KNOWN");
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

        // 设置列宽 - 更新为12列
        if (table.getColumnModel().getColumnCount() >= 12) {
            table.getColumnModel().getColumn(0).setPreferredWidth(35);    // ID
            table.getColumnModel().getColumn(1).setPreferredWidth(30);    // HTTP Method
            table.getColumnModel().getColumn(2).setPreferredWidth(400);   // URL
            table.getColumnModel().getColumn(3).setPreferredWidth(40);    // Test Type
            table.getColumnModel().getColumn(4).setPreferredWidth(100);   // Param (新增)
            table.getColumnModel().getColumn(5).setPreferredWidth(100);   // Payload (新增)
            table.getColumnModel().getColumn(6).setPreferredWidth(72);    // Orig Body Len
            table.getColumnModel().getColumn(7).setPreferredWidth(72);    // Modif Body Len
            table.getColumnModel().getColumn(8).setPreferredWidth(72);    // Modif status
            table.getColumnModel().getColumn(9).setPreferredWidth(72);    // Len Diff
            table.getColumnModel().getColumn(10).setPreferredWidth(72);   // Modif Time
            table.getColumnModel().getColumn(11).setPreferredWidth(80);   // Reflect
        }


        return table;
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