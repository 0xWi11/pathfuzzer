package pzfzr.model;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import burp.api.montoya.logging.Logging;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;


public class TableModel extends AbstractTableModel {
    private final List<ModifiedRequestResponse> modifiedEntries = new CopyOnWriteArrayList<>();
    private final List<ModifiedRequestResponse> filteredEntries = new CopyOnWriteArrayList<>();
    private final Map<Integer, OriginalRequestResponse> originalRequestMap = new ConcurrentHashMap<>();
    private JTable associatedTable;
    private String currentFilter = "ALL";
    private RequestResponseSaver requestResponseSaver; // 声明 RequestResponseSaver 成员变量
    private final Logging logging;


    private static final String[] COLUMN_NAMES = {
            "ID",
            "Method",
            "URL",
            "Test Type",
            "Orig. Len",
            "Modif. Len",
            "Modif. Status",
            "Len Diff",
            "Modif. Time",
            "Reflect"
    };
    // 为Reflect字段创建自定义单元格渲染器
    public static class ReflectCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (value != null && !value.toString().isEmpty()) {
                c.setBackground(Color.YELLOW);
            } else {
                if (row % 2 == 0) {
                    c.setBackground(table.getBackground());
                } else {
                    c.setBackground(new Color(251, 251, 251));
                }
            }
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            }
            return c;
        }
    }
    // Create a custom renderer for the status code column
    public static class StatusCodeCellRenderer extends DefaultTableCellRenderer {
        // Map to store status codes and their corresponding colors
        private static final Map<Integer, Color> STATUS_COLORS = new HashMap<>();

        static {
            // Initialize the color map based on the provided status code definitions
            STATUS_COLORS.put(200, new Color(198, 255, 221)); // #C6FFDD 淡薄荷绿
            STATUS_COLORS.put(201, new Color(213, 251, 232)); // #D5FBE8 极浅薄荷
            STATUS_COLORS.put(204, new Color(230, 255, 238)); // #E6FFEE 近白薄荷
            STATUS_COLORS.put(301, new Color(255, 222, 173)); // #FFDEAD 淡杏黄
            STATUS_COLORS.put(302, new Color(255, 234, 196)); // #FFEAC4 淡橙黄
            STATUS_COLORS.put(304, new Color(240, 248, 225)); // #F0F8E1 极浅黄绿
            STATUS_COLORS.put(307, new Color(255, 240, 213)); // #FFF0D5 极浅杏黄
            STATUS_COLORS.put(308, new Color(245, 222, 179)); // #F5DEB3 小麦色
            STATUS_COLORS.put(400, new Color(255, 204, 204)); // #FFCCCC 浅粉红
            STATUS_COLORS.put(401, new Color(255, 179, 186)); // #FFB3BA 淡草莓色
            STATUS_COLORS.put(403, new Color(255, 153, 153)); // #FF9999 淡珊瑚红
            STATUS_COLORS.put(406, new Color(255, 179, 167)); // #FFB3A7 妃色/浅红
            STATUS_COLORS.put(422, new Color(255, 188, 217)); // #FFBCD9 淡紫红
            STATUS_COLORS.put(500, new Color(216, 191, 216)); // #D8BFD8 蓟色(淡紫)
            STATUS_COLORS.put(502, new Color(204, 187, 216)); // #CCBBD8 淡薰衣草
            STATUS_COLORS.put(504, new Color(187, 191, 216)); // #BBBFD8 淡紫蓝
            STATUS_COLORS.put(0, new Color(230, 230, 230));   // #E6E6E6 浅灰
            STATUS_COLORS.put(-1, new Color(211, 211, 211));  // #D3D3D3 淡灰
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // If the cell is selected, keep the selection color
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
                return c;
            }

            // Otherwise, set background color based on status code
            try {
                if (value != null && !value.toString().equals("Pending")) {
                    int statusCode = Integer.parseInt(value.toString());

                    // Get color for the specific status code, or get color for status code family (e.g., 404 -> 400)
                    Color color = STATUS_COLORS.get(statusCode);
                    if (color == null && statusCode > 0) {
                        // Try to get the family color (first digit followed by two zeros)
                        int statusFamily = (statusCode / 100) * 100;
                        color = STATUS_COLORS.get(statusFamily);
                    }

                    if (color != null) {
                        c.setBackground(color);
                    } else {
                        // Default to unknown status color if no match
                        c.setBackground(STATUS_COLORS.get(0));
                    }
                } else {
                    // For "Pending" or null values
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
            } catch (NumberFormatException e) {
                // For non-numeric values, use default row background
                if (row % 2 == 0) {
                    c.setBackground(table.getBackground());
                } else {
                    c.setBackground(new Color(251, 251, 251));
                }
            }

            return c;
        }
    }
    // Create a custom renderer for the response time column
    public static class TimeCellRenderer extends DefaultTableCellRenderer {
        // Define colors for different time thresholds
        private static final Color DEFAULT_COLOR = null; // Use default table color
        private static final Color LIGHT_GRAY = new Color(230, 230, 230); // #E6E6E6 - Light gray for > 1000ms
        private static final Color MEDIUM_GRAY = new Color(211, 211, 211); // #D3D3D3 - Medium gray for > 7000ms

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // If the cell is selected, keep the selection color
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
                return c;
            }

            // Set background color based on response time
            try {
                if (value != null) {
                    int responseTime = Integer.parseInt(value.toString());

                    if (responseTime > 7000) {
                        c.setBackground(MEDIUM_GRAY);
                    } else if (responseTime > 1000) {
                        c.setBackground(LIGHT_GRAY);
                    } else {
                        // For response times < 1000, use default row background (alternating rows)
                        if (row % 2 == 0) {
                            c.setBackground(table.getBackground());
                        } else {
                            c.setBackground(new Color(251, 251, 251));
                        }
                    }
                } else {
                    // For null values, use default row background
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
            } catch (NumberFormatException e) {
                // For non-numeric values, use default row background
                if (row % 2 == 0) {
                    c.setBackground(table.getBackground());
                } else {
                    c.setBackground(new Color(251, 251, 251));
                }
            }

            return c;
        }
    }
    // 构造函数中接收 RequestResponseSaver 和 Logging
    public TableModel(RequestResponseSaver requestResponseSaver, Logging logging) {
        this.requestResponseSaver = requestResponseSaver; // 初始化 RequestResponseSaver
        this.logging = logging;
    }
    public void setRequestResponseSaver(RequestResponseSaver requestResponseSaver) {
        this.requestResponseSaver = requestResponseSaver;
    }

    public void setFilter(String filter) {
        if (!filter.equals(currentFilter)) {
            this.currentFilter = filter;
            updateFilteredEntries();
        }
    }

    public void setAssociatedTable(JTable table) {
        this.associatedTable = table;
    }

    private void updateFilteredEntries() {
        filteredEntries.clear();
        if ("ALL".equals(currentFilter)) {
            filteredEntries.addAll(modifiedEntries);
        } else {
            for (ModifiedRequestResponse entry : modifiedEntries) {
                if (entry.getTestType().equals(currentFilter)) {
                    filteredEntries.add(entry);
                }
            }
        }
        SwingUtilities.invokeLater(this::fireTableDataChanged);
    }

    public synchronized OriginalRequestResponse createEntry(OriginalRequestResponse entry,int messageId) {
        originalRequestMap.put(messageId, entry);
        return entry;
    }

    public synchronized void addModifiedEntry(ModifiedRequestResponse modifiedEntry) {
        if (SwingUtilities.isEventDispatchThread()) {
            addModifiedEntryInternal(modifiedEntry);
        } else {
            SwingUtilities.invokeLater(() -> addModifiedEntryInternal(modifiedEntry));
        }
    }

    private void addModifiedEntryInternal(ModifiedRequestResponse modifiedEntry) {
//        int insertIndex = modifiedEntries.size();
        modifiedEntries.add(modifiedEntry);
//        logging.logToOutput("TableModel: Added ModifiedEntry with ID: " + modifiedEntry.getId() + ", Total entries: " + modifiedEntries.size()); // 添加日志

        if ("ALL".equals(currentFilter) ||
                modifiedEntry.getTestType().equals(currentFilter)) {
            filteredEntries.add(modifiedEntry);
            final int filteredIndex = filteredEntries.size() - 1;
            fireTableRowsInserted(filteredIndex, filteredIndex);

            if (associatedTable != null) {
                SwingUtilities.invokeLater(() -> {
                    int selectedRow = associatedTable.getSelectedRow();
                    if (selectedRow != -1) {
                        associatedTable.setRowSelectionInterval(selectedRow, selectedRow);
                    }
                });
            }
        }
    }

    public synchronized OriginalRequestResponse findByMessageId(Integer messageId) {
        return originalRequestMap.get(messageId);
    }

    //  新增方法：根据 ID 查找 ModifiedRequestResponse
    public ModifiedRequestResponse getModifiedEntryById(int id) {
//        logging.logToOutput("TableModel: Searching for ModifiedEntry with ID: " + id); // 添加查找日志
        for (ModifiedRequestResponse entry : modifiedEntries) {
            if (entry.getId() == id) {
//                logging.logToOutput("TableModel: Found ModifiedEntry with ID: " + id); // 找到条目时添加日志
                return entry;
            }
        }
        logging.logToError("[TableModel] ModifiedRequestResponse entry NOT FOUND for ID: " + id + ", Total entries: " + modifiedEntries.size()); // 未找到条目时添加错误日志
        return null;
    }


    @Override
    public int getRowCount() {
        return filteredEntries.size();
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
    public Object getValueAt(int row, int column) {
        if (row < 0 || row >= filteredEntries.size()) {
            return null;
        }

        ModifiedRequestResponse modifiedEntry = filteredEntries.get(row);
        if (modifiedEntry == null) {
            return null;
        }

        OriginalRequestResponse originalEntry = findByMessageId(modifiedEntry.getOriginalMessageId());

        try {
            switch (column) {
                case 0:
                    return modifiedEntry.getId();
                case 1:
                    return originalEntry.getOriginalMethod() ;
                case 2:
                    return originalEntry.getOriginalUrl() ;
                case 3:
                    return modifiedEntry.getTestType();
                case 4:
                    return originalEntry != null && originalEntry.getOriginalResponseLen() != -1 ?
                            originalEntry.getOriginalResponseLen() : "Pending";
                case 5:
                    return modifiedEntry.getModifiedBodyLength() != -1 ? //  直接获取缓存值
                            modifiedEntry.getModifiedBodyLength() : "Pending";
                case 6:
                    return modifiedEntry.getStatusCode() != -1 ? // 直接获取缓存值
                            modifiedEntry.getStatusCode() : "Pending";
                case 7:
                    // 计算长度差异 (UI 线程计算，简单操作)
                    if (originalEntry != null && originalEntry.getOriginalResponseLen() != -1 &&
                            modifiedEntry.getModifiedBodyLength() != -1) { // 直接获取缓存值
                        int origLen = originalEntry.getOriginalResponseLen();
                        int modifyLen = modifiedEntry.getModifiedBodyLength(); // 直接获取缓存值
                        return Math.abs(modifyLen - origLen);
                    }
                    return "Pending";
                case 8:
                    return modifiedEntry.getResponseTime(); // 直接获取缓存值
                case 9:
                    return modifiedEntry.getReflectType(); // 直接获取缓存值
                default:
                    return null;
            }
        } catch (Exception e) {
            return "Error";
        }
    }

    public void setupSorter(JTable table) {
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(this);

        sorter.setComparator(9, (Comparator<Object>) (o1, o2) -> {
            if (o1 == null && o2 == null) return 0;
            if (o1 == null) return -1;
            if (o2 == null) return 1;
            return o1.toString().compareTo(o2.toString());
        });
        for (int i = 0; i < getColumnCount(); i++) {
            if (i != 9) {
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
        }
        table.setRowSorter(sorter);
    }
    // Update the setupTableRenderers method to include the new renderer
    public void setupTableRenderers(JTable table) {
        // Set the existing ReflectCellRenderer for the "Reflect" column (index 9)
        table.getColumnModel().getColumn(9).setCellRenderer(new ReflectCellRenderer());

        // Set the StatusCodeCellRenderer for the "Modif. Status" column (index 6)
        table.getColumnModel().getColumn(6).setCellRenderer(new StatusCodeCellRenderer());

        // Set the new TimeCellRenderer for the "Modif. Time" column (index 8)
        table.getColumnModel().getColumn(8).setCellRenderer(new TimeCellRenderer());
    }
    public ModifiedRequestResponse getModifiedEntry(int row) {
        if (row >= 0 && row < filteredEntries.size()) {
            return filteredEntries.get(row);
        }
        return null;
    }

    public List<ModifiedRequestResponse> getAllModifiedEntries() {
        return new ArrayList<>(modifiedEntries);
    }

    // 添加资源清理方法
    public void cleanup() {
        for(ModifiedRequestResponse entry : modifiedEntries) {
            entry.cleanup(); // 清理 ModifiedRequestResponse 内部资源
        }
    }
}