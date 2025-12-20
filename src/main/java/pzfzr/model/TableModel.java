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
    private RequestResponseSaver requestResponseSaver;
    private final Logging logging;

    // 更新列名顺序：在ID后添加Orig.ID列
    private static final String[] COLUMN_NAMES = {
            "ID",
            "Orig.ID",      // 新增列
            "Method",
            "URL",
            "Test Type",
            "Param",
            "Payload",
            "Modif. Status",
            "Len Diff",
            "Modif. len",
            "Modif. len+",
            "Orig. Len",
            "Modif. Time",
            "Reflect"
    };

    // 定义需要染成灰色的特殊alias列表
    private static final Set<String> SPECIAL_ALIASES = new HashSet<>(Arrays.asList(
            "{path}\\..X8",
            "{path}%5c..X8",
            "{path}%2f..X8",
            "{path}/..X8",
            "{path}%252f..X8",
            "{path}/%2E%2EX8",
            "{path}%2F%2E%2EX8",
            "{path}//..X8",
            "{path}%2f%2f..X8",
            "{path}/..;X8"
    ));

    // 定义param类型需要染成灰色的特殊alias列表
    private static final Set<String> PARAM_SPECIAL_ALIASES = new HashSet<>(Arrays.asList(
            "{param}\\..X8",
            "{param}%5c..X8",
            "{param}%2f..X8",
            "{param}/..X8",
            "{param}%252f..X8",
            "{param}/%2E%2EX8",
            "{param}%2F%2E%2EX8",
            "{param}//..X8",
            "{param}%2f%2f..X8",
            "{param}/..;X8"
    ));

    // 定义route1类型需要染成灰色的特殊alias列表
    private static final Set<String> ROUTE1_SPECIAL_ALIASES = new HashSet<>(Arrays.asList(
            "ng crlf",
            "ng crlf2",
            "ng crlf3"
    ));

    // 新增：定义param类型的新特殊alias列表（用户需求）
    private static final Set<String> PARAM_NEW_SPECIAL_ALIASES = new HashSet<>(Arrays.asList(
            "{param}%2f..",
            "{param}/..",
            "{param}%252f..",
            "{param}/%2E%2E",
            "{param}%2F%2E%2E",
            "{param}//..",
            "{param}%2f%2f..",
            "{param}/..;",
            "{param}%5c..",
            "{param}\\.."
    ));

    // 新增：定义route2类型的新特殊alias列表（用户需求）
    private static final Set<String> ROUTE2_NEW_SPECIAL_ALIASES = new HashSet<>(Arrays.asList(
            "{path}%2f..",
            "{path}/..",
            "{path}%252f..",
            "{path}/%2E%2E",
            "{path}%2F%2E%2E",
            "{path}//..",
            "{path}%2f%2f..",
            "{path}/..;",
            "{path}%5c..",
            "{path}\\.."
    ));

    // 通用的自定义单元格渲染器，用于Payload、Modif len和Len Diff列
    public class GrayBackgroundCellRenderer extends DefaultTableCellRenderer {
        // 定义当Payload包含"chaxx"或符合特殊条件时使用的灰色背景
        private static final Color CHAXX_BACKGROUND_COLOR = new Color(217, 217, 217);// 原本是230 230 230
        // 新增：定义用户需求的灰色背景 RGB 230 230 230
        private static final Color NEW_GRAY_BACKGROUND_COLOR = new Color(230, 230, 230);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // 处理选中状态
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            } else {
                boolean shouldGray = false;
                boolean shouldNewGray = false;

                // Payload列现在是索引6
                Object payloadValue = table.getValueAt(row, 6);
                Object testTypeValue = table.getValueAt(row, 4); // Test Type列索引为4

                if (payloadValue != null && testTypeValue != null) {
                    String payload = payloadValue.toString();
                    String testType = testTypeValue.toString().toLowerCase();

                    // 检查是否为特殊alias且testtype是route1、route2或route3
                    if ((testType.equals("route1") || testType.equals("route2") || testType.equals("route3")) &&
                            SPECIAL_ALIASES.contains(payload)) {
                        shouldGray = true;
                    }

                    // 检查test type为param且alias为指定列表的情况
                    if (!shouldGray && testType.equals("param") && PARAM_SPECIAL_ALIASES.contains(payload)) {
                        shouldGray = true;
                    }

                    // 检查test type为route1且alias为指定列表的情况
                    if (!shouldGray && testType.equals("route1") && ROUTE1_SPECIAL_ALIASES.contains(payload)) {
                        shouldGray = true;
                    }

                    // 新增：检查param类型的新特殊alias列表（用户需求）
                    if (!shouldGray && !shouldNewGray && testType.equals("param") && PARAM_NEW_SPECIAL_ALIASES.contains(payload)) {
                        shouldNewGray = true;
                    }

                    // 新增：检查route2类型的新特殊alias列表（用户需求）
                    if (!shouldGray && !shouldNewGray && testType.equals("route2") && ROUTE2_NEW_SPECIAL_ALIASES.contains(payload)) {
                        shouldNewGray = true;
                    }
                }

                if (shouldNewGray) {
                    // 设置为新的灰色背景 RGB 230 230 230
                    c.setBackground(NEW_GRAY_BACKGROUND_COLOR);
                } else if (shouldGray) {
                    // 设置为原来的灰色背景
                    c.setBackground(CHAXX_BACKGROUND_COLOR);
                } else {
                    // 使用默认的交替行背景色
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251)); // 原有的斑马线浅灰色
                    }
                }
                c.setForeground(table.getForeground());
            }

            return c;
        }
    }



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

    // 为状态码列创建自定义渲染器
    public static class StatusCodeCellRenderer extends DefaultTableCellRenderer {
        // 存储状态码及其对应颜色的映射表
        private static final Map<Integer, Color> STATUS_COLORS = new HashMap<>();
        static {
            STATUS_COLORS.put(200, new Color(198, 255, 221)); // #C6FFDD 淡薄荷绿
            STATUS_COLORS.put(201, new Color(213, 251, 232)); // #D5FBE8 极浅薄荷
            STATUS_COLORS.put(204, new Color(230, 255, 238)); // #E6FFEE 近白薄荷
            STATUS_COLORS.put(301, new Color(255, 222, 173)); // #FFDEAD 淡杏黄
            STATUS_COLORS.put(302, new Color(255, 234, 196)); // #FFEAC4 淡橙黄
            STATUS_COLORS.put(304, new Color(240, 248, 225)); // #F0F8E1 极浅黄绿
            STATUS_COLORS.put(307, new Color(255, 240, 213)); // #FFF0D5 极浅杏黄
            STATUS_COLORS.put(308, new Color(245, 222, 179)); // #F5DEB3 小麦色
            STATUS_COLORS.put(400, new Color(255, 139, 139)); // #FF8B8B 适中红，比403/404更重
            STATUS_COLORS.put(401, new Color(255, 179, 186)); // #FFB3BA 淡草莓色
            STATUS_COLORS.put(403, new Color(255, 182, 167)); // #FFB6A7 偏橙红，淡化但和404区分
            STATUS_COLORS.put(404, new Color(255, 200, 209)); // #FFC8D1 偏粉红，亮度+25%，更柔和
            STATUS_COLORS.put(405, new Color(255, 204, 204)); // #FFCCCC 浅红粉，柔和，和404/406保持差异
            STATUS_COLORS.put(406, new Color(255, 135, 189));
            STATUS_COLORS.put(409, new Color(255, 182, 193)); // #FFB6C1 浅粉红（比 404 稍淡）
            STATUS_COLORS.put(410, new Color(255, 160, 122)); // #FFA07A 浅鲑鱼色
            STATUS_COLORS.put(422, new Color(255, 188, 217)); // #FFBCD9 淡紫红
            STATUS_COLORS.put(440, new Color(255, 218, 185)); // #FFDAB9 桃色（和 403/404 有区分）
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
            // 如果单元格被选中，保持选中颜色
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
                return c;
            }
            // 否则，根据状态码设置背景颜色
            try {
                if (value != null && !value.toString().equals("Pending")) {
                    int statusCode = Integer.parseInt(value.toString());
                    // 获取特定状态码的颜色，或获取状态码家族的颜色（例如 404 -> 400）
                    Color color = STATUS_COLORS.get(statusCode);
                    if (color == null && statusCode > 0) {
                        // 尝试获取家族颜色（第一位数字后跟两个零）
                        int statusFamily = (statusCode / 100) * 100;
                        color = STATUS_COLORS.get(statusFamily);
                    }
                    if (color != null) {
                        c.setBackground(color);
                    } else {
                        // 如果没有匹配项，默认使用未知状态颜色
                        c.setBackground(STATUS_COLORS.get(0));
                    }
                } else {
                    // 对于"Pending"或null值
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
            } catch (NumberFormatException e) {
                // 对于非数字值，使用默认行背景
                if (row % 2 == 0) {
                    c.setBackground(table.getBackground());
                } else {
                    c.setBackground(new Color(251, 251, 251));
                }
            }
            return c;
        }
    }

    // 为响应时间列创建自定义渲染器
    public static class TimeCellRenderer extends DefaultTableCellRenderer {
        // 为不同时间阈值定义颜色
        private static final Color DEFAULT_COLOR = null; // 使用默认表格颜色
        private static final Color LIGHT_GRAY = new Color(230, 230, 230); // #E6E6E6 - 超过1000ms的浅灰色
        private static final Color MEDIUM_GRAY = new Color(211, 211, 211); // #D3D3D3 - 超过7000ms的中灰色

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // 如果单元格被选中，保持选中颜色
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
                return c;
            }

            // 根据响应时间设置背景颜色
            try {
                if (value != null) {
                    int responseTime = Integer.parseInt(value.toString());

                    if (responseTime > 7000) {
                        c.setBackground(MEDIUM_GRAY);
                    } else {
                        if (row % 2 == 0) {
                            c.setBackground(table.getBackground());
                        } else {
                            c.setBackground(new Color(251, 251, 251));
                        }
                    }
                } else {
                    // 对于null值，使用默认行背景
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
            } catch (NumberFormatException e) {
                // 对于非数字值，使用默认行背景
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

    /**
     * 更新过滤后的条目列表
     * 修改此方法以支持ROUTE3类型在ROUTE1和ROUTE2标签页中都显示，以及PARAM_DELETE类型
     */
    private void updateFilteredEntries() {
        filteredEntries.clear();
        if ("ALL".equals(currentFilter)) {
            filteredEntries.addAll(modifiedEntries);
        } else {
            for (ModifiedRequestResponse entry : modifiedEntries) {
                String entryTestType = entry.getTestType();

                // 检查条目是否应该在当前过滤器下显示
                boolean shouldInclude = false;

                if (entryTestType.equals(currentFilter)) {
                    // 直接匹配当前过滤器
                    shouldInclude = true;
                } else if ("ROUTE3".equals(entryTestType)) {
                    // ROUTE3类型的条目在ROUTE1和ROUTE2标签页中都显示
                    if ("ROUTE1".equals(currentFilter) || "ROUTE2".equals(currentFilter)) {
                        shouldInclude = true;
                    }
                }

                if (shouldInclude) {
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

    /**
     * 添加修改后的条目
     * 修改此方法以支持ROUTE3类型在ROUTE1和ROUTE2标签页中都显示，以及PARAM_DELETE类型
     *
     * 性能优化：移除了自动选中状态恢复逻辑，避免在高频插入+倒序排序时的卡顿问题
     */
    public synchronized void addModifiedEntry(ModifiedRequestResponse modifiedEntry) {
        if (SwingUtilities.isEventDispatchThread()) {
            addModifiedEntryInternal(modifiedEntry);
        } else {
            SwingUtilities.invokeLater(() -> addModifiedEntryInternal(modifiedEntry));
        }
    }

    private void addModifiedEntryInternal(ModifiedRequestResponse modifiedEntry) {
        modifiedEntries.add(modifiedEntry);

        String entryTestType = modifiedEntry.getTestType();
        boolean shouldAdd = false;

        // 检查是否应该在当前过滤器下添加条目
        if ("ALL".equals(currentFilter)) {
            shouldAdd = true;
        } else if (entryTestType.equals(currentFilter)) {
            shouldAdd = true;
        } else if ("ROUTE3".equals(entryTestType)) {
            // ROUTE3类型的条目在ROUTE1和ROUTE2标签页中都显示
            if ("ROUTE1".equals(currentFilter) || "ROUTE2".equals(currentFilter)) {
                shouldAdd = true;
            }
        }

        if (shouldAdd) {
            filteredEntries.add(modifiedEntry);
            final int filteredIndex = filteredEntries.size() - 1;
            fireTableRowsInserted(filteredIndex, filteredIndex);

            // ============================================
            // 关键修改：移除自动选中恢复逻辑
            // ============================================
            // 原因：
            // 1. TableRowSorter 会自动维护选中状态的模型索引
            // 2. 在倒序排序+高频插入时，手动恢复选中会导致：
            //    - 视图索引变化导致选中错误的行
            //    - 触发大量不必要的选择事件和数据加载
            //    - 造成严重的UI卡顿
            // 3. 移除后，用户的选中状态会自然保持，不会受影响
            // ============================================

            // 以下代码已注释掉，解决卡顿问题
        /*
        if (associatedTable != null) {
            SwingUtilities.invokeLater(() -> {
                int selectedRow = associatedTable.getSelectedRow();
                if (selectedRow != -1) {
                    associatedTable.setRowSelectionInterval(selectedRow, selectedRow);
                }
            });
        }
        */
        }
    }

    public synchronized OriginalRequestResponse findByMessageId(Integer messageId) {
        return originalRequestMap.get(messageId);
    }

    //  新增方法：根据 ID 查找 ModifiedRequestResponse
    public ModifiedRequestResponse getModifiedEntryById(int id) {
        for (ModifiedRequestResponse entry : modifiedEntries) {
            if (entry.getId() == id) {
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
                case 0: // ID
                    return modifiedEntry.getId();
                case 1: // Orig.ID (新增列)
                    return modifiedEntry.getOriginalMessageId();
                case 2: // Method
                    return originalEntry != null ? originalEntry.getOriginalMethod() : "";
                case 3: // URL
                    return originalEntry != null ? originalEntry.getOriginalUrl() : "";
                case 4: // Test type
                    return modifiedEntry.getTestType();
                case 5: // Param
                    return modifiedEntry.getTestParameterName() != null ?
                            modifiedEntry.getTestParameterName() : "";
                case 6: // Payload
                    return modifiedEntry.getPayloadAlias() != null ?
                            modifiedEntry.getPayloadAlias() : "";
                case 7: // Modif. Status
                    return modifiedEntry.getStatusCode() != -1 ?
                            modifiedEntry.getStatusCode() : "Pending";
                case 8: // Len Diff
                    if (originalEntry != null && originalEntry.getOriginalResponseLenWithoutHeader() != -1 &&
                            modifiedEntry.getModifiedBodyLengthWithoutHeader() != -1) {
                        int origLen = originalEntry.getOriginalResponseLenWithoutHeader();
                        int modifyLen = modifiedEntry.getModifiedBodyLengthWithoutHeader();
                        return Math.abs(modifyLen - origLen);
                    }
                    return "Pending";
                case 9: // modif len(withoutheader)
                    return modifiedEntry.getModifiedBodyLengthWithoutHeader() != -1 ?
                            modifiedEntry.getModifiedBodyLengthWithoutHeader() : "Pending";
                case 10: // modif len+(withheader)
                    return modifiedEntry.getModifiedBodyLength() != -1 ?
                            modifiedEntry.getModifiedBodyLength() : "Pending";
                case 11: // origin len(withoutheader)
                    return originalEntry != null && originalEntry.getOriginalResponseLenWithoutHeader() != -1 ?
                            originalEntry.getOriginalResponseLenWithoutHeader() : "Pending";
                case 12: // Modif. Time
                    return modifiedEntry.getResponseTime();
                case 13: // Reflect
                    return modifiedEntry.getReflectType();
                default:
                    return null;
            }
        } catch (Exception e) {
            return "Error";
        }
    }

    public void setupSorter(JTable table) {
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(this);

        // Reflect 列的索引现在是 13
        sorter.setComparator(13, (Comparator<Object>) (o1, o2) -> {
            if (o1 == null && o2 == null) return 0;
            if (o1 == null) return -1;
            if (o2 == null) return 1;
            return o1.toString().compareTo(o2.toString());
        });

        for (int i = 0; i < getColumnCount(); i++) {
            if (i != 13) {
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

    // 更新setupTableRenderers方法，为Payload、modif len和Len Diff列设置统一的灰色背景渲染器
    public void setupTableRenderers(JTable table) {
        // 为"Reflect"列（索引13）设置ReflectCellRenderer
        table.getColumnModel().getColumn(13).setCellRenderer(new ReflectCellRenderer());

        // 为"modif status"列（索引7）设置StatusCodeCellRenderer
        table.getColumnModel().getColumn(7).setCellRenderer(new StatusCodeCellRenderer());

        // 为"Modif. Time"列（索引12）设置TimeCellRenderer
        table.getColumnModel().getColumn(12).setCellRenderer(new TimeCellRenderer());

        // 为"Payload"列（索引6）设置GrayBackgroundCellRenderer
        table.getColumnModel().getColumn(6).setCellRenderer(new GrayBackgroundCellRenderer());

        // 为"Len Diff"列（索引8）设置GrayBackgroundCellRenderer
        table.getColumnModel().getColumn(8).setCellRenderer(new GrayBackgroundCellRenderer());

        // 为"Modif. len"列（索引9）设置GrayBackgroundCellRenderer
        table.getColumnModel().getColumn(9).setCellRenderer(new GrayBackgroundCellRenderer());
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
            entry.cleanup();
        }
    }
}