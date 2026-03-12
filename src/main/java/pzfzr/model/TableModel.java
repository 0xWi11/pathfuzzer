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
import java.util.concurrent.atomic.AtomicBoolean;

public class TableModel extends AbstractTableModel {
    // =========================================================================
    // 数据存储
    // =========================================================================
    private final List<ModifiedRequestResponse> modifiedEntries = Collections.synchronizedList(new ArrayList<>());
    private final List<ModifiedRequestResponse> filteredEntries = Collections.synchronizedList(new ArrayList<>());
    private final Map<Integer, OriginalRequestResponse> originalRequestMap = new ConcurrentHashMap<>();

    // ★★★ 新增：索引结构 - 原始消息ID → 该ID对应的所有Modified条目 ★★★
    private final ConcurrentHashMap<Integer, CopyOnWriteArrayList<ModifiedRequestResponse>>
            modifiedEntriesIndex = new ConcurrentHashMap<>();

    private JTable associatedTable;
    private String currentFilter = "ALL";
    private RequestResponseSaver requestResponseSaver;
    private final Logging logging;

    // 批量插入机制
    private final List<ModifiedRequestResponse> pendingInserts = new CopyOnWriteArrayList<>();
    private final javax.swing.Timer batchInsertTimer;
    private static final int BATCH_INSERT_INTERVAL_MS = 200;

    // 更新列名顺序：在ID后添加Orig.ID列
    private static final String[] COLUMN_NAMES = {
            "ID",
            "Orig.ID",
            "Method",
            "URL",
            "Test Type",
            "Param",
            "Content Type",
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

    private static final Set<String> ROUTE1_SPECIAL_ALIASES = new HashSet<>(Arrays.asList(
            "ng crlf",
            "ng crlf2",
            "ng crlf3"
    ));

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

    // =========================================================================
    // Cell Renderer 定义
    // =========================================================================

    public class GrayBackgroundCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            } else {
                int modelRow = table.convertRowIndexToModel(row);
                ModifiedRequestResponse entry = getModifiedEntry(modelRow);

                Color bgColor = null;
                if (entry != null) {
                    bgColor = entry.getPayloadBackgroundColor();
                }

                if (bgColor != null) {
                    c.setBackground(bgColor);
                } else {
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
                c.setForeground(table.getForeground());
            }

            return c;
        }
    }

    public class LenDiffCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            } else {
                int modelRow = table.convertRowIndexToModel(row);
                ModifiedRequestResponse entry = getModifiedEntry(modelRow);

                if (entry != null) {
                    Color bgColor = entry.getLenDiffBackgroundColor();
                    Color fgColor = entry.getLenDiffForegroundColor();

                    if (bgColor != null) {
                        c.setBackground(bgColor);
                    } else {
                        if (row % 2 == 0) {
                            c.setBackground(table.getBackground());
                        } else {
                            c.setBackground(new Color(251, 251, 251));
                        }
                    }

                    if (fgColor != null) {
                        c.setForeground(fgColor);
                    } else {
                        c.setForeground(table.getForeground());
                    }
                } else {
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                    c.setForeground(table.getForeground());
                }
            }

            return c;
        }
    }

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

    public class StatusCodeCellRenderer extends DefaultTableCellRenderer {
        public static final Map<Integer, Color> STATUS_COLORS = new HashMap<>();
        static {
            STATUS_COLORS.put(200, new Color(198, 255, 221));
            STATUS_COLORS.put(201, new Color(213, 251, 232));
            STATUS_COLORS.put(204, new Color(230, 255, 238));
            STATUS_COLORS.put(301, new Color(255, 222, 173));
            STATUS_COLORS.put(302, new Color(255, 234, 196));
            STATUS_COLORS.put(304, new Color(240, 248, 225));
            STATUS_COLORS.put(307, new Color(255, 240, 213));
            STATUS_COLORS.put(308, new Color(245, 222, 179));
            STATUS_COLORS.put(400, new Color(255, 139, 139));
            STATUS_COLORS.put(401, new Color(255, 179, 186));
            STATUS_COLORS.put(403, new Color(255, 182, 167));
            STATUS_COLORS.put(404, new Color(255, 200, 209));
            STATUS_COLORS.put(405, new Color(255, 204, 204));
            STATUS_COLORS.put(406, new Color(255, 135, 189));
            STATUS_COLORS.put(409, new Color(255, 182, 193));
            STATUS_COLORS.put(410, new Color(255, 160, 122));
            STATUS_COLORS.put(422, new Color(255, 188, 217));
            STATUS_COLORS.put(440, new Color(255, 218, 185));
            STATUS_COLORS.put(500, new Color(216, 191, 216));
            STATUS_COLORS.put(502, new Color(204, 187, 216));
            STATUS_COLORS.put(504, new Color(187, 191, 216));
            STATUS_COLORS.put(0, new Color(230, 230, 230));
            STATUS_COLORS.put(-1, new Color(211, 211, 211));
        }

        public static Color getColorForStatusCode(int statusCode) {
            Color color = STATUS_COLORS.get(statusCode);
            if (color == null && statusCode > 0) {
                int statusFamily = (statusCode / 100) * 100;
                color = STATUS_COLORS.get(statusFamily);
            }
            if (color == null) {
                color = STATUS_COLORS.get(0);
            }
            return color;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
                return c;
            }

            int modelRow = table.convertRowIndexToModel(row);
            ModifiedRequestResponse entry = getModifiedEntry(modelRow);

            if (entry != null) {
                Color bgColor = entry.getStatusCodeBackgroundColor();
                if (bgColor != null) {
                    c.setBackground(bgColor);
                } else {
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
            } else {
                if (row % 2 == 0) {
                    c.setBackground(table.getBackground());
                } else {
                    c.setBackground(new Color(251, 251, 251));
                }
            }

            return c;
        }
    }

    public class TimeCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
                return c;
            }

            int modelRow = table.convertRowIndexToModel(row);
            ModifiedRequestResponse entry = getModifiedEntry(modelRow);

            if (entry != null) {
                Color bgColor = entry.getResponseTimeBackgroundColor();
                if (bgColor != null) {
                    c.setBackground(bgColor);
                } else {
                    if (row % 2 == 0) {
                        c.setBackground(table.getBackground());
                    } else {
                        c.setBackground(new Color(251, 251, 251));
                    }
                }
            } else {
                if (row % 2 == 0) {
                    c.setBackground(table.getBackground());
                } else {
                    c.setBackground(new Color(251, 251, 251));
                }
            }

            return c;
        }
    }

    // =========================================================================
    // 构造函数
    // =========================================================================
    public TableModel(RequestResponseSaver requestResponseSaver, Logging logging) {
        this.requestResponseSaver = requestResponseSaver;
        this.logging = logging;

        this.batchInsertTimer = new javax.swing.Timer(BATCH_INSERT_INTERVAL_MS, e -> {
            flushPendingInserts();
            ((javax.swing.Timer) e.getSource()).stop();
        });
        this.batchInsertTimer.setRepeats(false);
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

    // =========================================================================
    // 过滤刷新
    // =========================================================================
    private void updateFilteredEntries() {
        if (SwingUtilities.isEventDispatchThread()) {
            flushPendingInserts();
        }

        List<ModifiedRequestResponse> tempFiltered = new ArrayList<>();

        synchronized (modifiedEntries) {
            if ("ALL".equals(currentFilter)) {
                tempFiltered.addAll(modifiedEntries);
            } else {
                for (ModifiedRequestResponse entry : modifiedEntries) {
                    String entryTestType = entry.getTestType();
                    boolean shouldInclude = false;

                    if (entryTestType.equals(currentFilter)) {
                        shouldInclude = true;
                    } else if ("ROUTE3".equals(entryTestType)) {
                        if ("ROUTE1".equals(currentFilter) || "ROUTE2".equals(currentFilter)) {
                            shouldInclude = true;
                        }
                    }

                    if (shouldInclude) {
                        tempFiltered.add(entry);
                    }
                }
            }
        }

        synchronized (filteredEntries) {
            filteredEntries.clear();
            filteredEntries.addAll(tempFiltered);
        }

        SwingUtilities.invokeLater(() -> {
            fireTableDataChanged();
        });
    }

    public synchronized OriginalRequestResponse createEntry(OriginalRequestResponse entry, int messageId) {
        originalRequestMap.put(messageId, entry);
        return entry;
    }

    // =========================================================================
    // P0 核心修复：批量插入入口
    // =========================================================================
    public void addModifiedEntry(ModifiedRequestResponse modifiedEntry) {
        if (SwingUtilities.isEventDispatchThread()) {
            addModifiedEntryInternal(modifiedEntry);
        } else {
            SwingUtilities.invokeLater(() -> addModifiedEntryInternal(modifiedEntry));
        }
    }

    private void addModifiedEntryInternal(ModifiedRequestResponse modifiedEntry) {
        // 在添加前计算 Len Diff
        OriginalRequestResponse originalEntry = findByMessageId(modifiedEntry.getOriginalMessageId());
        if (originalEntry != null) {
            modifiedEntry.updateLenDiff(originalEntry.getOriginalResponseLenWithoutHeader());
        }

        // 添加到主列表
        synchronized (modifiedEntries) {
            modifiedEntries.add(modifiedEntry);
        }

        // ★★★ 新增：建立索引 ★★★
        Integer originalMsgId = modifiedEntry.getOriginalMessageId();
        if (originalMsgId != null) {
            modifiedEntriesIndex.computeIfAbsent(originalMsgId, k -> new CopyOnWriteArrayList<>())
                    .add(modifiedEntry);
        }

        // 检查是否应该在当前过滤器下显示
        String entryTestType = modifiedEntry.getTestType();
        boolean shouldAdd = false;

        if ("ALL".equals(currentFilter)) {
            shouldAdd = true;
        } else if (entryTestType.equals(currentFilter)) {
            shouldAdd = true;
        } else if ("ROUTE3".equals(entryTestType)) {
            if ("ROUTE1".equals(currentFilter) || "ROUTE2".equals(currentFilter)) {
                shouldAdd = true;
            }
        }

        if (shouldAdd) {
            pendingInserts.add(modifiedEntry);

            if (!batchInsertTimer.isRunning()) {
                batchInsertTimer.start();
            }
        }
    }

    private void flushPendingInserts() {
        if (pendingInserts.isEmpty()) {
            return;
        }

        List<ModifiedRequestResponse> batch;
        synchronized (pendingInserts) {
            if (pendingInserts.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pendingInserts);
            pendingInserts.clear();
        }

        if (batch.isEmpty()) {
            return;
        }

        int startRow;
        int endRow;

        synchronized (filteredEntries) {
            startRow = filteredEntries.size();
            filteredEntries.addAll(batch);
            endRow = filteredEntries.size() - 1;
        }

        fireTableRowsInserted(startRow, endRow);
    }

    // =========================================================================
    // ★★★ 新增：原始响应更新时的批量更新方法 ★★★
    // =========================================================================

    /**
     * 当原始响应更新时，批量更新所有相关的Modified条目
     * 性能优化：O(1)查找 + 批量UI刷新
     *
     * @param messageId 原始消息ID
     * @param newOriginalLength 新的原始响应长度
     */
    public void onOriginalResponseUpdated(int messageId, int newOriginalLength) {
        // ★ 性能关键：O(1) 查找，而非遍历 200w 数据
        CopyOnWriteArrayList<ModifiedRequestResponse> relatedEntries =
                modifiedEntriesIndex.get(messageId);

        if (relatedEntries == null || relatedEntries.isEmpty()) {
            return;
        }

        // 批量更新所有相关条目的缓存
        for (ModifiedRequestResponse entry : relatedEntries) {
            entry.updateLenDiff(newOriginalLength);
        }

        // ★★★ 性能优化：批量UI刷新（一次性刷新所有受影响的行）★★★
        SwingUtilities.invokeLater(() -> {
            batchFireTableRowsUpdated(relatedEntries);
        });
    }

    /**
     * 批量触发UI更新（避免循环调用 fireTableRowsUpdated）
     *
     * @param entries 需要更新的条目列表
     */
    private void batchFireTableRowsUpdated(List<ModifiedRequestResponse> entries) {
        if (entries.isEmpty()) {
            return;
        }

        synchronized (filteredEntries) {
            // 收集所有受影响的行号
            List<Integer> affectedRows = new ArrayList<>();

            for (ModifiedRequestResponse entry : entries) {
                int index = filteredEntries.indexOf(entry);
                if (index != -1) {
                    affectedRows.add(index);
                }
            }

            if (affectedRows.isEmpty()) {
                return;
            }

            // 排序行号
            affectedRows.sort(Integer::compareTo);

            // ★ 性能优化：合并连续的行范围
            int rangeStart = affectedRows.get(0);
            int rangeEnd = rangeStart;

            for (int i = 1; i < affectedRows.size(); i++) {
                int currentRow = affectedRows.get(i);

                if (currentRow == rangeEnd + 1) {
                    // 连续行，扩展范围
                    rangeEnd = currentRow;
                } else {
                    // 不连续，先刷新之前的范围
                    fireTableRowsUpdated(rangeStart, rangeEnd);
                    rangeStart = currentRow;
                    rangeEnd = currentRow;
                }
            }

            // 刷新最后一个范围
            fireTableRowsUpdated(rangeStart, rangeEnd);
        }
    }

    // =========================================================================
    // 原有方法
    // =========================================================================

    public synchronized OriginalRequestResponse findByMessageId(Integer messageId) {
        return originalRequestMap.get(messageId);
    }

    public ModifiedRequestResponse getModifiedEntryById(int id) {
        synchronized (modifiedEntries) {
            for (ModifiedRequestResponse entry : modifiedEntries) {
                if (entry.getId() == id) {
                    return entry;
                }
            }
        }
        logging.logToError("[TableModel] ModifiedRequestResponse entry NOT FOUND for ID: " + id + ", Total entries: " + modifiedEntries.size());
        return null;
    }

    @Override
    public int getRowCount() {
        synchronized (filteredEntries) {
            return filteredEntries.size();
        }
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
        ModifiedRequestResponse modifiedEntry;
        synchronized (filteredEntries) {
            if (row < 0 || row >= filteredEntries.size()) {
                return null;
            }
            modifiedEntry = filteredEntries.get(row);
        }

        if (modifiedEntry == null) {
            return null;
        }

        OriginalRequestResponse originalEntry = findByMessageId(modifiedEntry.getOriginalMessageId());

        try {
            switch (column) {
                case 0:
                    return modifiedEntry.getId();
                case 1:
                    return modifiedEntry.getOriginalMessageId();
                case 2:
                    return originalEntry != null ? originalEntry.getOriginalMethod() : "";
                case 3:
                    return originalEntry != null ? originalEntry.getOriginalUrl() : "";
                case 4:
                    return modifiedEntry.getTestType();
                case 5:
                    return modifiedEntry.getTestParameterName() != null ?
                            modifiedEntry.getTestParameterName() : "";
                case 6:
                    return modifiedEntry.getContentType() != null ?
                            modifiedEntry.getContentType() : "";
                case 7:
                    return modifiedEntry.getPayloadAlias() != null ?
                            modifiedEntry.getPayloadAlias() : "";
                case 8:
                    return modifiedEntry.getStatusCode() != -1 ?
                            modifiedEntry.getStatusCode() : "Pending";
                case 9:
                    return modifiedEntry.getCachedLenDiff();
                case 10:
                    return modifiedEntry.getModifiedBodyLengthWithoutHeader() != -1 ?
                            modifiedEntry.getModifiedBodyLengthWithoutHeader() : "Pending";
                case 11:
                    return modifiedEntry.getModifiedBodyLength() != -1 ?
                            modifiedEntry.getModifiedBodyLength() : "Pending";
                case 12:
                    return originalEntry != null && originalEntry.getOriginalResponseLenWithoutHeader() != -1 ?
                            originalEntry.getOriginalResponseLenWithoutHeader() : "Pending";
                case 13:
                    return modifiedEntry.getResponseTime();
                case 14:
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

        sorter.setComparator(14, (Comparator<Object>) (o1, o2) -> {
            if (o1 == null && o2 == null) return 0;
            if (o1 == null) return -1;
            if (o2 == null) return 1;
            return o1.toString().compareTo(o2.toString());
        });

        sorter.setComparator(9, (Comparator<Object>) (o1, o2) -> {
            if (o1 == null && o2 == null) return 0;
            if (o1 == null) return -1;
            if (o2 == null) return 1;

            String s1 = o1.toString();
            String s2 = o2.toString();

            if (s1.equals("Pending") && s2.equals("Pending")) return 0;
            if (s1.equals("Pending")) return -1;
            if (s2.equals("Pending")) return 1;

            try {
                int v1 = Integer.parseInt(s1.replace("+", ""));
                int v2 = Integer.parseInt(s2.replace("+", ""));
                return Integer.compare(v1, v2);
            } catch (NumberFormatException e) {
                return s1.compareTo(s2);
            }
        });

        for (int i = 0; i < getColumnCount(); i++) {
            if (i != 14 && i != 9) {
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

    public void setupTableRenderers(JTable table) {
        table.getColumnModel().getColumn(14).setCellRenderer(new ReflectCellRenderer());
        table.getColumnModel().getColumn(8).setCellRenderer(new StatusCodeCellRenderer());
        table.getColumnModel().getColumn(13).setCellRenderer(new TimeCellRenderer());
        table.getColumnModel().getColumn(7).setCellRenderer(new GrayBackgroundCellRenderer());
        table.getColumnModel().getColumn(9).setCellRenderer(new LenDiffCellRenderer());
        table.getColumnModel().getColumn(10).setCellRenderer(new GrayBackgroundCellRenderer());
    }

    public ModifiedRequestResponse getModifiedEntry(int row) {
        synchronized (filteredEntries) {
            if (row >= 0 && row < filteredEntries.size()) {
                return filteredEntries.get(row);
            }
        }
        return null;
    }

    public List<ModifiedRequestResponse> getAllModifiedEntries() {
        synchronized (modifiedEntries) {
            return new ArrayList<>(modifiedEntries);
        }
    }

    public void cleanup() {
        // 停止批量插入定时器
        if (batchInsertTimer != null) {
            batchInsertTimer.stop();
        }

        // 清理待处理队列
        pendingInserts.clear();

        // ★ 新增：清理索引
        modifiedEntriesIndex.clear();

        synchronized (modifiedEntries) {
            for (ModifiedRequestResponse entry : modifiedEntries) {
                entry.cleanup();
            }
        }
    }
}