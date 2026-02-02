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
    private JTable associatedTable;
    private String currentFilter = "ALL";
    private RequestResponseSaver requestResponseSaver;
    private final Logging logging;

    // =========================================================================
    // P0 修复：真正的批量插入机制
    //
    // 原问题：每条 entry 都调用 fireTableRowsInserted，在 50qps 下每个请求还会生成多个
    // payload，实际 EDT 投递远超 50 次/秒。每次 fireTableRowsInserted 都让 TableRowSorter
    // 重新处理插入位置，累积效应直接堵死 EDT。
    //
    // 修复方案：
    //   1. addModifiedEntry 只往 pendingInserts 队列里放数据，不触发任何 UI 通知。
    //   2. 定时器每 500ms 触发一次，把队列里所有新数据一次性 addAll 到 filteredEntries，
    //      然后只发出一次 fireTableRowsInserted(startRow, endRow)。
    //   3. 这样排序开销从 N 次降为 1 次。
    //
    // P1 修复：彻底移除 performBatchRefresh 里的 fireTableDataChanged。
    //   fireTableDataChanged 会让 TableRowSorter 丢弃所有缓存并对全部数据重新排序，
    //   O(N log N) 在 10w+ 行时极其昂贵。它现在只保留在 updateFilteredEntries（切换 Tab）
    //   时使用，那是低频路径。
    //
    // P0 修复：彻底删除 viewToModelCache 及相关机制。
    //   rebuildViewToModelCache 里的 for 循环在 100w 行时就是 100万次迭代，而且在 EDT 上
    //   每 500ms 执行一次。这是堵死 EDT 的最大炸弹。JTable 内部的 convertRowIndexToModel
    //   在有 TableRowSorter 时本质是数组映射查找，开销极低，完全不需要自己缓存。
    // =========================================================================
    private final List<ModifiedRequestResponse> pendingInserts = new CopyOnWriteArrayList<>();
    private final javax.swing.Timer batchInsertTimer;
    private static final int BATCH_INSERT_INTERVAL_MS = 500;

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

    // =========================================================================
    // Cell Renderer 定义
    // 所有 Renderer 直接使用 table.convertRowIndexToModel(row)，
    // 不经过任何自定义缓存层。convertRowIndexToModel 在有 TableRowSorter 时
    // 内部是 O(1) 数组索引查找，开销可忽略。
    // =========================================================================

    // 通用的自定义单元格渲染器，用于Payload、Modif len列
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

    // 新增：Len Diff 列的专用渲染器（带符号和颜色）
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

    // 为响应时间列创建自定义渲染器
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

        // 批量插入定时器：每 500ms 检查一次 pendingInserts，
        // 如果有积压数据就一次性 flush，触发单次 fireTableRowsInserted(start, end)。
        // 执行完一次后停止，等下次 addModifiedEntry 调用时再 restart。
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
    // 过滤刷新 — 仅在切换 Tab 时调用，此时用 fireTableDataChanged 是合理的，
    // 因为 filteredEntries 的内容确实完全替换了。切换 Tab 是低频操作，不影响性能。
    // =========================================================================
    private void updateFilteredEntries() {
        // 切换 Tab 时需要先 flush 任何待处理的插入，确保数据一致
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
            // 切换 Tab 时用 fireTableDataChanged 是唯一合理的场景：
            // filteredEntries 内容被完全替换，Sorter 必须重新排序。
            // 这是低频操作（用户点击 Tab），开销可以接受。
            fireTableDataChanged();
        });
    }

    public synchronized OriginalRequestResponse createEntry(OriginalRequestResponse entry, int messageId) {
        originalRequestMap.put(messageId, entry);
        return entry;
    }

    // =========================================================================
    // P0 核心修复：批量插入入口
    //
    // 调用路径：后台线程 -> addModifiedEntry -> (如果不在EDT) invokeLater -> addModifiedEntryInternal
    // addModifiedEntryInternal 把数据放到 pendingInserts 队列里，然后 restart 定时器。
    // 定时器到期时 flushPendingInserts 被调用（在 EDT 上执行），一次性处理所有积压数据。
    // =========================================================================
    public void addModifiedEntry(ModifiedRequestResponse modifiedEntry) {
        if (SwingUtilities.isEventDispatchThread()) {
            addModifiedEntryInternal(modifiedEntry);
        } else {
            SwingUtilities.invokeLater(() -> addModifiedEntryInternal(modifiedEntry));
        }
    }

    /**
     * 在 EDT 上执行。
     * 只做数据预处理和入队，不触发任何 UI 通知。
     * 定时器到期后 flushPendingInserts 会统一处理。
     */
    private void addModifiedEntryInternal(ModifiedRequestResponse modifiedEntry) {
        // 在添加前计算 Len Diff
        OriginalRequestResponse originalEntry = findByMessageId(modifiedEntry.getOriginalMessageId());
        if (originalEntry != null) {
            modifiedEntry.updateLenDiff(originalEntry.getOriginalResponseLenWithoutHeader());
        }

        // 添加到主列表（对所有 Tab 的数据源）
        synchronized (modifiedEntries) {
            modifiedEntries.add(modifiedEntry);
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
            // 只入队，不触发任何 fire* 方法
            pendingInserts.add(modifiedEntry);

            // 启动/重启定时器。如果定时器已在倒计时中，restart 会重置计时。
            // 这意味着实际 flush 发生在"最后一次插入后 500ms"，确保尽量合并更多数据。
            if (!batchInsertTimer.isRunning()) {
                batchInsertTimer.start();
            }
        }
    }

    /**
     * 批量 flush — 在 EDT 上由定时器触发。
     * 将 pendingInserts 中的所有条目一次性加入 filteredEntries，
     * 然后发出一次 fireTableRowsInserted(startRow, endRow)。
     * 排序器只需处理一次插入事件，而不是 N 次。
     */
    private void flushPendingInserts() {
        if (pendingInserts.isEmpty()) {
            return;
        }

        // 原子取出当前队列内容并清空
        // CopyOnWriteArrayList 的迭代是快照，这里直接取全部然后清空是安全的
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

        // 核心优化：一次性通知 Swing 新增了 [startRow, endRow] 这一段行。
        // TableRowSorter 只需处理这一次插入，而不是逐条处理 N 次。
        // 对于倒序排序模式，这把排序开销从 O(N * log(totalRows)) 降到 O(batchSize * log(totalRows))。
        fireTableRowsInserted(startRow, endRow);
    }

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

    // =========================================================================
    // Sorter 设置 — 删除了所有 viewToModelCache 相关逻辑和 RowSorterListener。
    // Sorter 内部已经高效维护视图->模型映射，自己缓存反而是性能杀手。
    // =========================================================================
    public void setupSorter(JTable table) {
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(this);

        // Reflect 列的索引现在是 14
        sorter.setComparator(14, (Comparator<Object>) (o1, o2) -> {
            if (o1 == null && o2 == null) return 0;
            if (o1 == null) return -1;
            if (o2 == null) return 1;
            return o1.toString().compareTo(o2.toString());
        });

        // Len Diff 列（索引 9）的特殊排序器
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

        // 不再添加 RowSorterListener。
        // 原代码在 SORTED 事件中调用 rebuildViewToModelCache，
        // 那是在 100w 行时每次排序都执行百万级循环的根本原因。
        // 现在完全依赖 JTable 自身的映射机制，无需额外监听。

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

        synchronized (modifiedEntries) {
            for (ModifiedRequestResponse entry : modifiedEntries) {
                entry.cleanup();
            }
        }
    }
}