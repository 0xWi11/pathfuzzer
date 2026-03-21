package pzfzr.core;

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * 参数黑名单管理类
 * JSON 参数路径遵循 JSONPath 约定，以 $ 开头（如 $.user.info.name）。
 * 内部存储时保留 $ 前缀；匹配时对两侧路径统一规范化，兼容有无 $ 的写法。
 */
public class ParamBlacklist {
    private static ParamBlacklist instance;

    private final Set<String> blacklist;
    private final List<BlacklistChangeListener> listeners;

    private ParamBlacklist() {
        this.blacklist = new CopyOnWriteArraySet<>();
        this.listeners = new ArrayList<>();
    }

    public static synchronized ParamBlacklist getInstance() {
        if (instance == null) {
            instance = new ParamBlacklist();
        }
        return instance;
    }

    // -------------------------------------------------------------------------
    // ★ 核心：路径规范化
    //    JSON 路径（含 "." 或 "[" 的路径，或显式以 "$" 开头）统一补全为 "$." 前缀。
    //    普通参数名（如 username、id）保持原样。
    // -------------------------------------------------------------------------

    /**
     * 规范化一个路径字符串：
     * <ul>
     *   <li>若已是 "$." 开头 → 保持不变</li>
     *   <li>若以 "$" 开头但无 "." → 补成 "$."（如 "$foo" → "$.foo"）</li>
     *   <li>若含 "." 或 "[" 但无 "$" → 补上 "$." 前缀（如 "user.name" → "$.user.name"）</li>
     *   <li>其余纯参数名 → 原样返回</li>
     * </ul>
     */
    private static String normalizePath(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return s;

        // 已有标准 "$." 前缀
        if (s.startsWith("$.")) {
            return s;
        }
        // 以 "$" 开头但后面没有 "."（容错）
        if (s.startsWith("$")) {
            return "$." + s.substring(1);
        }
        // 不含 "$"，但看起来是 JSON 路径（含 "." 或 "["）
        if (s.contains(".") || s.contains("[")) {
            return "$." + s;
        }
        // 纯参数名，原样返回
        return s;
    }

    // -------------------------------------------------------------------------
    // CRUD
    // -------------------------------------------------------------------------

    public boolean addItem(String item) {
        if (item == null || item.trim().isEmpty()) return false;
        boolean added = blacklist.add(normalizePath(item));
        if (added) notifyListeners();
        return added;
    }

    public int addItems(Collection<String> items) {
        if (items == null || items.isEmpty()) return 0;
        int count = 0;
        for (String item : items) {
            if (addItem(item)) count++;
        }
        return count;
    }

    public int addFromText(String text) {
        if (text == null || text.trim().isEmpty()) return 0;
        List<String> items = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) items.add(trimmed);
        }
        return addItems(items);
    }

    public void setFromText(String text) {
        Set<String> newItems = new HashSet<>();
        if (text != null && !text.trim().isEmpty()) {
            for (String line : text.split("\\r?\\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    newItems.add(normalizePath(trimmed)); // ★ 存储时规范化
                }
            }
        }
        if (!blacklist.equals(newItems)) {
            blacklist.clear();
            blacklist.addAll(newItems);
            notifyListeners();
        }
    }

    public boolean removeItem(String item) {
        if (item == null) return false;
        boolean removed = blacklist.remove(normalizePath(item));
        if (removed) notifyListeners();
        return removed;
    }

    public void clear() {
        if (!blacklist.isEmpty()) {
            blacklist.clear();
            notifyListeners();
        }
    }

    // -------------------------------------------------------------------------
    // 查询
    // -------------------------------------------------------------------------

    /**
     * 检查路径是否在黑名单中（完全匹配 + 前缀匹配）。
     * 查询路径会先规范化，因此 "user.name" 与 "$.user.name" 等价。
     */
    public boolean isBlacklisted(String item) {
        if (item == null || item.trim().isEmpty()) return false;

        String normalized = normalizePath(item.trim()); // ★ 查询侧规范化

        // 1. 完全匹配
        if (blacklist.contains(normalized)) return true;

        // 2. 前缀匹配
        for (String entry : blacklist) {
            if (isPrefixMatch(normalized, entry)) return true;
        }
        return false;
    }

    /**
     * 前缀匹配：判断 fullPath 是否以 prefix 为前缀（对象属性或数组元素）。
     */
    private boolean isPrefixMatch(String fullPath, String prefix) {
        if (fullPath.equals(prefix)) return true;
        if (fullPath.startsWith(prefix + ".")) return true;
        if (fullPath.startsWith(prefix + "[")) return true;
        return false;
    }

    // -------------------------------------------------------------------------
    // 工具方法
    // -------------------------------------------------------------------------

    public List<String> getAll() {
        return new ArrayList<>(blacklist);
    }

    public int size() {
        return blacklist.size();
    }

    public boolean isEmpty() {
        return blacklist.isEmpty();
    }

    /** 返回排序后的文本，每行一项（已含规范化的 $ 前缀）。 */
    public String toText() {
        if (blacklist.isEmpty()) return "";
        List<String> sorted = new ArrayList<>(blacklist);
        Collections.sort(sorted);
        return String.join("\n", sorted);
    }

    // -------------------------------------------------------------------------
    // 监听器
    // -------------------------------------------------------------------------

    public void addListener(BlacklistChangeListener listener) {
        if (listener != null && !listeners.contains(listener)) listeners.add(listener);
    }

    public void removeListener(BlacklistChangeListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners() {
        for (BlacklistChangeListener l : listeners) {
            try { l.onBlacklistChanged(); } catch (Exception ignored) {}
        }
    }

    public interface BlacklistChangeListener {
        void onBlacklistChanged();
    }
}