package pzfzr.core;

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * 参数黑名单管理类
 * 用于管理需要跳过测试的参数（支持JSONPath和参数名）
 * 支持完全匹配和前缀匹配两种模式
 */
public class ParamBlacklist {
    private static ParamBlacklist instance;

    // 使用线程安全的Set存储黑名单，提供O(1)查找效率
    private final Set<String> blacklist;

    // 监听器列表，用于通知UI更新
    private final List<BlacklistChangeListener> listeners;

    private ParamBlacklist() {
        this.blacklist = new CopyOnWriteArraySet<>();
        this.listeners = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized ParamBlacklist getInstance() {
        if (instance == null) {
            instance = new ParamBlacklist();
        }
        return instance;
    }

    /**
     * 添加黑名单项
     * @param item 黑名单项（参数名或JSONPath）
     * @return 是否成功添加（false表示已存在）
     */
    public boolean addItem(String item) {
        if (item == null || item.trim().isEmpty()) {
            return false;
        }

        String trimmedItem = item.trim();
        boolean added = blacklist.add(trimmedItem);

        if (added) {
            notifyListeners();
        }

        return added;
    }

    /**
     * 批量添加黑名单项
     * @param items 黑名单项列表
     * @return 成功添加的数量
     */
    public int addItems(Collection<String> items) {
        if (items == null || items.isEmpty()) {
            return 0;
        }

        int addedCount = 0;
        for (String item : items) {
            if (addItem(item)) {
                addedCount++;
            }
        }

        return addedCount;
    }

    /**
     * 从文本内容批量添加（每行一个）
     * @param text 文本内容
     * @return 成功添加的数量
     */
    public int addFromText(String text) {
        if (text == null || text.trim().isEmpty()) {
            return 0;
        }

        String[] lines = text.split("\\r?\\n");
        List<String> items = new ArrayList<>();

        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                items.add(trimmed);
            }
        }

        return addItems(items);
    }

    /**
     * 从文本内容重新设置黑名单（清空后重新添加）
     * @param text 文本内容
     */
    public void setFromText(String text) {
        Set<String> newItems = new HashSet<>();

        if (text != null && !text.trim().isEmpty()) {
            String[] lines = text.split("\\r?\\n");
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    newItems.add(trimmed);
                }
            }
        }

        // 检查是否有变化
        if (!blacklist.equals(newItems)) {
            blacklist.clear();
            blacklist.addAll(newItems);
            notifyListeners();
        }
    }

    /**
     * 移除黑名单项
     * @param item 要移除的项
     * @return 是否成功移除
     */
    public boolean removeItem(String item) {
        if (item == null) {
            return false;
        }

        boolean removed = blacklist.remove(item.trim());

        if (removed) {
            notifyListeners();
        }

        return removed;
    }

    /**
     * 清空黑名单
     */
    public void clear() {
        if (!blacklist.isEmpty()) {
            blacklist.clear();
            notifyListeners();
        }
    }

    /**
     * 检查项是否在黑名单中（支持完全匹配和前缀匹配）
     * @param item 要检查的项
     * @return 是否在黑名单中
     */
    public boolean isBlacklisted(String item) {
        if (item == null || item.trim().isEmpty()) {
            return false;
        }

        String trimmedItem = item.trim();

        // 1. 完全匹配检查
        if (blacklist.contains(trimmedItem)) {
            return true;
        }

        // 2. 前缀匹配检查（支持跳过整个对象）
        // 例如：黑名单中有 "tasks[0]"，则 "tasks[0].task_id" 会被跳过
        for (String blacklistItem : blacklist) {
            if (isPrefixMatch(trimmedItem, blacklistItem)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查是否为前缀匹配
     * @param fullPath 完整路径（如 tasks[0].task_id）
     * @param prefix 前缀（如 tasks[0]）
     * @return 是否匹配
     */
    private boolean isPrefixMatch(String fullPath, String prefix) {
        if (fullPath.equals(prefix)) {
            return true;
        }

        // 检查是否以 prefix. 开头（对象属性）
        if (fullPath.startsWith(prefix + ".")) {
            return true;
        }

        // 检查是否以 prefix[ 开头（数组元素）
        if (fullPath.startsWith(prefix + "[")) {
            return true;
        }

        return false;
    }

    /**
     * 获取所有黑名单项（返回副本）
     * @return 黑名单项列表
     */
    public List<String> getAll() {
        return new ArrayList<>(blacklist);
    }

    /**
     * 获取黑名单项数量
     * @return 数量
     */
    public int size() {
        return blacklist.size();
    }

    /**
     * 检查黑名单是否为空
     * @return 是否为空
     */
    public boolean isEmpty() {
        return blacklist.isEmpty();
    }

    /**
     * 获取所有项的文本表示（每行一个）
     * @return 文本内容
     */
    public String toText() {
        if (blacklist.isEmpty()) {
            return "";
        }

        List<String> sorted = new ArrayList<>(blacklist);
        Collections.sort(sorted);

        return String.join("\n", sorted);
    }

    /**
     * 添加监听器
     */
    public void addListener(BlacklistChangeListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * 移除监听器
     */
    public void removeListener(BlacklistChangeListener listener) {
        listeners.remove(listener);
    }

    /**
     * 通知所有监听器
     */
    private void notifyListeners() {
        for (BlacklistChangeListener listener : listeners) {
            try {
                listener.onBlacklistChanged();
            } catch (Exception e) {
                // 忽略监听器异常
            }
        }
    }

    /**
     * 黑名单变化监听器接口
     */
    public interface BlacklistChangeListener {
        void onBlacklistChanged();
    }
}