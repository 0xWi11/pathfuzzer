package pzfzr.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import burp.api.montoya.http.message.HttpHeader;

/**
 * 一个单例类，用于存储和管理不同主机的请求头。
 * 用于替换请求中与认证相关的请求头。
 */
public class CookieChanger {

    // 单例实例
    private static volatile CookieChanger instance;

    // 用于存储主机 -> 请求头映射关系的数据结构
    // Map<host, List<HeaderEntry>> - 注意：键现在是存储的模式，不一定是请求主机
    private final Map<String, List<HeaderEntry>> hostHeadersMap;

    /**
     * 私有构造函数，强制使用单例模式
     */
    private CookieChanger() {
        // 使用 LinkedHashMap 可能稍微好一些，可以保持插入顺序以便显示，
        // 但 HashMap 在这里对于查找逻辑已经足够了。
        hostHeadersMap = new HashMap<>();
    }

    /**
     * 获取 CookieChanger 的单例实例
     *
     * @return 单例实例
     */
    public static CookieChanger getInstance() {
        if (instance == null) {
            synchronized (CookieChanger.class) {
                if (instance == null) {
                    instance = new CookieChanger();
                }
            }
        }
        return instance;
    }

    /**
     * 存储请求头条目列表
     *
     * @param entries 包含主机模式、请求头名称和请求头值的请求头条目列表
     */
    public void storeHeaderEntries(List<HeaderEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return;
        }

        synchronized (hostHeadersMap) {
            for (HeaderEntry entry : entries) {
                String hostPattern = entry.getHost();

                // 如果此主机模式不存在，则创建列表
                if (!hostHeadersMap.containsKey(hostPattern)) {
                    hostHeadersMap.put(hostPattern, new ArrayList<>());
                }

                // 将条目添加到主机模式的列表中
                // 注意：这允许同一主机模式有多个条目，这是可以的。
                // 如果你想要防止主机/请求头名称的重复，这里需要更多的逻辑。
                hostHeadersMap.get(hostPattern).add(entry);
            }
        }
    }

    /**
     * 存储单个请求头条目
     *
     * @param entry 要存储的请求头条目
     */
    public void storeHeaderEntry(HeaderEntry entry) {
        if (entry == null) {
            return;
        }

        // 虽然 storeHeaderEntries 可以处理列表，但对于单个条目
        // 如果我们想要在添加之前根据主机模式 + 请求头名称检查重复，
        // 这里直接添加会更直接。
        // 现在，让我们保持简单，只调用列表版本。
        List<HeaderEntry> entries = new ArrayList<>();
        entries.add(entry);
        storeHeaderEntries(entries);
    }

    /**
     * 获取与请求的主机匹配的 HttpHeader 对象。
     * 处理精确匹配和通配符 *.domain 模式。
     *
     * @param requestHost 来自传入 HTTP 请求的主机
     * @return 匹配的 HttpHeader 对象列表，如果没有请求头匹配主机或没有存储规则则返回 null
     */
    public List<HttpHeader> getHttpHeadersForHost(String requestHost) {
        if (requestHost == null || requestHost.trim().isEmpty()) {
            return null;
        }

        synchronized (hostHeadersMap) {
            // 添加这个判断：如果 map 为空，直接返回 null
            if (hostHeadersMap.isEmpty()) {
                return null;
            }

            List<HeaderEntry> matchingEntries = new ArrayList<>();

            // 遍历所有存储的请求头条目列表
            // 注意：我们遍历 VALUES() 因为 KEYS 是模式
            // 我们需要检查每个模式与 requestHost 的匹配。
            for (List<HeaderEntry> entriesForPattern : hostHeadersMap.values()) {
                // 为列表本身添加 null 检查，虽然理论上如果键存在它不应该为 null，
                // 但这是良好的防御性编程。
                if (entriesForPattern == null) {
                    continue; // 如果列表意外为 null 则跳过
                }

                // 遍历列表中的每个单独条目
                for (HeaderEntry entry : entriesForPattern) {
                    String storedHostPattern = entry.getHost();

                    // --- 匹配逻辑 ---
                    boolean isMatch = false;
                    // 确保存储的模式在尝试匹配前不为 null 或空
                    if (storedHostPattern != null && !storedHostPattern.trim().isEmpty()) {
                        if (storedHostPattern.startsWith("*.")) {
                            // 通配符模式匹配：*.domain
                            String domainPart = storedHostPattern.substring(2); // 获取 "*." 后的 "domain" 部分
                            // 确保子字符串后域部分不为空
                            if (!domainPart.isEmpty()) {
                                // 检查请求主机是否以 ".domain" 结尾并且长度大于 ".domain"
                                // 长度检查防止 "*.example.com" 匹配 "example.com"
                                if (requestHost.endsWith("." + domainPart) && requestHost.length() > (domainPart.length() + 1)) {
                                    isMatch = true;
                                }
                            }
                        } else {
                            // 精确字符串匹配
                            if (requestHost.equals(storedHostPattern)) {
                                isMatch = true;
                            }
                        }
                    }

                    if (isMatch) {
                        matchingEntries.add(entry);
                    }
                }
            }

            if (matchingEntries.isEmpty()) {
                return null; // 如果没有请求头匹配任何规则则返回 null
            }

            // 将匹配的 HeaderEntry 对象转换为 HttpHeader 对象
            return matchingEntries.stream()
                    .map(entry -> HttpHeader.httpHeader(entry.getHeaderName(), entry.getHeaderValue()))
                    .collect(Collectors.toList());
        }
    }

    /**
     * 获取所有主机的所有请求头条目
     *
     * @return 所有请求头条目的列表
     */
    public List<HeaderEntry> getAllHeaderEntries() {
        synchronized (hostHeadersMap) {
            List<HeaderEntry> allEntries = new ArrayList<>();

            // 遍历映射中的值（条目列表）
            for (List<HeaderEntry> entries : hostHeadersMap.values()) {
                allEntries.addAll(entries);
            }

            return allEntries;
        }
    }

    /**
     * 更新现有的请求头条目
     *
     * @param oldEntry 要更新的条目（通过其原始主机模式、请求头名称和值识别）
     * @param newEntry 新的条目值（可能包含新的主机模式）
     * @return 如果条目已更新返回 true，否则返回 false
     */
    public boolean updateHeaderEntry(HeaderEntry oldEntry, HeaderEntry newEntry) {
        if (oldEntry == null || newEntry == null) {
            return false;
        }

        synchronized (hostHeadersMap) {
            String oldHostPattern = oldEntry.getHost();
            String newHostPattern = newEntry.getHost();

            // 检查旧主机模式是否存在于映射中
            if (!hostHeadersMap.containsKey(oldHostPattern)) {
                return false;
            }

            List<HeaderEntry> entriesList = hostHeadersMap.get(oldHostPattern);

            // 在列表中找到确切的 oldEntry
            int index = -1;
            for(int i=0; i < entriesList.size(); i++){
                if(entriesList.get(i).equals(oldEntry)){ // 使用重写的 equals 方法
                    index = i;
                    break;
                }
            }


            if (index == -1) {
                // 在其声明的主机模式列表中未找到旧条目
                return false;
            }

            // 如果主机模式已更改
            if (!oldHostPattern.equals(newHostPattern)) {
                // 从旧主机模式列表中移除
                entriesList.remove(index);

                // 添加到新主机模式列表
                if (!hostHeadersMap.containsKey(newHostPattern)) {
                    hostHeadersMap.put(newHostPattern, new ArrayList<>());
                }
                hostHeadersMap.get(newHostPattern).add(newEntry);

                // 如果旧列表变空，清理旧列表键
                if (entriesList.isEmpty()) {
                    hostHeadersMap.remove(oldHostPattern);
                }

            } else {
                // 相同主机模式，只需就地更新条目
                entriesList.set(index, newEntry);
            }

            return true;
        }
    }


    /**
     * 删除特定的请求头条目
     *
     * @param entryToDelete 要删除的条目（通过其主机模式、请求头名称和值识别）
     * @return 如果条目已删除返回 true，否则返回 false
     */
    public boolean deleteHeaderEntry(HeaderEntry entryToDelete) {
        if (entryToDelete == null) {
            return false;
        }

        synchronized (hostHeadersMap) {
            String hostPattern = entryToDelete.getHost();

            if (!hostHeadersMap.containsKey(hostPattern)) {
                return false;
            }

            List<HeaderEntry> entriesList = hostHeadersMap.get(hostPattern);

            // 从列表中查找并移除确切的条目
            boolean removed = entriesList.remove(entryToDelete); // 使用重写的 equals 方法

            // 如果此主机模式的列表现在为空，移除主机模式键
            if (entriesList.isEmpty()) {
                hostHeadersMap.remove(hostPattern);
            }

            return removed;
        }
    }


    /**
     * 清除所有存储的请求头条目
     */
    public void clearAll() {
        synchronized (hostHeadersMap) {
            hostHeadersMap.clear();
        }
    }

    /**
     * 清除特定主机模式的请求头条目
     *
     * @param hostPattern 要清除条目的主机模式
     */
    public void clearHost(String hostPattern) {
        synchronized (hostHeadersMap) {
            hostHeadersMap.remove(hostPattern);
        }
    }

    /**
     * 内部类，表示包含主机模式、请求头名称和请求头值的请求头条目
     */
    public static class HeaderEntry {
        // 从 'host' 重命名为 'hostPattern'，以便在 CookieChanger 类中更清晰
        private final String hostPattern;
        private final String headerName;
        private final String headerValue;

        public HeaderEntry(String hostPattern, String headerName, String headerValue) {
            this.hostPattern = hostPattern;
            this.headerName = headerName;
            this.headerValue = headerValue;
        }

        // Getter 保持 getHost() 以便与 TableModel 和 Dialog 兼容
        public String getHost() {
            return hostPattern;
        }

        public String getHeaderName() {
            return headerName;
        }

        public String getHeaderValue() {
            return headerValue;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;

            HeaderEntry that = (HeaderEntry) obj;

            // 相等性基于所有三个字段
            if (!hostPattern.equals(that.hostPattern)) return false;
            if (!headerName.equals(that.headerName)) return false;
            return headerValue.equals(that.headerValue);
        }

        @Override
        public int hashCode() {
            int result = hostPattern.hashCode();
            result = 31 * result + headerName.hashCode();
            result = 31 * result + headerValue.hashCode();
            return result;
        }
    }
}