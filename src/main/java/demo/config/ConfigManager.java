package demo.config;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.io.*;

public class ConfigManager {
    private static ConfigManager instance;
    private final List<String> payloadList;
    private final List<String> collectedList;
    private final List<String> suspiciousList;
    private final List<String> blackList;
    private final List<String> removeList;
    private final List<ConfigChangeListener> listeners;
    // 添加过滤规则列表
    private final List<FilterRule> filterRules;

    private ConfigManager() {
        payloadList = new CopyOnWriteArrayList<>();
        collectedList = new CopyOnWriteArrayList<>();
        suspiciousList = new CopyOnWriteArrayList<>();
        blackList = new CopyOnWriteArrayList<>();
        removeList = new CopyOnWriteArrayList<>();
        listeners = new ArrayList<>();
        // 初始化过滤规则列表
        filterRules = new CopyOnWriteArrayList<>();
    }

    public static synchronized ConfigManager getInstance() {
        if (instance == null) {
            instance = new ConfigManager();
        }
        return instance;
    }

    // === 过滤规则管理相关方法 ===
    public void addFilterRule(FilterRule rule) {
        filterRules.add(rule);
        notifyListeners(ConfigChangeType.FILTER_RULES);
    }

    public void removeFilterRule(FilterRule rule) {
        filterRules.remove(rule);
        notifyListeners(ConfigChangeType.FILTER_RULES);
    }

    public void updateFilterRule(FilterRule oldRule, FilterRule newRule) {
        int index = filterRules.indexOf(oldRule);
        if (index != -1) {
            filterRules.set(index, newRule);
            notifyListeners(ConfigChangeType.FILTER_RULES);
        }
    }

    public List<FilterRule> getFilterRules() {
        return new ArrayList<>(filterRules);
    }

    public boolean shouldFilter(HttpRequest request) {
        return filterRules.stream().anyMatch(rule -> rule.matches(request));
    }

    // === 原有的配置管理方法 ===
    public void loadFromFile(ConfigChangeType type, File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    switch (type) {
                        case PAYLOAD:
                            addPayload(line.trim());
                            break;
                        case COLLECTED:
                            addCollected(line.trim());
                            break;
                        case SUSPICIOUS:
                            addSuspicious(line.trim());
                            break;
                        case BLACKLIST:
                            addBlacklist(line.trim());
                            break;
                        case REMOVE:
                            addRemove(line.trim());
                            break;
                    }
                }
            }
        }
    }

    public void clearList(ConfigChangeType type) {
        switch (type) {
            case PAYLOAD:
                payloadList.clear();
                break;
            case COLLECTED:
                collectedList.clear();
                break;
            case SUSPICIOUS:
                suspiciousList.clear();
                break;
            case BLACKLIST:
                blackList.clear();
                break;
            case REMOVE:
                removeList.clear();
                break;
            case FILTER_RULES:
                filterRules.clear();
                break;
        }
        notifyListeners(type);
    }

    public void deduplicateList(ConfigChangeType type) {
        switch (type) {
            case PAYLOAD:
                deduplicateSpecificList(payloadList);
                break;
            case COLLECTED:
                deduplicateSpecificList(collectedList);
                break;
            case SUSPICIOUS:
                deduplicateSpecificList(suspiciousList);
                break;
            case BLACKLIST:
                deduplicateSpecificList(blackList);
                break;
            case REMOVE:
                deduplicateSpecificList(removeList);
                break;
        }
        notifyListeners(type);
    }

    private void deduplicateSpecificList(List<String> list) {
        Set<String> set = new LinkedHashSet<>(list);
        list.clear();
        list.addAll(set);
    }

    // Payload List operations
    public void addPayload(String payload) {
        payloadList.add(payload);
        notifyListeners(ConfigChangeType.PAYLOAD);
    }

    public void removePayload(String payload) {
        payloadList.remove(payload);
        notifyListeners(ConfigChangeType.PAYLOAD);
    }

    public List<String> getPayloadList() {
        return Collections.unmodifiableList(payloadList);
    }

    // Collected List operations
    public void addCollected(String item) {
        collectedList.add(item);
        notifyListeners(ConfigChangeType.COLLECTED);
    }

    public void removeCollected(String item) {
        collectedList.remove(item);
        notifyListeners(ConfigChangeType.COLLECTED);
    }

    public List<String> getCollectedList() {
        return Collections.unmodifiableList(collectedList);
    }

    // Suspicious List operations
    public void addSuspicious(String item) {
        suspiciousList.add(item);
        notifyListeners(ConfigChangeType.SUSPICIOUS);
    }

    public void removeSuspicious(String item) {
        suspiciousList.remove(item);
        notifyListeners(ConfigChangeType.SUSPICIOUS);
    }

    public List<String> getSuspiciousList() {
        return Collections.unmodifiableList(suspiciousList);
    }

    // Blacklist operations
    public void addBlacklist(String item) {
        blackList.add(item);
        notifyListeners(ConfigChangeType.BLACKLIST);
    }

    public void removeBlacklist(String item) {
        blackList.remove(item);
        notifyListeners(ConfigChangeType.BLACKLIST);
    }

    public List<String> getBlacklist() {
        return Collections.unmodifiableList(blackList);
    }
    public void addRemove(String item) {
        removeList.add(item);
        notifyListeners(ConfigChangeType.REMOVE);
    }

    public void removeRemove(String item) {
        removeList.remove(item);
        notifyListeners(ConfigChangeType.REMOVE);
    }

    public List<String> getRemoveList() {
        return Collections.unmodifiableList(removeList);
    }

    // Listener management
    public void addListener(ConfigChangeListener listener) {
        listeners.add(listener);
    }

    public void removeListener(ConfigChangeListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners(ConfigChangeType type) {
        for (ConfigChangeListener listener : listeners) {
            listener.onConfigChanged(type);
        }
    }

    public void clearAllLists() {
        payloadList.clear();
        collectedList.clear();
        suspiciousList.clear();
        blackList.clear();
        removeList.clear();
        filterRules.clear();
    }
}