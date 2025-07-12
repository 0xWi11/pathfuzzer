package pzfzr.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

public class PersistenceManager {
    private static final Path BASE_DIR = Paths.get(System.getProperty("user.home"), ".burp", "path_fuzzer");
    private static final Path CONFIG_DIR = BASE_DIR.resolve("config");
    private static final Path CONFIG_FILE = CONFIG_DIR.resolve("config.json");
    private static final Path COLLECTED_LIST_FILE = CONFIG_DIR.resolve("CollectedList.txt");
    private final ExecutorService responseExecutor = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final ConfigManager configManager;
    private final Gson gson;


    public PersistenceManager(ConfigManager configManager) {
        this.configManager = configManager;
        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .create();

        initializeDirectories();
        setupAutomaticSaving();
    }

    private void initializeDirectories() {
        try {
            Files.createDirectories(CONFIG_DIR);
            // 创建当月目录
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    private void setupAutomaticSaving() {
        // 每15秒保存一次配置
        scheduler.scheduleAtFixedRate(this::saveConfig, 15, 15, TimeUnit.SECONDS);
    }

    // 配置相关的数据类
    private static class ConfigData {
        List<String> payloadList;
        List<String> collectedList;
        List<String> suspiciousList;
        List<String> blackList;
        List<String> removeList;
        List<FilterRule> filterRules;
    }

    public void saveConfig() {
        // 保存主配置文件
        ConfigData configData = new ConfigData();
        configData.payloadList = configManager.getPayloadList();
        configData.collectedList = configManager.getCollectedList();
        configData.suspiciousList = configManager.getSuspiciousList();
        configData.blackList = configManager.getBlacklist();
        configData.removeList = configManager.getRemoveList();
        configData.filterRules = configManager.getFilterRules();

        try {
            // 保存config.json
            String json = gson.toJson(configData);
            Files.writeString(CONFIG_FILE, json, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            // 创建每日备份文件
            String dateStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
            Path backupFile = CONFIG_DIR.resolve(dateStr + "config.json");
            Files.writeString(backupFile, json, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            // 保存CollectedList.txt
            saveCollectedListToTxt();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 新增方法：保存CollectedList到txt文件
    private void saveCollectedListToTxt() {
        try {
            List<String> collectedList = configManager.getCollectedList();
            if (collectedList == null || collectedList.isEmpty()) {
                // 如果集合为空，创建一个空文件
                Files.writeString(COLLECTED_LIST_FILE, "", StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                return;
            }

            // 使用StringBuilder拼接每一行
            StringBuilder content = new StringBuilder();
            for (String item : collectedList) {
                content.append(item).append(System.lineSeparator());
            }

            // 写入文件
            Files.writeString(COLLECTED_LIST_FILE, content.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            // 创建每日备份文件
            String dateStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
            Path backupFile = CONFIG_DIR.resolve(dateStr + "CollectedList.txt");
            Files.writeString(backupFile, content.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void loadConfig() {
        if (!Files.exists(CONFIG_FILE)) {
            return;
        }

        try {
            String json = Files.readString(CONFIG_FILE, StandardCharsets.UTF_8);
            ConfigData configData = gson.fromJson(json, ConfigData.class);

            configManager.clearAllLists();

            if (configData.payloadList != null) {
                configData.payloadList.forEach(configManager::addPayload);
            }
            if (configData.collectedList != null) {
                configData.collectedList.forEach(configManager::addCollected);
            }
            if (configData.suspiciousList != null) {
                configData.suspiciousList.forEach(configManager::addSuspicious);
            }
            if (configData.blackList != null) {
                configData.blackList.forEach(configManager::addBlacklist);
            }
            if (configData.removeList != null) {
                configData.removeList.forEach(configManager::addRemove);
            }
            if (configData.filterRules != null) {
                configData.filterRules.forEach(configManager::addFilterRule);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void shutdown() {
        // 先关闭调度器
        scheduler.shutdown();
        responseExecutor.shutdown();
        try {
            // 确保最后一次保存配置
            saveConfig();

            // 等待所有定时任务完成
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
            // 关闭响应执行器
            if (!responseExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                responseExecutor.shutdownNow();
            }
        } catch (Exception e) {
            // 确保强制关闭
            scheduler.shutdownNow();
            responseExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}