package pzfzr.core;

import burp.api.montoya.logging.Logging;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class RequestDeduplicator {
    private static RequestDeduplicator instance;
    private final ConcurrentHashMap<Integer, Long> requestHashes = new ConcurrentHashMap<>(); // 存储请求哈希和过期时间戳
    private final ScheduledExecutorService expiryScheduler = Executors.newSingleThreadScheduledExecutor(); // 定时清理过期哈希
    private final Logging logging; // 用于日志记录

    private RequestDeduplicator(Logging logging) {
        this.logging = logging;
        // 启动定时任务，定期清理过期的哈希值
        expiryScheduler.scheduleAtFixedRate(this::removeExpiredHashes, 10, 10, TimeUnit.MINUTES); // 每分钟检查一次
    }

    // 单例模式获取实例
    public static RequestDeduplicator getInstance(Logging logging) {
        if (instance == null) {
            synchronized (RequestDeduplicator.class) {
                if (instance == null) {
                    instance = new RequestDeduplicator(logging);
                }
            }
        }
        return instance;
    }

    // 检查是否应该跳过请求
    public boolean shouldSkipRequest(String method, String url, String re) {
        // 修改URL处理逻辑，忽略问号后面的部分
        String baseUrl = removeQueryParameters(url);

        int requestHash = Objects.hash(method, baseUrl, re); // 使用处理后的URL计算哈希值
        if (requestHashes.containsKey(requestHash)) {
            // 检查哈希是否已过期
            if (isHashExpired(requestHash)) {
                requestHashes.remove(requestHash); // 如果过期则移除，允许再次测试
                return false; // 不跳过，允许本次请求
            }
            return true; // 跳过，请求在30分钟内已测试过
        } else {
            // 添加新的哈希值，并设置过期时间为30分钟后
            requestHashes.put(requestHash, Instant.now().plusSeconds(30 * 60).toEpochMilli());
            return false; // 不跳过，允许本次请求
        }
    }

    // 移除URL中的查询参数部分（问号及其后面的部分）
    private String removeQueryParameters(String url) {
        int questionMarkIndex = url.indexOf('?');
        if (questionMarkIndex != -1) {
            return url.substring(0, questionMarkIndex);
        }
        return url; // 如果没有问号，返回原始URL
    }

    // 检查哈希是否过期
    private boolean isHashExpired(int requestHash) {
        Long expiryTime = requestHashes.get(requestHash);
        if (expiryTime == null) {
            return true; // 如果哈希不存在，则视为过期
        }
        return Instant.now().toEpochMilli() > expiryTime;
    }

    // 定期清理过期哈希
    private void removeExpiredHashes() {
        long now = Instant.now().toEpochMilli();
        requestHashes.entrySet().removeIf(entry -> {
            if (now > entry.getValue()) {
//                logging.logToOutput("[RequestDeduplicator] Removed expired request hash: " + entry.getKey()); // 记录日志，可选
                return true; // 移除过期的哈希
            }
            return false;
        });
    }

    // 清除所有哈希
    public void clearAllHashes() {
        int count = requestHashes.size();
        requestHashes.clear();
        logging.logToOutput("[RequestDeduplicator] Manually cleared all " + count + " request hashes.");
    }

    // 获取当前哈希数量
    public int getHashCount() {
        return requestHashes.size();
    }

    // 在插件卸载时调用，关闭定时任务线程池
    public void shutdown() {
        logging.logToOutput("[RequestDeduplicator] RequestDeduplicator is shutting down...");
        expiryScheduler.shutdown();
        try {
            if (!expiryScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                expiryScheduler.shutdownNow();
                if (!expiryScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    logging.logToError("[RequestDeduplicator] RequestDeduplicator scheduler did not terminate.");
                }
            }
        } catch (InterruptedException e) {
            expiryScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        requestHashes.clear(); // 清理哈希列表
        logging.logToOutput("[RequestDeduplicator] RequestDeduplicator shutdown complete.");
    }
}