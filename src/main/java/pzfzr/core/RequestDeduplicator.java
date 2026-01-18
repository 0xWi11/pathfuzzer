package pzfzr.core;

import burp.api.montoya.logging.Logging;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public class RequestDeduplicator {
    private static RequestDeduplicator instance;
    private final ConcurrentHashMap<Integer, Long> requestHashes = new ConcurrentHashMap<>();
    private final ScheduledExecutorService expiryScheduler = Executors.newSingleThreadScheduledExecutor();
    private final Logging logging;

    // 存储用户配置的正则表达式列表
    private volatile List<Pattern> noSkipUrlPatterns = new ArrayList<>();

    private RequestDeduplicator(Logging logging) {
        this.logging = logging;
        setDefaultNoSkipUrlPatterns();
        expiryScheduler.scheduleAtFixedRate(this::removeExpiredHashes, 10, 10, TimeUnit.MINUTES);
    }

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

    private void setDefaultNoSkipUrlPatterns() {
        List<Pattern> patterns = new ArrayList<>();
        try {
            patterns.add(Pattern.compile("(?i).*graphql.*"));
        } catch (Exception e) {
            logging.logToError("[RequestDeduplicator] Error setting default patterns: " + e.getMessage());
        }
        this.noSkipUrlPatterns = patterns;
    }

    public void setNoSkipUrlPatterns(List<String> regexPatterns) {
        List<Pattern> patterns = new ArrayList<>();

        if (regexPatterns == null || regexPatterns.isEmpty()) {
            setDefaultNoSkipUrlPatterns();
            return;
        }

        for (String regex : regexPatterns) {
            try {
                patterns.add(Pattern.compile(regex));
            } catch (Exception e) {
                logging.logToError("[RequestDeduplicator] Invalid regex pattern: " + regex +
                        ", Error: " + e.getMessage());
            }
        }

        if (patterns.isEmpty()) {
            setDefaultNoSkipUrlPatterns();
        } else {
            this.noSkipUrlPatterns = patterns;
        }

    }

    public List<String> getNoSkipUrlPatterns() {
        List<String> patterns = new ArrayList<>();
        for (Pattern pattern : noSkipUrlPatterns) {
            patterns.add(pattern.pattern());
        }
        return patterns;
    }

    private boolean matchesNoSkipPattern(String url) {
        if (noSkipUrlPatterns.isEmpty()) {
            return false;
        }

        for (Pattern pattern : noSkipUrlPatterns) {
            try {
                if (pattern.matcher(url).matches()) {
                    return true;
                }
            } catch (Exception e) {
                logging.logToError("[RequestDeduplicator] Error matching pattern: " +
                        pattern.pattern() + ", Error: " + e.getMessage());
            }
        }
        return false;
    }

    public boolean shouldSkipRequest(String method, String url, String re) {
        // 对URL进行规范化处理
        String normalizedUrl = normalizeUrl(url);

        // 计算hash
        int requestHash = Objects.hash(method, normalizedUrl, re);

        if (matchesNoSkipPattern(url)) {
            if (!"RouteFuzzer".equals(re)) {
                if (!requestHashes.containsKey(requestHash)) {
                    requestHashes.put(requestHash, Instant.now().plusSeconds(6 * 24 * 60 * 60).toEpochMilli());
                }
                return false;
            }
        }

        if (requestHashes.containsKey(requestHash)) {
            if (isHashExpired(requestHash)) {
                requestHashes.remove(requestHash);
                return false;
            }
            return true;
        } else {
            requestHashes.put(requestHash, Instant.now().plusSeconds(6 * 24 * 60 * 60).toEpochMilli());
            return false;
        }
    }

    /**
     * 规范化URL，移除攻击payload中的随机变化部分
     */
    private String normalizeUrl(String url) {
        try {
            // 1. 移除query参数
            String baseUrl = removeQueryParameters(url);

            // 2. 规范化 zcyy.fun 的所有子域名
            baseUrl = normalizeZcyyFunSubdomains(baseUrl);

            return baseUrl;

        } catch (Exception e) {
            logging.logToError("[RequestDeduplicator] Error normalizing URL: " + e.getMessage());
            return removeQueryParameters(url);
        }
    }

    /**
     * 规范化 zcyy.fun 的所有子域名，统一替换为 zcyy.fun
     * 例如: @ua0rf.tejq8.zcyy.fun -> @zcyy.fun
     *      //el0u6.tejq8.zcyy.fun -> //zcyy.fun
     */
    private String normalizeZcyyFunSubdomains(String url) {
        // 快速检查：如果URL中不包含目标域名，直接返回
        if (!url.contains("zcyy.fun")) {
            return url;
        }

        // 只有包含 zcyy.fun 时才执行正则替换
        // 匹配模式：任意字符.zcyy.fun 替换为 zcyy.fun
        return url.replaceAll("([a-zA-Z0-9-]+\\.)+zcyy\\.fun", "zcyy.fun");
    }

    private String removeQueryParameters(String url) {
        int questionMarkIndex = url.indexOf('?');
        if (questionMarkIndex != -1) {
            return url.substring(0, questionMarkIndex);
        }
        return url;
    }

    private boolean isHashExpired(int requestHash) {
        Long expiryTime = requestHashes.get(requestHash);
        if (expiryTime == null) {
            return true;
        }
        return Instant.now().toEpochMilli() > expiryTime;
    }

    private void removeExpiredHashes() {
        long now = Instant.now().toEpochMilli();
        requestHashes.entrySet().removeIf(entry -> now > entry.getValue());
    }

    public void clearAllHashes() {
        int count = requestHashes.size();
        requestHashes.clear();
        logging.logToOutput("[RequestDeduplicator] Manually cleared all " + count + " request hashes.");
    }

    public int getHashCount() {
        return requestHashes.size();
    }

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
        requestHashes.clear();
        logging.logToOutput("[RequestDeduplicator] RequestDeduplicator shutdown complete.");
    }
}