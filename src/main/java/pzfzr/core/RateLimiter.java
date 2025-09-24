package pzfzr.core;

import burp.api.montoya.logging.Logging;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 阻塞令牌桶速率限制器 - 单例模式
 * 用于控制HTTP请求发送速率
 */
public class RateLimiter {
    // 单例实例
    private static volatile RateLimiter instance;

    // 默认配置
    private static final int DEFAULT_CAPACITY = 30;
    private static final int DEFAULT_REFILL_RATE = 30; // 每秒添加的令牌数
    private static final int DEFAULT_URL_RATE_LIMIT = 10; // 相同URL每秒最多获取的令牌数
    private static final long DEFAULT_URL_EXPIRE_TIME = 20000; // URL在无访问后的过期时间（毫秒）
    private static final long DEFAULT_REFILL_INTERVAL = 1000; // 默认令牌添加间隔（毫秒）

    // 锁和条件变量，用于线程同步
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();

    // 令牌桶配置
    private volatile int capacity;         // 桶容量
    private volatile int refillRate;       // 每秒添加的令牌数
    private volatile long refillPeriodNanos; // 添加一个令牌的时间间隔（纳秒）
    private volatile long refillIntervalMillis; // 添加令牌的时间间隔（毫秒）

    // URL限流配置
    private volatile int urlRateLimit;     // 相同URL每秒最多获取的令牌数
    private volatile long urlExpireTime;   // URL在无访问后的过期时间（毫秒）

    // 令牌桶状态
    private AtomicInteger tokens;          // 当前令牌数
    private volatile long lastRefillTime;  // 上次添加令牌的时间

    // URL访问控制映射：URL -> [访问次数, 上次重置时间]
    private final Map<String, UrlThrottleInfo> urlThrottleMap = new ConcurrentHashMap<>();

    // 速率统计
    private AtomicInteger requestCount = new AtomicInteger(0);
    private volatile long startTimeMillis;
    private volatile boolean isShutdown = false;

    // 日志记录
    private Logging logging;
    // 新增字段：每批次最大header数量控制
    private volatile int maxHeadersPerBatch = 50; // 默认值为50


    /**
     * URL流量控制信息类
     */
    private static class UrlThrottleInfo {
        private AtomicInteger count;
        private long lastResetTime;

        public UrlThrottleInfo() {
            this.count = new AtomicInteger(0);
            this.lastResetTime = System.currentTimeMillis();
        }

        public int incrementAndGet() {
            return count.incrementAndGet();
        }

        public void reset() {
            count.set(0);
            lastResetTime = System.currentTimeMillis();
        }

        public int getCount() {
            return count.get();
        }

        public long getLastResetTime() {
            return lastResetTime;
        }
    }

    /**
     * 私有构造函数，防止直接实例化
     */
    private RateLimiter(Logging logging) {
        this.logging = logging;
        this.capacity = DEFAULT_CAPACITY;
        this.refillRate = DEFAULT_REFILL_RATE;
        this.urlRateLimit = DEFAULT_URL_RATE_LIMIT;
        this.urlExpireTime = DEFAULT_URL_EXPIRE_TIME;
        this.refillIntervalMillis = DEFAULT_REFILL_INTERVAL; // 初始化为默认添加间隔
        this.tokens = new AtomicInteger(capacity); // 初始时令牌桶是满的
        updateRefillPeriodNanos(); // 计算refillPeriodNanos
        this.lastRefillTime = System.nanoTime();
        this.startTimeMillis = System.currentTimeMillis();

        // 启动后台令牌补充线程
        Thread refillThread = new Thread(this::refillLoop);
        refillThread.setDaemon(true);
        refillThread.setName("rate-limiter-refill");
        refillThread.start();

        // 启动统计日志线程
        Thread statsThread = new Thread(this::logStats);
        statsThread.setDaemon(true);
        statsThread.setName("rate-limiter-stats");
        statsThread.start();

        // 启动URL限流计数器重置线程
        Thread urlThrottleThread = new Thread(this::urlThrottleResetLoop);
        urlThrottleThread.setDaemon(true);
        urlThrottleThread.setName("url-throttle-reset");
        urlThrottleThread.start();

        logging.logToOutput("[RateLimiter] Initialized. Capacity: " + capacity + ", Rate: " + refillRate +
                " requests/sec, URL rate limit: " + urlRateLimit + " requests/sec, URL expiry: " + (urlExpireTime/1000) + " sec" +
                ", Token refill interval: " + refillIntervalMillis + " ms");

    }

    /**
     * 获取单例实例
     */
    public static RateLimiter getInstance(Logging logging) {
        if (instance == null) {
            synchronized (RateLimiter.class) {
                if (instance == null) {
                    instance = new RateLimiter(logging);
                }
            }
        }
        return instance;
    }

    /**
     * 更新refillPeriodNanos的值，基于refillRate和refillIntervalMillis
     */
    private void updateRefillPeriodNanos() {
        // 如果refillRate为0，设置一个极大的时间间隔
        if (refillRate == 0) {
            this.refillPeriodNanos = Long.MAX_VALUE;
            return;
        }

        // 计算在指定时间间隔内添加的令牌数
        double tokensPerInterval = (double) refillRate * refillIntervalMillis / 1000.0;

        // 如果tokensPerInterval小于1，则使用默认的单个令牌间隔
        if (tokensPerInterval < 1.0) {
            // 使用默认方式：每秒refillRate个令牌
            this.refillPeriodNanos = TimeUnit.SECONDS.toNanos(1) / refillRate;
        } else {
            // 在refillIntervalMillis毫秒内添加tokensPerInterval个令牌
            // 每个令牌的添加间隔为refillIntervalMillis / tokensPerInterval
            this.refillPeriodNanos = (long)(TimeUnit.MILLISECONDS.toNanos(refillIntervalMillis) / tokensPerInterval);
        }
    }

    /**
     * 获取令牌（阻塞方法）
     * 如果没有可用令牌，会阻塞直到有令牌可用
     */
    public void acquire() {
        if (isShutdown) {
            return;
        }

        lock.lock();
        try {
            while (tokens.get() <= 0) {
                try {
                    notEmpty.await(100, TimeUnit.MILLISECONDS); // 等待令牌
                    if (isShutdown) {
                        return;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logging.logToError("[RateLimiter] Waiting for token was interrupted");
                    return;
                }
            }
            tokens.decrementAndGet();
            requestCount.incrementAndGet();
        } finally {
            lock.unlock();
        }
    }

    /**
     * 获取令牌（阻塞方法）- 带URL限流
     * 如果没有可用令牌或URL已达到限流阈值，会阻塞直到可以获取令牌
     * @param url 请求的URL
     */
    public void acquire(String url) {
        if (isShutdown) {
            return;
        }

        // 首先检查URL访问频率
        boolean urlAllowed = false;
        while (!urlAllowed) {
            if (isShutdown) {
                return;
            }

            urlAllowed = checkUrlThrottle(url);
            if (!urlAllowed) {
                try {
                    Thread.sleep(50); // 稍等片刻再次尝试
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logging.logToError("[RateLimiter] Waiting for token was interrupted");
                    return;
                }
            }
        }

        // URL检查通过后，获取全局令牌
        lock.lock();
        try {
            while (tokens.get() <= 0) {
                try {
                    notEmpty.await(100, TimeUnit.MILLISECONDS); // 等待令牌
                    if (isShutdown) {
                        return;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logging.logToError("[RateLimiter] Waiting for token was interrupted");
                    return;
                }
            }
            tokens.decrementAndGet();
            requestCount.incrementAndGet();
        } finally {
            lock.unlock();
        }
    }

    /**
     * 检查URL是否超过限流阈值
     * @param url 请求URL
     * @return 如果未超过限流阈值则返回true
     */
    private boolean checkUrlThrottle(String url) {
        UrlThrottleInfo info = urlThrottleMap.computeIfAbsent(url, k -> new UrlThrottleInfo());

        // 检查是否需要重置计数器（已经超过1秒）
        long currentTime = System.currentTimeMillis();
        if (currentTime - info.getLastResetTime() > 1000) {
            info.reset();
        }

        // 先检查是否已达到阈值，再增加计数
        if (info.getCount() >= urlRateLimit) {
            return false;  // 已达到限制，不增加计数，直接返回false
        }

        // 还未达到阈值，安全地增加计数
        info.incrementAndGet();
        return true;
    }

    /**
     * URL限流计数器重置循环
     */
    private void urlThrottleResetLoop() {
        while (!isShutdown) {
            try {
                Thread.sleep(1000); // 每秒检查一次
                long currentTime = System.currentTimeMillis();

                // 清理长时间未使用的URL
                urlThrottleMap.entrySet().removeIf(entry ->
                        currentTime - entry.getValue().getLastResetTime() > urlExpireTime); // 根据配置的过期时间移除

            } catch (InterruptedException e) {
                if (isShutdown) {
                    return;
                }
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 令牌补充循环
     */
    private void refillLoop() {
        while (!isShutdown) {
            refillTokens();
            try {
                Thread.sleep(50); // 每50ms检查一次是否需要补充令牌
            } catch (InterruptedException e) {
                if (isShutdown) {
                    return;
                }
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 根据经过的时间补充令牌
     */
    private void refillTokens() {
        // 如果速率为0，则不添加任何令牌
        if (refillRate == 0) {
            return;
        }
        long now = System.nanoTime();
        long elapsed = now - lastRefillTime;

        if (elapsed < refillPeriodNanos) {
            return; // 还没到添加令牌的时间
        }

        // 计算应该添加的令牌数
        int tokensToAdd = (int) (elapsed / refillPeriodNanos);
        if (tokensToAdd > 0) {
            lock.lock();
            try {
                int newTokens = Math.min(tokens.get() + tokensToAdd, capacity);
                tokens.set(newTokens);
                lastRefillTime = now;

                // 通知等待的线程有新令牌可用
                notEmpty.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * 打印速率统计信息
     */
    private void logStats() {
        int lastCount = 0;

        while (!isShutdown) {
            try {
                Thread.sleep(20000); // 每20秒记录一次统计信息

                int currentCount = requestCount.get();
                int diff = currentCount - lastCount;
                double rate = diff / 20.0; // 20秒内的请求速率

                logging.logToOutput(String.format("[RateLimiter] Current rate: %.2f requests/sec, Total requests: %d, Tokens: %d/%d, URL rate limit: %d requests/sec, URL map size: %d, Token refill interval: %d ms",
                        rate, currentCount, tokens.get(), capacity, urlRateLimit, urlThrottleMap.size(), refillIntervalMillis));

                lastCount = currentCount;
            } catch (InterruptedException e) {
                if (isShutdown) {
                    return;
                }
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 更新速率限制配置
     * @param newCapacity 新的令牌桶容量
     * @param newRefillRate 新的令牌补充速率（每秒）
     */
    public void updateConfiguration(int newCapacity, int newRefillRate) {
        updateConfiguration(newCapacity, newRefillRate, urlRateLimit, urlExpireTime, refillIntervalMillis, maxHeadersPerBatch);
    }

    /**
     * 更新速率限制配置（包含URL限流参数）
     * @param newCapacity 新的令牌桶容量
     * @param newRefillRate 新的令牌补充速率（每秒）
     * @param newUrlRateLimit 新的URL限流速率（每秒每URL）
     * @param newUrlExpireTime 新的URL过期时间（毫秒）
     */
    public void updateConfiguration(int newCapacity, int newRefillRate, int newUrlRateLimit, long newUrlExpireTime) {
        updateConfiguration(newCapacity, newRefillRate, newUrlRateLimit, newUrlExpireTime, refillIntervalMillis, maxHeadersPerBatch);
    }

    /**
     * 更新速率限制配置（包含所有参数）
     * @param newCapacity 新的令牌桶容量
     * @param newRefillRate 新的令牌补充速率（每秒）
     * @param newUrlRateLimit 新的URL限流速率（每秒每URL）
     * @param newUrlExpireTime 新的URL过期时间（毫秒）
     * @param newRefillIntervalMillis 新的令牌添加间隔（毫秒）
     */
    public void updateConfiguration(int newCapacity, int newRefillRate, int newUrlRateLimit, long newUrlExpireTime,
                                    long newRefillIntervalMillis, int maxHeadersPerBatch) {
        if (newCapacity <= 0 || newRefillRate < 0 || newUrlRateLimit < 0 || newUrlExpireTime < 0 || newRefillIntervalMillis <= 0) {
            logging.logToError("[RateLimiter] Invalid configuration: Capacity=" + newCapacity + ", Rate=" + newRefillRate +
                    ", URL rate limit=" + newUrlRateLimit + ", URL expiry=" + newUrlExpireTime +
                    ", Token refill interval=" + newRefillIntervalMillis);
            return;
        }

        lock.lock();
        try {
            logging.logToOutput("[RateLimiter] Updated configuration: Capacity " + capacity + "->" + newCapacity +
                    ", Rate " + refillRate + "->" + newRefillRate + " requests/sec" +
                    ", URL rate limit " + urlRateLimit + "->" + newUrlRateLimit + " requests/sec" +
                    ", URL expiry " + (urlExpireTime/1000) + "->" + (newUrlExpireTime/1000) + " sec" +
                    ", Token refill interval " + refillIntervalMillis + "->" + newRefillIntervalMillis + " ms");

            // Store previous values to check for changes
            int prevUrlRateLimit = this.urlRateLimit;
            long prevUrlExpireTime = this.urlExpireTime;

            this.capacity = newCapacity;
            this.refillRate = newRefillRate;
            this.urlRateLimit = newUrlRateLimit;
            this.urlExpireTime = newUrlExpireTime;
            this.refillIntervalMillis = newRefillIntervalMillis;
            if (maxHeadersPerBatch > 0) {
                this.maxHeadersPerBatch = maxHeadersPerBatch;
            }
            // 更新refillPeriodNanos的值
            updateRefillPeriodNanos();

            // If URL rate limit configuration changed, reset all URL throttles
            if (prevUrlRateLimit != newUrlRateLimit || prevUrlExpireTime != newUrlExpireTime) {
                // Clear all URL throttle entries to apply new settings immediately
                urlThrottleMap.clear();
                logging.logToOutput("[RateLimiter] URL rate limit configuration changed, reset all URL counters");
            }

            // 如果新容量大于当前令牌数，可以立即添加一些令牌
            int currentTokens = tokens.get();
            if (newCapacity > currentTokens) {
                tokens.set(Math.min(currentTokens + (newCapacity - currentTokens) / 2, newCapacity));
                notEmpty.signalAll(); // 通知等待的线程有新令牌可用
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * 获取当前令牌桶容量
     */
    public int getCapacity() {
        return capacity;
    }

    /**
     * 获取当前令牌补充速率
     */
    public int getRefillRate() {
        return refillRate;
    }

    /**
     * 获取当前令牌添加间隔（毫秒）
     */
    public long getRefillIntervalMillis() {
        return refillIntervalMillis;
    }

    /**
     * 获取当前URL限流速率
     */
    public int getUrlRateLimit() {
        return urlRateLimit;
    }

    /**
     * 获取当前URL过期时间（毫秒）
     */
    public long getUrlExpireTime() {
        return urlExpireTime;
    }

    /**
     * 获取当前令牌数
     */
    public int getAvailableTokens() {
        return tokens.get();
    }

    /**
     * 获取总请求数
     */
    public int getTotalRequests() {
        return requestCount.get();
    }
    // 新增getter方法
    public int getMaxHeadersPerBatch() {
        return maxHeadersPerBatch;
    }

    // 新增setter方法
    public void setMaxHeadersPerBatch(int maxHeadersPerBatch) {
        if (maxHeadersPerBatch > 0) {
            this.maxHeadersPerBatch = maxHeadersPerBatch;
        }
    }

    /**
     * 关闭速率限制器
     */
    public void shutdown() {
        logging.logToOutput("[RateLimiter] Shutting down rate limiter");
        isShutdown = true;

        lock.lock();
        try {
            notEmpty.signalAll(); // 唤醒所有等待的线程
        } finally {
            lock.unlock();
        }
    }
}