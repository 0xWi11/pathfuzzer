package pzfzr.core;

import burp.api.montoya.MontoyaApi;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 线程池监控类，可以独立监控一个 ScheduledExecutorService 的状态
 */
public class ThreadPoolMonitor {
    private final MontoyaApi api;
    private final ScheduledExecutorService executorService;
    private final ScheduledExecutorService monitorExecutor;
    private ScheduledFuture<?> monitorTask;

    private static final long DEFAULT_INITIAL_DELAY = 10;
    private static final long DEFAULT_PERIOD = 20;
    private static final TimeUnit DEFAULT_TIME_UNIT = TimeUnit.SECONDS;

    /**
     * 创建一个线程池监控器
     *
     * @param api Burp API接口
     * @param executorService 需要监控的线程池
     */
    public ThreadPoolMonitor(MontoyaApi api, ScheduledExecutorService executorService) {
        this.api = api;
        this.executorService = executorService;
        // 创建一个单线程的调度器，专门用于监控任务
        this.monitorExecutor = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "thread-pool-monitor");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * 使用默认参数启动监控
     */
    public void startMonitoring() {
        startMonitoring(DEFAULT_INITIAL_DELAY, DEFAULT_PERIOD, DEFAULT_TIME_UNIT);
    }

    /**
     * 使用自定义参数启动监控
     *
     * @param initialDelay 初始延迟
     * @param period 周期间隔
     * @param unit 时间单位
     */
    public void startMonitoring(long initialDelay, long period, TimeUnit unit) {
        if (monitorTask != null && !monitorTask.isDone()) {
            api.logging().logToOutput("[ThreadPoolMonitor] Monitoring already started");
            return;
        }

        monitorTask = monitorExecutor.scheduleAtFixedRate(
                this::logThreadPoolStatus,
                initialDelay,
                period,
                unit
        );

        api.logging().logToOutput("[ThreadPoolMonitor] Monitoring started with period: " + period + " " + unit.name());
    }

    /**
     * 停止监控
     */
    public void stopMonitoring() {
        if (monitorTask != null) {
            monitorTask.cancel(false);
            api.logging().logToOutput("[ThreadPoolMonitor] Monitoring stopped");
        }
    }

    /**
     * 关闭监控器释放资源
     */
    public void shutdown() {
        stopMonitoring();
        monitorExecutor.shutdownNow();
    }

    /**
     * 记录线程池状态，包含文本进度条
     */
    private void logThreadPoolStatus() {
        try {
            if (executorService instanceof ScheduledThreadPoolExecutor) {
                ScheduledThreadPoolExecutor executor = (ScheduledThreadPoolExecutor) executorService;
                // 获取当前时间格式
                java.text.SimpleDateFormat dateFormat = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String currentTime = dateFormat.format(new java.util.Date());

                // 计算进度信息
                long completedTasks = executor.getCompletedTaskCount();
                long totalTasks = executor.getTaskCount();

                // 计算原始百分比 (0.0 到 1.0)
                double percentage = (totalTasks > 0) ? (double) completedTasks / totalTasks : 0.0;

                // 格式化百分比字符串
                String progressPercentage = String.format("%.2f%%", percentage * 100);

                // --- 进度条生成逻辑 ---
                int barWidth = 50; // 进度条的总宽度（字符数）
                int filledWidth = (int) (percentage * barWidth);
                int emptyWidth = barWidth - filledWidth;

                StringBuilder progressBar = new StringBuilder("[");
                for (int i = 0; i < filledWidth; i++) {
                    progressBar.append("#"); // 已完成的部分用 # 表示
                }
                for (int i = 0; i < emptyWidth; i++) {
                    progressBar.append("_"); // 未完成的部分用 _ 表示
                }
                progressBar.append("]");
                // --- 进度条生成逻辑结束 ---


                StringBuilder status = new StringBuilder();
                status.append("[Thread Pool Status] ").append(currentTime).append(" - ");
                status.append("Pool size: ").append(executor.getPoolSize()).append(", ");
                status.append("Active threads: ").append(executor.getActiveCount()).append(", ");
                status.append("Tasks in queue: ").append(executor.getQueue().size()).append(" - ");
                status.append("Total tasks: ").append(totalTasks);
                status.append(", Completed: ").append(completedTasks).append("/").append(totalTasks);
                status.append(" ").append(progressBar.toString()); // 添加进度条
                status.append(" (").append(progressPercentage).append(")"); // 添加百分比


                api.logging().logToOutput(status.toString());
            } else {
                api.logging().logToOutput("[ThreadPoolMonitor] The provided executor is not a ScheduledThreadPoolExecutor");
            }
        } catch (Exception e) {
            api.logging().logToError("[ThreadPoolMonitor] Error monitoring thread pool: " + e.getMessage());
        }
    }
}