package pzfzr.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.security.MessageDigest;
import java.util.regex.Pattern;

/**
 * RequestResponseSaver - 支持Netty的版本
 */
public class RequestResponseSaver {

    private final Path STORAGE_DIR;
    private static final int HEADER_SIZE = 4;
    private final LZ4Factory lz4Factory = LZ4Factory.fastestInstance();
    private final Logging logging;
    private final TableModel tableModel;
    private final String dailyDirHash;

    // 使用更高效的线程池配置
    private final ExecutorService ioExecutor;
    private final ExecutorService processingExecutor;

    // 批处理配置
    private static final int BATCH_SIZE = 50;
    private static final int BATCH_TIMEOUT_MS = 200;

    // 缓存配置
    private final Map<Integer, CompletableFuture<Void>> pendingWrites = new ConcurrentHashMap<>();
    private final BlockingQueue<WriteTask> writeQueue = new LinkedBlockingQueue<>();

    // 统计信息
    private final AtomicLong totalWrites = new AtomicLong(0);
    private final AtomicLong totalReads = new AtomicLong(0);
    private final AtomicLong writeErrors = new AtomicLong(0);

    private static final Path BASE_DIR = Paths.get(System.getProperty("user.home"), ".burp", "path_fuzzer");
    private static final Path HISTORY_DIR = BASE_DIR.resolve("project_request_history");

    private volatile boolean isShutdown = false;

    public RequestResponseSaver(Logging logging, TableModel tableModel) {
        this.logging = logging;
        this.tableModel = tableModel;
        this.dailyDirHash = generateRandomHash();
        this.STORAGE_DIR = createDailyStorageDir();

        if (this.STORAGE_DIR == null) {
            throw new StorageException("[RequestResponseSaver] Failed to create daily storage directory.");
        }

        // 创建IO线程池 - 用于文件操作
        this.ioExecutor = new ThreadPoolExecutor(
                5, 20,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                new ThreadFactory() {
                    private final AtomicInteger threadNumber = new AtomicInteger(1);
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread thread = new Thread(r, "rs-io-" + threadNumber.getAndIncrement());
                        thread.setDaemon(true);
                        thread.setPriority(Thread.MIN_PRIORITY + 1);
                        return thread;
                    }
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        // 创建处理线程池 - 用于响应处理
        this.processingExecutor = new ForkJoinPool(
                Math.min(Runtime.getRuntime().availableProcessors() * 2, 16),
                ForkJoinPool.defaultForkJoinWorkerThreadFactory,
                null,
                true
        );

        // 启动批处理写入线程
        startBatchWriter();

        logging.logToOutput("[RequestResponseSaver] Initialization complete, storage directory: " + STORAGE_DIR);
    }

    /**
     * 处理Netty的异步响应
     */
    public void handleNettyResponse(HttpResponse response, int id, long responseTime,
                                    ModifiedRequestResponse modifiedEntry) {
        if (isShutdown) {
            return;
        }

        processingExecutor.execute(() -> {
            try {
                // 保存响应
                saveModifiedResponseAsync(response, id, responseTime).thenRun(() -> {
                    // 更新表格模型
                    if (modifiedEntry != null) {
                        int responseLength = calculateResponseLengthWithoutSetCookieValues(response);
                        modifiedEntry.setModifiedResponseAndCalculateMetadata(
                                response.statusCode(),
                                responseLength,
                                response.body().length(),
                                detectReflectType(response),
                                responseTime
                        );
                    }
                }).exceptionally(ex -> {
                    logging.logToError("[RequestResponseSaver] Failed to process response for ID " + id + ": " + ex.getMessage());
                    return null;
                });
            } catch (Exception e) {
                logging.logToError("[RequestResponseSaver] Error handling Netty response: " + e.getMessage());
            }
        });
    }

    /**
     * 处理OkHttp的异步响应（保留以支持向后兼容）
     */
    public void handleOkHttpResponse(HttpResponse response, int id, long responseTime,
                                     ModifiedRequestResponse modifiedEntry) {
        handleNettyResponse(response, id, responseTime, modifiedEntry);
    }

    /**
     * 异步保存修改后的响应
     */
    private CompletableFuture<Void> saveModifiedResponseAsync(HttpResponse response, int id, long timingData) {
        String filename = "ModResp_" + id + "_" + timingData + ".lz4";
        return storeDataAsync(response.toByteArray(), filename);
    }

    /**
     * 异步存储数据
     */
    private CompletableFuture<Void> storeDataAsync(ByteArray data, String filename) {
        if (isShutdown) {
            return CompletableFuture.completedFuture(null);
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        pendingWrites.put(filename.hashCode(), future);

        WriteTask task = new WriteTask(data, filename, future);
        writeQueue.offer(task);

        return future;
    }

    /**
     * 批处理写入线程
     */
    private void startBatchWriter() {
        Thread writerThread = new Thread(() -> {
            List<WriteTask> batch = new ArrayList<>(BATCH_SIZE);

            while (!isShutdown) {
                try {
                    // 等待第一个任务
                    WriteTask task = writeQueue.poll(BATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    if (task != null) {
                        batch.add(task);

                        // 收集更多任务形成批次
                        writeQueue.drainTo(batch, BATCH_SIZE - 1);

                        // 批量写入
                        processBatch(batch);
                        batch.clear();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logging.logToError("[RequestResponseSaver] Batch writer error: " + e.getMessage());
                }
            }
        });

        writerThread.setName("rs-batch-writer");
        writerThread.setDaemon(true);
        writerThread.start();
    }

    /**
     * 处理批量写入
     */
    private void processBatch(List<WriteTask> batch) {
        if (batch.isEmpty()) {
            return;
        }

        // 使用并行流处理批次
        batch.parallelStream().forEach(task -> {
            try {
                storeDataInternal(task.data, task.filename);
                task.future.complete(null);
                totalWrites.incrementAndGet();
            } catch (Exception e) {
                task.future.completeExceptionally(e);
                writeErrors.incrementAndGet();
                logging.logToError("[RequestResponseSaver] Failed to write " + task.filename + ": " + e.getMessage());
            } finally {
                pendingWrites.remove(task.filename.hashCode());
            }
        });
    }

    /**
     * 内部存储数据方法 - 优化版本
     */
    private void storeDataInternal(ByteArray data, String filename) throws StorageException {
        Path file = STORAGE_DIR.resolve(filename);

        try (FileChannel channel = FileChannel.open(file,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {

            byte[] rawData = data.getBytes();
            LZ4Compressor compressor = lz4Factory.fastCompressor();

            // 使用更高的压缩级别以减少IO
            int maxCompressedSize = compressor.maxCompressedLength(rawData.length);
            byte[] compressedData = new byte[maxCompressedSize];

            int compressedSize = compressor.compress(rawData, 0, rawData.length,
                    compressedData, 0, maxCompressedSize);

            // 写入原始长度和压缩数据
            ByteBuffer buffer = ByteBuffer.allocateDirect(HEADER_SIZE + compressedSize);
            buffer.putInt(rawData.length);
            buffer.put(compressedData, 0, compressedSize);
            buffer.flip();

            channel.write(buffer);

        } catch (IOException e) {
            throw new StorageException("[RequestResponseSaver] Failed to store data to " + filename, e);
        }
    }

    /**
     * 保存原始请求 - 异步版本
     */
    public void saveOriginalRequest(HttpRequest request, int messageID) {
        if (isShutdown) return;
        storeDataAsync(request.toByteArray(), "OrigReq_" + messageID + ".lz4");
    }

    /**
     * 保存原始响应 - 异步版本
     */
    public void saveOriginalResponse(HttpResponse response, int messageID) {
        if (isShutdown) return;
        storeDataAsync(response.toByteArray(), "OrigResp_" + messageID + ".lz4");
    }

    /**
     * 保存修改后的请求 - 异步版本
     */
    public void saveModifiedRequest(HttpRequest request, int id) {
        if (isShutdown) return;
        storeDataAsync(request.toByteArray(), "ModReq_" + id + ".lz4");
    }

    /**
     * 计算响应长度，排除Set-Cookie值
     */
    private int calculateResponseLengthWithoutSetCookieValues(HttpResponse response) {
        if (response == null) {
            return -1;
        }

        byte[] fullResponse = response.toByteArray().getBytes();
        int totalLength = fullResponse.length;
        int setCookieValuesLength = 0;

        for (HttpHeader header : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                setCookieValuesLength += header.value().length();
            }
        }

        return totalLength - setCookieValuesLength;
    }

    /**
     * 检测反射类型
     */
    private String detectReflectType(HttpResponse response) {
        if (response == null) {
            return "";
        }
        List<String> detectedTypes = new ArrayList<>();
        try {
            if (response.contains("73504", false) || response.contains("918891889188", false)) {
                detectedTypes.add("SSTI-73504-9188");
            }
            if (response.contains("/bin/sh", false)) {
                detectedTypes.add("LFI");
            }
            if (response.contains("Message too large to display", false)) {
                detectedTypes.add("Large");
            }
            if (response.contains("chaxx123'\">", false)) {
                detectedTypes.add("RXSS");
            }
            if (response.contains("SHELL=/", false) || response.contains("PWD=/", false) || response.contains("HOME=/", false) ) {
                detectedTypes.add("CMDI");
            }
            if (response.contains("\"swagger\":", false) || response.contains("\"swaggerVersion\":", false)) {
                detectedTypes.add("SWAGGER");
            }
            if (response.contains("Whitelabel Error Page", false)) {
                detectedTypes.add("Spring Boot");
            }
            if (response.contains("debug mode</a> is enabled.", false) || response.contains("id=\"sfWebDebugSymfony\"", false)) {
                detectedTypes.add("SYMFONY");
            }
            // 检测 Actuator 端点
            String responseBody = response.bodyToString(); // 根据实际API调整
            if (Pattern.compile("\"href\":\"http.*?/actuator\"").matcher(responseBody).find()) {
                detectedTypes.add("ACTUATOR");
            }
            // 新增：检测 HTTP 505 错误，不区分大小写
            if (response.contains("HTTP/1.1 505 HTTP Version Not Supported", false)) {
                detectedTypes.add("505 HTTP Version");
            }
            // 检测CRLF漏洞
            for (HttpHeader header : response.headers()) {
                if (header.name().toLowerCase().contains("c9w") ||
                        header.name().toLowerCase().contains("v5m") ||
                        header.name().equalsIgnoreCase("www.xixicrt.top") ) {
                    detectedTypes.add("CRLF");
                    break;
                }
            }
            return String.join(",", detectedTypes);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 数据加载方法 - 优化版本
     */
    public ByteArray loadData(String filename) throws StorageException {
        Path file = STORAGE_DIR.resolve(filename);
        if (!Files.exists(file)) {
            return null;
        }

        totalReads.incrementAndGet();

        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer buffer = ByteBuffer.allocateDirect((int) channel.size());
            channel.read(buffer);
            buffer.flip();

            int originalSize = buffer.getInt();
            byte[] compressedData = new byte[buffer.remaining()];
            buffer.get(compressedData);

            LZ4FastDecompressor decompressor = lz4Factory.fastDecompressor();
            byte[] restored = new byte[originalSize];
            decompressor.decompress(compressedData, 0, restored, 0, originalSize);

            return ByteArray.byteArray(restored);
        } catch (IOException e) {
            throw new StorageException("[RequestResponseSaver] Failed to load data from " + filename, e);
        }
    }

    /**
     * 创建每日存储目录
     */
    private Path createDailyStorageDir() {
        LocalDateTime now = LocalDateTime.now();
        String monthDir = now.format(DateTimeFormatter.ofPattern("yyyyMM"));
        String dayDir = now.format(DateTimeFormatter.ofPattern("dd")) + "_" + this.dailyDirHash;

        Path monthlyHistoryDir = HISTORY_DIR.resolve(monthDir);
        Path dailyStorageDir = monthlyHistoryDir.resolve(dayDir);

        try {
            Files.createDirectories(dailyStorageDir);
            logging.logToOutput("[RequestResponseSaver] Created daily storage directory: " + dailyStorageDir);
            return dailyStorageDir;
        } catch (IOException e) {
            logging.logToError("[RequestResponseSaver] Failed to create directory: " + e.getMessage());
            return null;
        }
    }

    /**
     * 生成随机哈希
     */
    private String generateRandomHash() {
        try {
            String randomStr = UUID.randomUUID().toString();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(randomStr.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < Math.min(hash.length, 4); i++) {
                result.append(String.format("%02x", hash[i]));
            }
            return result.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString().substring(0, 8);
        }
    }

    /**
     * 获取统计信息
     */
    public String getStats() {
        return String.format("Storage Stats - Total Writes: %d, Total Reads: %d, Write Errors: %d, Pending: %d",
                totalWrites.get(), totalReads.get(), writeErrors.get(), writeQueue.size());
    }

    /**
     * 清理存储
     */
    public void cleanupStorage() {
        logging.logToOutput("[RequestResponseSaver] Starting cleanup...");
        isShutdown = true;

        // 等待所有待处理的写入完成
        int retries = 0;
        while (!writeQueue.isEmpty() && retries < 50) {
            try {
                Thread.sleep(100);
                retries++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // 关闭线程池
        ioExecutor.shutdown();
        processingExecutor.shutdown();

        try {
            if (!ioExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                ioExecutor.shutdownNow();
            }
            if (!processingExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                processingExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            ioExecutor.shutdownNow();
            processingExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // 清理空目录
        if (STORAGE_DIR != null) {
            try {
                if (Files.list(STORAGE_DIR).findAny().isEmpty()) {
                    Files.delete(STORAGE_DIR);
                    logging.logToOutput("[RequestResponseSaver] Deleted empty directory: " + STORAGE_DIR);
                }
            } catch (IOException e) {
                logging.logToError("[RequestResponseSaver] Failed to clean directory: " + e.getMessage());
            }
        }

        logging.logToOutput("[RequestResponseSaver] Cleanup complete. " + getStats());
    }

    public Path getDailyStorageDir() {
        return STORAGE_DIR;
    }

    public String generateFilename(String extension) {
        String dateStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String randomStr = UUID.randomUUID().toString().substring(0, 8);
        return dateStr + "_" + randomStr + "." + extension;
    }

    /**
     * 写入任务
     */
    private static class WriteTask {
        final ByteArray data;
        final String filename;
        final CompletableFuture<Void> future;

        WriteTask(ByteArray data, String filename, CompletableFuture<Void> future) {
            this.data = data;
            this.filename = filename;
            this.future = future;
        }
    }

    /**
     * 存储异常
     */
    private static class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }

        public StorageException(String message) {
            super(message);
        }
    }
}