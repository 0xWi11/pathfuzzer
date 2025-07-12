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
import java.security.MessageDigest;

public class RequestResponseSaver {

    private final Path STORAGE_DIR;
    private static final int HEADER_SIZE = 4;
    private final LZ4Factory lz4Factory = LZ4Factory.fastestInstance();
    private final Logging logging;
    private final ScheduledExecutorService executorService;
    private final Map<Integer, HttpRequestResponse> modifiedRequestResponses = new ConcurrentHashMap<>();
    // 新增：记录每个ID的轮询重试次数
    private final ConcurrentMap<Integer, Integer> pollingRetries = new ConcurrentHashMap<>();
    private final String dailyDirHash;
    private final TableModel tableModel;
    private static final Path BASE_DIR = Paths.get(System.getProperty("user.home"), ".burp", "path_fuzzer");
    private static final Path HISTORY_DIR = BASE_DIR.resolve("project_request_history");
    private final Set<Integer> pendingResponseIds = new ConcurrentSkipListSet<>();
    private volatile boolean pollingScheduled = false;
    private static final int POLLING_DELAY_MS = 500;
    private static final int MAX_POLLING_RETRIES = 210;

    public RequestResponseSaver(Logging logging, TableModel tableModel) {
        this.logging = logging;
        this.dailyDirHash = generateRandomHash();
        this.STORAGE_DIR = createDailyStorageDir();
        if (this.STORAGE_DIR == null) {
            throw new StorageException("[RequestResponseSaver] Failed to create daily storage directory.");
        }
        this.tableModel = tableModel;

        this.executorService = new ScheduledThreadPoolExecutor(
                5,
                new ThreadFactory() {
                    private final AtomicInteger threadNumber = new AtomicInteger(1);
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread thread = new Thread(r, "request-response-saver-thread-" + threadNumber.getAndIncrement());
                        thread.setDaemon(true);
                        return thread;
                    }
                }
        );
        ((ScheduledThreadPoolExecutor) executorService).setMaximumPoolSize(25);
        ((ScheduledThreadPoolExecutor) executorService).setKeepAliveTime(60L, TimeUnit.SECONDS);
        ((ScheduledThreadPoolExecutor) executorService).setRejectedExecutionHandler(
                (r, executor) -> logging.logToError("[RequestResponseSaver] RequestResponseSaver task rejected: thread pool overloaded")
        );
    }

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
            logging.logToError("[RequestResponseSaver] Failed to create daily storage directory: " + dailyStorageDir + ", error: " + e.getMessage());
            return null;
        }
    }

    private String generateRandomHash() {
        try {
            String randomStr = UUID.randomUUID().toString();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(randomStr.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (byte b : hash) {
                result.append(String.format("%02x", b));
            }
            return result.substring(0, 8);
        } catch (Exception e) {
            return UUID.randomUUID().toString().substring(0, 8);
        }
    }

    // 保存原始请求
    public void saveOriginalRequest(HttpRequest request, int messageID) {
        executorService.execute(() -> {
            try {
                storeData(request.toByteArray(), "OrigReq_" + messageID + ".lz4");
            } catch (StorageException e) {
                logging.logToError("[RequestResponseSaver] Failed to save original request for messageID " + messageID + ": " + e.getMessage());
            }
        });
    }

    // 保存原始响应
    public void saveOriginalResponse(HttpResponse response, int messageID) {
        executorService.execute(() -> {
            try {
                storeData(response.toByteArray(), "OrigResp_" + messageID + ".lz4");
            } catch (StorageException e) {
                logging.logToError("[RequestResponseSaver] Failed to save original response for messageID " + messageID + ": " + e.getMessage());
            }
        });
    }

    // 保存修改后的请求
    public void saveModifiedRequest(HttpRequest request, int id) {
        executorService.execute(() -> {
            try {
                storeData(request.toByteArray(), "ModReq_" + id + ".lz4");
            } catch (StorageException e) {
                logging.logToError("[RequestResponseSaver] Failed to save modified request for ID " + id + ": " + e.getMessage());
            }
        });
    }

    // 异步处理修改后的响应，使用 Debounce 机制
    public void handleDelayedModifiedResponse(HttpRequestResponse modifiedRequestResponse, int id) {
        modifiedRequestResponses.put(id, modifiedRequestResponse);
        pendingResponseIds.add(id);
        schedulePollingTask();
    }

    // 调度轮询任务，如果尚未调度
    private void schedulePollingTask() {
        if (!pollingScheduled) {
            pollingScheduled = true;
            executorService.schedule(this::pollAndSaveModifiedResponses, POLLING_DELAY_MS, TimeUnit.MILLISECONDS);
        }
    }

    // 批量轮询并保存修改后的响应（优化后的部分）
    private void pollAndSaveModifiedResponses() {
        pollingScheduled = false;

        if (pendingResponseIds.isEmpty()) {
            return;
        }

        Set<Integer> idsToPoll = new HashSet<>(pendingResponseIds);
        pendingResponseIds.clear();

        for (Integer id : idsToPoll) {
            HttpRequestResponse httpRequestResponse = modifiedRequestResponses.get(id);
            if (httpRequestResponse == null) {
                logging.logToError("[RequestResponseSaver] HttpRequestResponse not found for modified ID: " + id + ", potential memory leak or logic error.");
                continue;
            }

            HttpResponse response = httpRequestResponse.response();
            if (response != null) {
                try {
                    saveModifiedResponseInternal(response, id, httpRequestResponse.timingData().get().timeBetweenRequestSentAndStartOfResponse().toMillis());
//                    logging.logToOutput("RequestResponseSaver: Attempting to get ModifiedEntry by ID: " + id + " from TableModel"); // 添加日志，记录尝试获取的 ID
                    ModifiedRequestResponse modifiedEntry = null;
                    for (int i = 0; i < 4 && (modifiedEntry = tableModel.getModifiedEntryById(id)) == null; i++) {
                        try {
                            Thread.sleep(100* i * i);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                    if (modifiedEntry == null)
                        throw new RuntimeException("[RequestResponseSaver] ModifiedRequestResponse entry not found in TableModel for ID: " + id);
                    modifiedEntry.setModifiedResponseAndCalculateMetadata(
                            response.statusCode(), response.body().length(), detectReflectType(response),
                            httpRequestResponse.timingData().get().timeBetweenRequestSentAndStartOfResponse().toMillis()
                    );
                    httpRequestResponse = null;
                    response = null;
                    modifiedRequestResponses.remove(id);
                    pollingRetries.remove(id);
                } catch (StorageException e) {
                    logging.logToError("[RequestResponseSaver] Failed to save modified response for ID " + id + ": " + e.getMessage());
                }
            } else {
                // 累计重试次数
                int retries = pollingRetries.getOrDefault(id, 0) + 1;
                if (retries < MAX_POLLING_RETRIES) {
                    pollingRetries.put(id, retries);
                    pendingResponseIds.add(id);
                } else {
                    httpRequestResponse = null;
                    response = null;
                    pollingRetries.remove(id);
                    modifiedRequestResponses.remove(id);
                    logging.logToError("[RequestResponseSaver] Maximum polling retries reached for modified ID: " + id + ". Response might not be saved.retry times: " + retries);
                }
            }
        }
        if (!pendingResponseIds.isEmpty()) {
            schedulePollingTask();
        }
    }

    // 内部方法：保存修改后的响应（被轮询和直接调用）
    private void saveModifiedResponseInternal(HttpResponse response, int id, long timingData) throws StorageException {
        storeData(response.toByteArray(), "ModResp_" + id + "_" + timingData + ".lz4");
    }

    // 底层数据存储方法
    private void storeData(ByteArray data, String filename) throws StorageException {
        Path file = STORAGE_DIR.resolve(filename);
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {

            byte[] rawData = data.getBytes();
            LZ4Compressor compressor = lz4Factory.fastCompressor();
            int maxCompressedSize = compressor.maxCompressedLength(rawData.length);

            ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE + maxCompressedSize);
            buffer.putInt(rawData.length); // 写入原始数据长度

            int compressedSize = compressor.compress(rawData, 0, rawData.length,
                    buffer.array(), HEADER_SIZE, maxCompressedSize);

            buffer.position(0);
            buffer.limit(HEADER_SIZE + compressedSize);
            channel.write(buffer);
            rawData = null;
        } catch (IOException e) {
            throw new StorageException("[RequestResponseSaver] Failed to store data to " + filename, e);
        }
    }

    // 数据加载方法
    public ByteArray loadData(String filename) throws StorageException {
        Path file = STORAGE_DIR.resolve(filename);
        if (!Files.exists(file)) {
            return null;
        }

        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer headerBuffer = ByteBuffer.allocate(HEADER_SIZE);
            channel.read(headerBuffer);
            headerBuffer.flip();
            int originalSize = headerBuffer.getInt();

            int compressedSize = (int)(channel.size() - HEADER_SIZE);
            ByteBuffer compressedBuffer = ByteBuffer.allocate(compressedSize);
            channel.read(compressedBuffer);
            byte[] compressedData = compressedBuffer.array();

            LZ4FastDecompressor decompressor = lz4Factory.fastDecompressor();
            byte[] restored = new byte[originalSize];
            decompressor.decompress(compressedData, 0, restored, 0, originalSize);

            return ByteArray.byteArray(restored);
        } catch (IOException e) {
            throw new StorageException("[RequestResponseSaver] Failed to load data from " + filename, e);
        }
    }
    private String detectReflectType(HttpResponse response) {
        if (response == null) {
            return "";
        }
        List<String> detectedTypes = new ArrayList<>(); // 使用 List 存储检测到的漏洞类型
        try {
            if (response.contains("chaxx123'\">", false)) {
                detectedTypes.add("RXSS");
            }
            if (response.contains("chaxx123", false)) {
                detectedTypes.add("STRR");
            }
            if (response.contains("You have an error in your SQL", false) ||
                    response.contains("Unclosed quotation mark", false)) {
                detectedTypes.add("SQLI");
            }
            if (response.contains("/bin/sh", false)) {
                detectedTypes.add("LFI");
            }
            if (response.contains("SHELL=/", false) || response.contains("PWD=/", false) || response.contains("HOME=/", false) ) {
                detectedTypes.add("CMDI");
            }
            // 检测CRLF漏洞
            for (HttpHeader header : response.headers()) {
                if (header.name().toLowerCase().contains("c9w") || header.name().toLowerCase().contains("v5m")) {
                    detectedTypes.add("CRLF");
                    break; // 找到 CRLF 相关的 header 后，可以跳出循环，提高效率
                }
            }

            // 将检测到的漏洞类型列表转换为逗号分隔的字符串
            if (!detectedTypes.isEmpty()) {
                return String.join(",", detectedTypes);
            } else {
                return "";
            }

        } catch (Exception e) {
            return "";
        }
    }
    /**
     * Returns the current daily storage directory path
     * @return Path to daily storage directory
     */
    public Path getDailyStorageDir() {
        return STORAGE_DIR;
    }

    /**
     * Generates a filename with the specified extension using YYYYMMDD+hash format
     * @param extension File extension (without dot)
     * @return Generated filename
     */
    public String generateFilename(String extension) {
        String dateStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String randomStr = UUID.randomUUID().toString().substring(0, 8);
        return dateStr + "_" + randomStr + "." + extension;
    }
    public void cleanupStorage() {
        executorService.shutdownNow(); // 更改为 shutdownNow 立即关闭
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) { // 等待一段时间，以便记录错误信息 (可选，可以适当缩短时间)
                logging.logToError("[RequestResponseSaver] Executor service did not terminate in 10 seconds after shutdownNow.");
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow(); // 再次调用 shutdownNow，确保停止
            Thread.currentThread().interrupt();
            logging.logToError("[RequestResponseSaver] Executor service termination interrupted.");
        }

        // 检查文件夹是否为空
        if (STORAGE_DIR != null) {
            try {
                // 获取目录中的文件列表
                try (java.util.stream.Stream<Path> files = Files.list(STORAGE_DIR)) {
                    // 检查目录是否为空
                    if (!files.findAny().isPresent()) {
                        // 目录为空，删除它
                        logging.logToOutput("[RequestResponseSaver] Directory is empty. Deleting: " + STORAGE_DIR);
                        Files.delete(STORAGE_DIR);
                        logging.logToOutput("[RequestResponseSaver] Successfully deleted empty directory: " + STORAGE_DIR);
                    } else {
                        // 目录不为空，不删除
                        logging.logToOutput("[RequestResponseSaver] Directory is not empty. Keeping: " + STORAGE_DIR);
                    }
                }
            } catch (IOException e) {
                logging.logToError("[RequestResponseSaver] Failed to check or delete daily storage directory: " + STORAGE_DIR + ", error: " + e.getMessage());
            }
        }

        modifiedRequestResponses.clear();
        pendingResponseIds.clear();
        pollingRetries.clear();
    }

    private static class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
        public StorageException(String message) {
            super(message);
        }
    }
}
