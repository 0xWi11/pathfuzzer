package pzfzr.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * RequestResponseSaver - SQLite版本，支持读写分离
 */
public class RequestResponseSaver {

    private final Path STORAGE_DIR;
    private final Logging logging;
    private final TableModel tableModel;
    private final String dailyDirHash;

    // SQLite连接 - 读写分离
    private Connection writeConnection;  // 专用于批量写入
    private Connection readConnection;   // 专用于数据读取
    private final Object connectionLock = new Object();

    // 线程池配置
    private final ExecutorService ioExecutor;
    private final ExecutorService processingExecutor;

    // 批处理配置
    private static final int BATCH_SIZE = 50;
    private static final int BATCH_TIMEOUT_MS = 200;

    // 写入队列和缓存
    private final Map<Integer, CompletableFuture<Void>> pendingWrites = new ConcurrentHashMap<>();
    private final BlockingQueue<WriteTask> writeQueue = new LinkedBlockingQueue<>();

    // 统计信息
    private final AtomicLong totalWrites = new AtomicLong(0);
    private final AtomicLong totalReads = new AtomicLong(0);
    private final AtomicLong writeErrors = new AtomicLong(0);

    private static final Path BASE_DIR = Paths.get(System.getProperty("user.home"), ".burp", "path_fuzzer");
    private static final Path HISTORY_DIR = BASE_DIR.resolve("project_request_history");

    private volatile boolean isShutdown = false;

    /**
     * 内部类：存储拆分后的HTTP数据
     */
    private static class HttpMessageParts {
        String headers;
        String body;
        boolean isBodyBase64;

        HttpMessageParts(String headers, String body, boolean isBodyBase64) {
            this.headers = headers;
            this.body = body;
            this.isBodyBase64 = isBodyBase64;
        }
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

    public RequestResponseSaver(Logging logging, TableModel tableModel) {
        this.logging = logging;
        this.tableModel = tableModel;
        this.dailyDirHash = generateRandomHash();
        this.STORAGE_DIR = createDailyStorageDir();

        if (this.STORAGE_DIR == null) {
            throw new StorageException("[RequestResponseSaver] Failed to create daily storage directory.");
        }

        // 初始化SQLite数据库
        initDatabase();

        // 创建IO线程池
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

        // 创建处理线程池
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
     * 初始化数据库连接
     */
    private void initDatabase() {
        try {
            // 显式加载SQLite JDBC驱动
            try {
                Class.forName("org.sqlite.JDBC");
                logging.logToOutput("[RequestResponseSaver] SQLite JDBC driver loaded successfully");
            } catch (ClassNotFoundException e) {
                throw new RuntimeException("SQLite JDBC driver not found. Please ensure sqlite-jdbc is in the classpath.", e);
            }

            String dbPath = STORAGE_DIR.resolve("requests.db").toString();

            // 创建写连接
            writeConnection = createConnection(dbPath);
            logging.logToOutput("[RequestResponseSaver] Write connection established");

            // 创建读连接
            readConnection = createConnection(dbPath);
            logging.logToOutput("[RequestResponseSaver] Read connection established");

            // 只在写连接上执行PRAGMA配置和建表
            configurePragmas(writeConnection);
            createTable(writeConnection);

            // 完整性检查
            checkDatabaseIntegrity(writeConnection);

            logging.logToOutput("[RequestResponseSaver] SQLite database initialized: " + dbPath);

        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize SQLite database", e);
        }
    }

    /**
     * 创建单个连接（支持重试）
     */
    private Connection createConnection(String dbPath) throws SQLException {
        int maxRetries = 3;
        SQLException lastException = null;

        for (int i = 0; i < maxRetries; i++) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
                return conn;
            } catch (SQLException e) {
                lastException = e;
                logging.logToError("[RequestResponseSaver] Connection attempt " + (i+1) + " failed: " + e.getMessage());
                if (i < maxRetries - 1) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        throw lastException;
    }

    /**
     * 配置PRAGMA参数
     */
    private void configurePragmas(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA journal_mode=WAL;");
            stmt.execute("PRAGMA synchronous=NORMAL;");
            stmt.execute("PRAGMA cache_size=-64000;");
            stmt.execute("PRAGMA page_size=8192;");
            stmt.execute("PRAGMA temp_store=MEMORY;");
            stmt.execute("PRAGMA mmap_size=268435456;");
            stmt.execute("PRAGMA auto_vacuum=INCREMENTAL;");
            stmt.execute("PRAGMA busy_timeout=5000;");
            stmt.execute("PRAGMA locking_mode=NORMAL;");
        }
    }

    /**
     * 创建表结构
     */
    private void createTable(Connection conn) throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS http_data (\n"
                + "    composite_key TEXT PRIMARY KEY,\n"
                + "    message_id INTEGER NOT NULL,\n"
                + "    data_type TEXT NOT NULL,\n"
                + "    timing_data INTEGER,\n"
                + "    header_data TEXT NOT NULL,\n"
                + "    body_data TEXT NOT NULL,\n"
                + "    is_body_base64 INTEGER DEFAULT 0\n"
                + ");\n"
                + "CREATE INDEX IF NOT EXISTS idx_message_id ON http_data(message_id);\n"
                + "CREATE INDEX IF NOT EXISTS idx_data_type ON http_data(data_type);";

        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }

    /**
     * 完整性检查
     */
    private void checkDatabaseIntegrity(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA integrity_check;")) {
            if (rs.next() && !"ok".equals(rs.getString(1))) {
                throw new SQLException("Database integrity check failed");
            }
        }
    }

    /**
     * 确保连接可用（健康检查）
     */
    private void ensureConnectionAlive(Connection conn) throws SQLException {
        if (conn == null || conn.isClosed() || !conn.isValid(2)) {
            throw new SQLException("Connection is not valid");
        }
    }

    /**
     * 拆分HTTP消息并智能编码body
     */
    private HttpMessageParts splitAndEncodeHttpMessage(ByteArray data, String dataType) {
        byte[] bytes = data.getBytes();

        // 查找 \r\n\r\n 分隔符位置
        int separatorIndex = findHeaderBodySeparator(bytes);

        String headers;
        String body;
        boolean isBodyBase64 = false;

        if (separatorIndex != -1) {
            // 分离header和body
            byte[] headerBytes = Arrays.copyOfRange(bytes, 0, separatorIndex);
            byte[] bodyBytes = Arrays.copyOfRange(bytes, separatorIndex + 4, bytes.length);

            // Header总是UTF-8文本
            headers = new String(headerBytes, StandardCharsets.UTF_8);

            // 检测body是否为二进制内容
            String contentType = extractContentType(headers);
            if (isBinaryContentType(contentType) || !isValidUtf8(bodyBytes)) {
                // 二进制内容：Base64编码
                body = Base64.getEncoder().encodeToString(bodyBytes);
                isBodyBase64 = true;
            } else {
                // 文本内容：直接存储
                body = new String(bodyBytes, StandardCharsets.UTF_8);
                isBodyBase64 = false;
            }
        } else {
            // 没有body，整个数据就是header
            headers = new String(bytes, StandardCharsets.UTF_8);
            body = "";
            isBodyBase64 = false;
        }

        return new HttpMessageParts(headers, body, isBodyBase64);
    }

    /**
     * 查找 \r\n\r\n 分隔符
     */
    private int findHeaderBodySeparator(byte[] bytes) {
        for (int i = 0; i < bytes.length - 3; i++) {
            if (bytes[i] == '\r' && bytes[i+1] == '\n' &&
                    bytes[i+2] == '\r' && bytes[i+3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    /**
     * 从header中提取Content-Type
     */
    private String extractContentType(String headers) {
        String[] lines = headers.split("\r\n");
        for (String line : lines) {
            if (line.toLowerCase().startsWith("content-type:")) {
                return line.substring(13).trim().toLowerCase();
            }
        }
        return "";
    }

    /**
     * 判断是否为二进制Content-Type
     */
    private boolean isBinaryContentType(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return false;
        }

        // 常见二进制类型
        String[] binaryTypes = {
                "image/", "video/", "audio/", "application/octet-stream",
                "application/pdf", "application/zip", "application/x-rar",
                "application/x-gzip", "application/x-compressed",
                "font/", "application/vnd.ms-", "application/x-"
        };

        for (String type : binaryTypes) {
            if (contentType.startsWith(type)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检测字节数组是否为有效UTF-8
     */
    private boolean isValidUtf8(byte[] bytes) {
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            decoder.decode(ByteBuffer.wrap(bytes));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 合并header和body为完整HTTP消息
     */
    private byte[] combineHttpMessage(String headers, String body, boolean isBodyBase64) {
        byte[] headerBytes = headers.getBytes(StandardCharsets.UTF_8);
        byte[] separator = "\r\n\r\n".getBytes(StandardCharsets.UTF_8);

        byte[] bodyBytes;
        if (isBodyBase64) {
            // Base64解码
            bodyBytes = Base64.getDecoder().decode(body);
        } else {
            // 直接UTF-8编码
            bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        }

        byte[] result = new byte[headerBytes.length + separator.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(separator, 0, result, headerBytes.length, separator.length);
        System.arraycopy(bodyBytes, 0, result, headerBytes.length + separator.length, bodyBytes.length);

        return result;
    }

    /**
     * 从filename生成composite_key
     */
    private String generateCompositeKey(String filename) {
        return filename.replace(".lz4", "");
    }

    /**
     * 从filename提取message_id
     */
    private int extractMessageId(String filename) {
        String key = generateCompositeKey(filename);
        String[] parts = key.split("_");

        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                logging.logToError("[RequestResponseSaver] Invalid message_id in filename: " + filename);
                return -1;
            }
        }
        return -1;
    }

    /**
     * 从filename提取data_type
     */
    private String extractDataType(String filename) {
        String key = generateCompositeKey(filename);
        String[] parts = key.split("_");
        return parts.length > 0 ? parts[0] : "Unknown";
    }

    /**
     * 从filename提取timing_data（仅ModResp有）
     */
    private Integer extractTimingData(String filename) {
        String key = generateCompositeKey(filename);

        if (key.startsWith("ModResp")) {
            String[] parts = key.split("_");
            if (parts.length >= 3) {
                try {
                    return Integer.parseInt(parts[2]);
                } catch (NumberFormatException e) {
                    logging.logToError("[RequestResponseSaver] Invalid timing_data in filename: " + filename);
                }
            }
        }
        return null;
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
     * 处理批量写入（使用writeConnection）
     */
    private void processBatch(List<WriteTask> batch) {
        if (batch.isEmpty()) {
            return;
        }

        String sql = "INSERT OR REPLACE INTO http_data (composite_key, message_id, data_type, timing_data, header_data, body_data, is_body_base64) VALUES (?, ?, ?, ?, ?, ?, ?)";

        try {
            // 确保写连接可用
            synchronized (connectionLock) {
                ensureConnectionAlive(writeConnection);
            }

            writeConnection.setAutoCommit(false);

            try (PreparedStatement pstmt = writeConnection.prepareStatement(sql)) {
                for (WriteTask task : batch) {
                    String compositeKey = generateCompositeKey(task.filename);
                    int messageId = extractMessageId(task.filename);
                    String dataType = extractDataType(task.filename);
                    Integer timingData = extractTimingData(task.filename);

                    // 拆分并编码HTTP消息
                    HttpMessageParts parts = splitAndEncodeHttpMessage(task.data, dataType);

                    pstmt.setString(1, compositeKey);
                    pstmt.setInt(2, messageId);
                    pstmt.setString(3, dataType);
                    if (timingData != null) {
                        pstmt.setInt(4, timingData);
                    } else {
                        pstmt.setNull(4, Types.INTEGER);
                    }
                    pstmt.setString(5, parts.headers);
                    pstmt.setString(6, parts.body);
                    pstmt.setInt(7, parts.isBodyBase64 ? 1 : 0);

                    pstmt.addBatch();
                }

                pstmt.executeBatch();
                writeConnection.commit();

                // 标记所有任务完成
                for (WriteTask task : batch) {
                    task.future.complete(null);
                    totalWrites.incrementAndGet();
                    pendingWrites.remove(task.filename.hashCode());
                }

            } catch (SQLException e) {
                writeConnection.rollback();
                writeErrors.addAndGet(batch.size());
                logging.logToError("[RequestResponseSaver] Batch insert failed: " + e.getMessage());

                // 降级为单条插入
                for (WriteTask task : batch) {
                    try {
                        insertSingleRecord(task);
                        task.future.complete(null);
                        totalWrites.incrementAndGet();
                    } catch (Exception ex) {
                        task.future.completeExceptionally(ex);
                        logging.logToError("[RequestResponseSaver] Single insert failed for " + task.filename + ": " + ex.getMessage());
                    } finally {
                        pendingWrites.remove(task.filename.hashCode());
                    }
                }
            }

        } catch (SQLException e) {
            logging.logToError("[RequestResponseSaver] Transaction error: " + e.getMessage());

            // 检测磁盘空间不足
            if (e.getErrorCode() == 13) { // SQLITE_FULL
                logging.logToError("[RequestResponseSaver] CRITICAL: Disk full! Cannot write to database.");
            }

            for (WriteTask task : batch) {
                task.future.completeExceptionally(e);
                pendingWrites.remove(task.filename.hashCode());
            }
        } finally {
            try {
                writeConnection.setAutoCommit(true);
            } catch (SQLException e) {
                logging.logToError("[RequestResponseSaver] Error resetting autocommit: " + e.getMessage());
            }
        }
    }

    /**
     * 单条记录插入（降级方案，使用writeConnection）
     */
    private void insertSingleRecord(WriteTask task) throws SQLException {
        String sql = "INSERT OR REPLACE INTO http_data (composite_key, message_id, data_type, timing_data, header_data, body_data, is_body_base64) VALUES (?, ?, ?, ?, ?, ?, ?)";

        synchronized (connectionLock) {
            ensureConnectionAlive(writeConnection);
        }

        try (PreparedStatement pstmt = writeConnection.prepareStatement(sql)) {
            String compositeKey = generateCompositeKey(task.filename);
            int messageId = extractMessageId(task.filename);
            String dataType = extractDataType(task.filename);
            Integer timingData = extractTimingData(task.filename);

            HttpMessageParts parts = splitAndEncodeHttpMessage(task.data, dataType);

            pstmt.setString(1, compositeKey);
            pstmt.setInt(2, messageId);
            pstmt.setString(3, dataType);
            if (timingData != null) {
                pstmt.setInt(4, timingData);
            } else {
                pstmt.setNull(4, Types.INTEGER);
            }
            pstmt.setString(5, parts.headers);
            pstmt.setString(6, parts.body);
            pstmt.setInt(7, parts.isBodyBase64 ? 1 : 0);

            pstmt.executeUpdate();
        }
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
     * 数据加载方法（使用readConnection）
     */
    public ByteArray loadData(String filename) throws StorageException {
        String compositeKey = generateCompositeKey(filename);

        String sql = "SELECT header_data, body_data, is_body_base64 FROM http_data WHERE composite_key = ?";

        try {
            // 确保读连接可用
            synchronized (connectionLock) {
                ensureConnectionAlive(readConnection);
            }

            try (PreparedStatement pstmt = readConnection.prepareStatement(sql)) {
                pstmt.setString(1, compositeKey);

                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        String headers = rs.getString("header_data");
                        String body = rs.getString("body_data");
                        boolean isBodyBase64 = rs.getInt("is_body_base64") == 1;

                        // 合并HTTP消息
                        byte[] fullMessage = combineHttpMessage(headers, body, isBodyBase64);

                        totalReads.incrementAndGet();
                        return ByteArray.byteArray(fullMessage);
                    }

                    return null; // 数据不存在
                }
            }

        } catch (SQLException e) {
            // 如果读连接出错，尝试重新创建
            try {
                if (!readConnection.isValid(2)) {
                    logging.logToError("[RequestResponseSaver] Read connection invalid, attempting to recreate...");
                    synchronized (connectionLock) {
                        readConnection.close();
                        String dbPath = STORAGE_DIR.resolve("requests.db").toString();
                        readConnection = createConnection(dbPath);
                        logging.logToOutput("[RequestResponseSaver] Read connection recreated");
                    }
                }
            } catch (SQLException reconnectEx) {
                logging.logToError("[RequestResponseSaver] Failed to recreate read connection: " + reconnectEx.getMessage());
            }

            throw new StorageException("[RequestResponseSaver] Failed to load data for key: " + compositeKey, e);
        }
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

                        // 获取 MIME type，处理空值情况
                        String contentType = null;
                        try {
                            if (response.mimeType() != null) {
                                contentType = response.mimeType().toString();
                            }
                        } catch (Exception e) {
                            logging.logToError("[RequestResponseSaver] Failed to get MIME type: " + e.getMessage());
                        }

                        modifiedEntry.setModifiedResponseAndCalculateMetadata(
                                response.statusCode(),
                                responseLength,
                                response.body().length(),
                                detectReflectType(response),
                                responseTime,
                                contentType  // 添加 contentType 参数
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
     * 异步保存修改后的响应
     */
    private CompletableFuture<Void> saveModifiedResponseAsync(HttpResponse response, int id, long timingData) {
        String filename = "ModResp_" + id + "_" + timingData + ".lz4";
        return storeDataAsync(response.toByteArray(), filename);
    }

    /**
     * 保存原始请求
     */
    public void saveOriginalRequest(HttpRequest request, int messageID) {
        if (isShutdown) return;
        storeDataAsync(request.toByteArray(), "OrigReq_" + messageID + ".lz4");
    }

    /**
     * 保存原始响应
     */
    public void saveOriginalResponse(HttpResponse response, int messageID) {
        if (isShutdown) return;
        storeDataAsync(response.toByteArray(), "OrigResp_" + messageID + ".lz4");
    }

    /**
     * 保存修改后的请求
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
            if (response.contains("808544", false) || response.contains("918891889188", false)) {
                detectedTypes.add("SSTI-808544-9188");
            }
            if (response.contains("/bin/sh", false)) {
                detectedTypes.add("LFI");
            }
            if (response.contains("Message too large to display", false)) {
                detectedTypes.add("Large");
            }
            if (response.bodyToString().contains("chaxx123'\">")) {
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
            if (response.contains("Request Header Fields Too Large", false)) {
                detectedTypes.add("431 Header Too Large");
            }
            if (response.contains("URI Too Long", false)) {
                detectedTypes.add("URI Too Long");
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
     * 清理存储（关闭两个连接）
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

        // 优化并关闭数据库连接
        synchronized (connectionLock) {
            // 关闭写连接
            if (writeConnection != null) {
                try (Statement stmt = writeConnection.createStatement()) {
                    stmt.execute("PRAGMA optimize;");
                    logging.logToOutput("[RequestResponseSaver] Database optimized");
                } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error optimizing database: " + e.getMessage());
                }

                try {
                    writeConnection.close();
                    logging.logToOutput("[RequestResponseSaver] Write connection closed");
                } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error closing write connection: " + e.getMessage());
                }
            }

            // 关闭读连接
            if (readConnection != null) {
                try {
                    readConnection.close();
                    logging.logToOutput("[RequestResponseSaver] Read connection closed");
                } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error closing read connection: " + e.getMessage());
                }
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
}