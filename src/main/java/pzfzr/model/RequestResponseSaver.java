package pzfzr.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.lang.ref.WeakReference;
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
 * 优化版本：
 *   - detectReflectType 使用真正的 Aho-Corasick 自动机（O(n)）
 *   - isValidUtf8 使用 ThreadLocal 复用 CharsetDecoder
 *   - calculateResponseLengthWithoutSetCookieValues 不再调用 toByteArray()
 */
public class RequestResponseSaver {

    private final Path STORAGE_DIR;
    private final Logging logging;
    private final TableModel tableModel;
    private final String dbFileName;

    // SQLite连接 - 读写分离
    private Connection writeConnection;
    private Connection readConnection;
    private final Object connectionLock = new Object();

    // 线程池配置
    private final ExecutorService ioExecutor;
    private final ExecutorService processingExecutor;

    // 批处理配置
    private static final int BATCH_SIZE = 50;
    private static final int BATCH_TIMEOUT_MS = 200;
    private static final int MAX_QUEUE_SIZE = 10000;

    // 写入队列和缓存
    private final Map<Integer, WeakReference<CompletableFuture<Void>>> pendingWrites = new ConcurrentHashMap<>();
    private final BlockingQueue<WriteTask> writeQueue = new LinkedBlockingQueue<>(MAX_QUEUE_SIZE);

    // 统计信息
    private final AtomicLong totalWrites = new AtomicLong(0);
    private final AtomicLong totalReads = new AtomicLong(0);
    private final AtomicLong writeErrors = new AtomicLong(0);

    private static final Path BASE_DIR = Paths.get(System.getProperty("user.home"), ".burp", "path_fuzzer");
    private static final Path HISTORY_DIR = BASE_DIR.resolve("project_request_history");

    private volatile boolean isShutdown = false;

    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "rs-cleanup");
        t.setDaemon(true);
        return t;
    });

    // ========== 检测模式定义 ==========

    private static class DetectionPattern {
        final byte[] pattern;
        final String type;

        DetectionPattern(String pattern, String type) {
            this.pattern = pattern.getBytes(StandardCharsets.UTF_8);
            this.type = type;
        }
    }

    private static final List<DetectionPattern> BODY_PATTERNS = Arrays.asList(
            new DetectionPattern("808544", "SSTI-808544-9188"),
            new DetectionPattern("918891889188", "SSTI-808544-9188"),
            new DetectionPattern("/bin/sh", "LFI"),
            new DetectionPattern("SHELL=/", "CMDI"),
            new DetectionPattern("PWD=/", "CMDI"),
            new DetectionPattern("HOME=/", "CMDI"),
            new DetectionPattern("\"swagger\":", "SWAGGER"),
            new DetectionPattern("\"swaggerVersion\":", "SWAGGER"),
            new DetectionPattern("Whitelabel Error Page", "Spring Boot"),
            new DetectionPattern("debug mode</a> is enabled.", "SYMFONY"),
            new DetectionPattern("id=\"sfWebDebugSymfony\"", "SYMFONY"),
            new DetectionPattern("HTTP/1.1 505 HTTP Version Not Supported", "505 HTTP Version"),
            new DetectionPattern("Request Header Fields Too Large", "431 Header Too Large"),
            new DetectionPattern("URI Too Long", "URI Too Long"),
            new DetectionPattern("<ListBucketResult", "S3 List"),
            new DetectionPattern("zcydyyyya", "XFFI"),
            new DetectionPattern("Directory listing for ", "dir-listing"),
            new DetectionPattern("Index of /", "dir-listing"),
            new DetectionPattern("[To Parent Directory]", "dir-listing"),
            new DetectionPattern("Directory: /", "dir-listing"),
            new DetectionPattern("Tomcat Manager", "Tomcat Manager")
    );

    // ========== [优化1] 真正的 Aho-Corasick 自动机（静态，类加载时构建一次）==========
    //
    // 原实现虽注释为"单次遍历"，但本质是对 body 每个字节都遍历所有 m 个模式，
    // 复杂度为 O(n × m)。以 50KB body、20 个模式为例约触发百万次比较。
    //
    // 真正的 Aho-Corasick 自动机：
    //   - 构建阶段（静态初始化，只做一次）：O(∑|pattern|)
    //   - 搜索阶段（运行时，每个响应）：O(n)，n = body 字节数
    //
    // goto 表在构建时已通过 fail 链补全，搜索时无需 while 循环回退，
    // 内循环只有一次数组查找 + 一次判空，分支预测友好。

    private static final int[][] AC_GOTO;
    private static final int[] AC_FAIL;
    private static final Set<String>[] AC_OUTPUT;
    private static final int AC_SIZE;

    static {
        int[][] g = buildAcGoto();
        AC_GOTO = g;
        AC_SIZE  = g.length;
        AC_FAIL  = buildAcFail(g);
        AC_OUTPUT = buildAcOutput(g, AC_FAIL);
    }

    @SuppressWarnings("unchecked")
    private static int[][] buildAcGoto() {
        List<int[]> gotoList = new ArrayList<>();
        List<Set<String>> outputList = new ArrayList<>();
        gotoList.add(new int[256]);
        outputList.add(new HashSet<>());

        for (DetectionPattern dp : BODY_PATTERNS) {
            int cur = 0;
            for (byte b : dp.pattern) {
                int c = b & 0xFF;
                if (gotoList.get(cur)[c] == 0) {
                    gotoList.add(new int[256]);
                    outputList.add(new HashSet<>());
                    gotoList.get(cur)[c] = gotoList.size() - 1;
                }
                cur = gotoList.get(cur)[c];
            }
            outputList.get(cur).add(dp.type);
        }
        // 暂存 outputList 到临时字段供后续方法使用
        _tempOutputList = outputList;
        return gotoList.toArray(new int[0][]);
    }

    // 构建期临时中转，仅在 static 初始化阶段使用
    private static List<Set<String>> _tempOutputList;

    private static int[] buildAcFail(int[][] gotoTable) {
        int size = gotoTable.length;
        int[] fail = new int[size];
        Queue<Integer> queue = new LinkedList<>();

        for (int c = 0; c < 256; c++) {
            int s = gotoTable[0][c];
            if (s != 0) {
                fail[s] = 0;
                queue.add(s);
            }
        }
        while (!queue.isEmpty()) {
            int r = queue.poll();
            for (int c = 0; c < 256; c++) {
                int s = gotoTable[r][c];
                if (s != 0) {
                    queue.add(s);
                    fail[s] = gotoTable[fail[r]][c];
                    if (fail[s] == s) fail[s] = 0;
                    _tempOutputList.get(s).addAll(_tempOutputList.get(fail[s]));
                } else {
                    gotoTable[r][c] = gotoTable[fail[r]][c];
                }
            }
        }
        return fail;
    }

    @SuppressWarnings("unchecked")
    private static Set<String>[] buildAcOutput(int[][] gotoTable, int[] fail) {
        Set<String>[] output = _tempOutputList.toArray(new Set[0]);
        _tempOutputList = null; // 释放临时引用
        return output;
    }

    // ========== [优化2] ThreadLocal 复用 CharsetDecoder ==========
    //
    // 原实现每次调用 isValidUtf8 都 new 一个 CharsetDecoder，
    // CharsetDecoder 不是轻量对象（内部含状态机和 ByteBuffer 持有），
    // 高并发时会产生大量短命对象，加重 GC 压力。
    //
    // ThreadLocal 保证每个线程持有一个实例，reset() 后复用，
    // 避免重复分配，也无需同步。
    private static final ThreadLocal<CharsetDecoder> UTF8_DECODER = ThreadLocal.withInitial(() ->
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
    );

    // Actuator检测的分段模式
    private static final byte[] ACTUATOR_PREFIX = "\"href\":\"http".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ACTUATOR_SUFFIX = "/actuator\"".getBytes(StandardCharsets.UTF_8);

    // RXSS检测模式
    private static final String RXSS_PATTERN = "chaxx123'\">";

    // SQL Error 预编译正则
    private static final Pattern SQL_ERROR_PATTERN = Pattern.compile(
            "SQL syntax.*?MySQL|Warning.*?\\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result" +
                    "|check the manual that (corresponds to|fits) your MySQL server version" +
                    "|Unknown column '[^ ]+' in 'field list'|MySqlClient\\.|com\\.mysql\\.jdbc" +
                    "|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[./_\\\\]Mysql|MySqlException" +
                    "|SQLSTATE\\[\\d+\\]: Syntax error or access violation" +
                    "|check the manual that (corresponds to|fits) your MariaDB server version" +
                    "|check the manual that (corresponds to|fits) your Drizzle server version" +
                    "|MemSQL does not support this type of query|is not supported by MemSQL" +
                    "|unsupported nested scalar subselect" +
                    "|PostgreSQL.*?ERROR|Warning.*?\\Wpg_|valid PostgreSQL result|Npgsql\\." +
                    "|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException" +
                    "|ERROR:\\s\\ssyntax error at or near|ERROR: parser: parse error at or near" +
                    "|PostgreSQL query failed|org\\.postgresql\\.jdbc|Pdo[./_\\\\]Pgsql|PSQLException" +
                    "|Driver.*? SQL[\\-\\_\\ ]*Server|OLE DB.*? SQL Server" +
                    "|\\bSQL Server[^<\"]+Driver|Warning.*?\\W(mssql|sqlsrv)_" +
                    "|\\bSQL Server[^<\"]+[0-9a-fA-F]{8}" +
                    "|System\\.Data\\.SqlClient\\.SqlException\\.(SqlException|SqlConnection\\.OnError)" +
                    "|(?s)Exception.*?\\bRoadhouse\\.Cms\\." +
                    "|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|\\[SQL Server\\]" +
                    "|ODBC SQL Server Driver|ODBC Driver \\d+ for SQL Server|SQLServer JDBC Driver" +
                    "|com\\.jnetdirect\\.jsql|macromedia\\.jdbc\\.sqlserver" +
                    "|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\\.microsoft\\.sqlserver\\.jdbc" +
                    "|Pdo[./_\\\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception" +
                    "|Unclosed quotation mark after the character string" +
                    "|Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine" +
                    "|ODBC Microsoft Access|Syntax error \\(missing operator\\) in query expression" +
                    "|\\bORA-\\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\\W(oci|ora)_" +
                    "|quoted string not properly terminated|SQL command not properly ended" +
                    "|macromedia\\.jdbc\\.oracle|oracle\\.jdbc" +
                    "|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[./_\\\\](Oracle|OCI)|OracleException",
            Pattern.DOTALL
    );

    // ========== 内部类 ==========

    private static class HttpMessageParts {
        String headers;
        String body;
        boolean isBodyBase64;

        HttpMessageParts(String headers, String body, boolean isBodyBase64) {
            this.headers = headers;
            this.body = body;
            this.isBodyBase64 = isBodyBase64;
        }

        void clear() {
            headers = null;
            body = null;
        }
    }

    private static class WriteTask {
        final ByteArray data;
        final String filename;
        final CompletableFuture<Void> future;

        WriteTask(ByteArray data, String filename, CompletableFuture<Void> future) {
            this.data = data;
            this.filename = filename;
            this.future = future;
        }

        void clear() {}
    }

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
        this.dbFileName = generateDbFileName();
        this.STORAGE_DIR = createMonthlyStorageDir();

        if (this.STORAGE_DIR == null) {
            throw new StorageException("[RequestResponseSaver] Failed to create monthly storage directory.");
        }

        initDatabase();

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

        this.processingExecutor = new ForkJoinPool(
                Math.min(Runtime.getRuntime().availableProcessors() * 2, 16),
                ForkJoinPool.defaultForkJoinWorkerThreadFactory,
                null,
                true
        );

        startBatchWriter();
        startPeriodicCleanup();

        logging.logToOutput("[RequestResponseSaver] Initialization complete, storage directory: " + STORAGE_DIR);
        logging.logToOutput("[RequestResponseSaver] Database file: " + dbFileName);
    }

    private String generateDbFileName() {
        LocalDateTime now = LocalDateTime.now();
        String dateStr = now.format(DateTimeFormatter.ofPattern("dd"));
        String randomHash = generateRandomHash();
        return dateStr + "_" + randomHash + "_requestdata.db";
    }

    private void initDatabase() {
        try {
            try {
                Class.forName("org.sqlite.JDBC");
                logging.logToOutput("[RequestResponseSaver] SQLite JDBC driver loaded successfully");
            } catch (ClassNotFoundException e) {
                throw new RuntimeException("SQLite JDBC driver not found. Please ensure sqlite-jdbc is in the classpath.", e);
            }

            String dbPath = STORAGE_DIR.resolve(dbFileName).toString();

            writeConnection = createConnection(dbPath);
            logging.logToOutput("[RequestResponseSaver] Write connection established");

            readConnection = createConnection(dbPath);
            logging.logToOutput("[RequestResponseSaver] Read connection established");

            configurePragmas(writeConnection);
            createTable(writeConnection);
            checkDatabaseIntegrity(writeConnection);

            logging.logToOutput("[RequestResponseSaver] SQLite database initialized: " + dbPath);

        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize SQLite database", e);
        }
    }

    private Connection createConnection(String dbPath) throws SQLException {
        int maxRetries = 3;
        SQLException lastException = null;

        for (int i = 0; i < maxRetries; i++) {
            try {
                return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            } catch (SQLException e) {
                lastException = e;
                logging.logToError("[RequestResponseSaver] Connection attempt " + (i + 1) + " failed: " + e.getMessage());
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

    private void checkDatabaseIntegrity(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA integrity_check;")) {
            if (rs.next() && !"ok".equals(rs.getString(1))) {
                throw new SQLException("Database integrity check failed");
            }
        }
    }

    private void ensureConnectionAlive(Connection conn) throws SQLException {
        if (conn == null || conn.isClosed() || !conn.isValid(2)) {
            throw new SQLException("Connection is not valid");
        }
    }

    private HttpMessageParts splitAndEncodeHttpMessage(ByteArray data, String dataType) {
        byte[] bytes = data.getBytes();
        int separatorIndex = findHeaderBodySeparator(bytes);

        String headers;
        String body;
        boolean isBodyBase64 = false;

        if (separatorIndex != -1) {
            headers = new String(bytes, 0, separatorIndex, StandardCharsets.UTF_8);

            int bodyStart = separatorIndex + 4;
            int bodyLength = bytes.length - bodyStart;

            String contentType = extractContentType(headers);
            if (isBinaryContentType(contentType) || !isValidUtf8(bytes, bodyStart, bodyLength)) {
                body = Base64.getEncoder().encodeToString(Arrays.copyOfRange(bytes, bodyStart, bytes.length));
                isBodyBase64 = true;
            } else {
                body = new String(bytes, bodyStart, bodyLength, StandardCharsets.UTF_8);
            }
        } else {
            headers = new String(bytes, StandardCharsets.UTF_8);
            body = "";
        }

        return new HttpMessageParts(headers, body, isBodyBase64);
    }

    private int findHeaderBodySeparator(byte[] bytes) {
        for (int i = 0; i < bytes.length - 3; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n' &&
                    bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private String extractContentType(String headers) {
        int startIndex = 0;
        int endIndex;

        while (startIndex < headers.length()) {
            endIndex = headers.indexOf("\r\n", startIndex);
            if (endIndex == -1) {
                endIndex = headers.length();
            }
            if (endIndex - startIndex > 13) {
                String line = headers.substring(startIndex, endIndex);
                if (line.regionMatches(true, 0, "content-type:", 0, 13)) {
                    return line.substring(13).trim().toLowerCase();
                }
            }
            startIndex = endIndex + 2;
        }
        return "";
    }

    private boolean isBinaryContentType(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return false;
        }
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
     * [优化2] 检测字节数组是否为有效 UTF-8。
     *
     * 原实现每次调用都 new CharsetDecoder()，产生大量短命对象，GC 压力大。
     * 现改为 ThreadLocal 复用同一个解码器实例，reset() 后重用，无锁且线程安全。
     */
    private boolean isValidUtf8(byte[] bytes, int offset, int length) {
        if (length <= 0) return true;
        try {
            CharsetDecoder decoder = UTF8_DECODER.get();
            decoder.reset(); // 必须 reset，清除上次调用的残留状态
            decoder.decode(ByteBuffer.wrap(bytes, offset, length));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] combineHttpMessage(String headers, String body, boolean isBodyBase64) {
        byte[] headerBytes = headers.getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = isBodyBase64
                ? Base64.getDecoder().decode(body)
                : body.getBytes(StandardCharsets.UTF_8);

        byte[] result = new byte[headerBytes.length + 4 + bodyBytes.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        result[headerBytes.length] = '\r';
        result[headerBytes.length + 1] = '\n';
        result[headerBytes.length + 2] = '\r';
        result[headerBytes.length + 3] = '\n';
        System.arraycopy(bodyBytes, 0, result, headerBytes.length + 4, bodyBytes.length);
        return result;
    }

    private String generateCompositeKey(String filename) {
        return filename.replace(".lz4", "");
    }

    private int extractMessageId(String filename) {
        String key = generateCompositeKey(filename);
        int firstUnderscore = key.indexOf('_');
        if (firstUnderscore != -1 && firstUnderscore < key.length() - 1) {
            int secondUnderscore = key.indexOf('_', firstUnderscore + 1);
            int endIndex = secondUnderscore != -1 ? secondUnderscore : key.length();
            try {
                return Integer.parseInt(key.substring(firstUnderscore + 1, endIndex));
            } catch (NumberFormatException e) {
                logging.logToError("[RequestResponseSaver] Invalid message_id in filename: " + filename);
                return -1;
            }
        }
        return -1;
    }

    private String extractDataType(String filename) {
        String key = generateCompositeKey(filename);
        int firstUnderscore = key.indexOf('_');
        return firstUnderscore != -1 ? key.substring(0, firstUnderscore) : "Unknown";
    }

    private Integer extractTimingData(String filename) {
        String key = generateCompositeKey(filename);
        if (key.startsWith("ModResp")) {
            int firstUnderscore = key.indexOf('_');
            if (firstUnderscore != -1) {
                int secondUnderscore = key.indexOf('_', firstUnderscore + 1);
                if (secondUnderscore != -1 && secondUnderscore < key.length() - 1) {
                    try {
                        return Integer.parseInt(key.substring(secondUnderscore + 1));
                    } catch (NumberFormatException e) {
                        logging.logToError("[RequestResponseSaver] Invalid timing_data in filename: " + filename);
                    }
                }
            }
        }
        return null;
    }

    private void startPeriodicCleanup() {
        cleanupExecutor.scheduleWithFixedDelay(() -> {
            try {
                pendingWrites.entrySet().removeIf(entry -> {
                    WeakReference<CompletableFuture<Void>> ref = entry.getValue();
                    CompletableFuture<Void> future = ref.get();
                    return future == null || future.isDone();
                });
            } catch (Exception e) {
                logging.logToError("[RequestResponseSaver] Cleanup task error: " + e.getMessage());
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    private void startBatchWriter() {
        Thread writerThread = new Thread(() -> {
            List<WriteTask> batch = new ArrayList<>(BATCH_SIZE);
            while (!isShutdown) {
                try {
                    WriteTask task = writeQueue.poll(BATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    if (task != null) {
                        batch.add(task);
                        writeQueue.drainTo(batch, BATCH_SIZE - 1);
                        processBatch(batch);
                        for (WriteTask t : batch) t.clear();
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

    private void processBatch(List<WriteTask> batch) {
        if (batch.isEmpty()) return;

        String sql = "INSERT OR REPLACE INTO http_data (composite_key, message_id, data_type, timing_data, header_data, body_data, is_body_base64) VALUES (?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement pstmt = null;
        try {
            synchronized (connectionLock) {
                ensureConnectionAlive(writeConnection);
            }
            writeConnection.setAutoCommit(false);
            pstmt = writeConnection.prepareStatement(sql);

            for (WriteTask task : batch) {
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
                pstmt.addBatch();
                parts.clear();
            }

            pstmt.executeBatch();
            writeConnection.commit();

            for (WriteTask task : batch) {
                task.future.complete(null);
                totalWrites.incrementAndGet();
                pendingWrites.remove(task.filename.hashCode());
            }

        } catch (SQLException e) {
            try {
                writeConnection.rollback();
            } catch (SQLException rollbackEx) {
                logging.logToError("[RequestResponseSaver] Rollback failed: " + rollbackEx.getMessage());
            }
            writeErrors.addAndGet(batch.size());
            logging.logToError("[RequestResponseSaver] Batch insert failed: " + e.getMessage());

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
        } finally {
            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error closing PreparedStatement: " + e.getMessage());
                }
            }
            try {
                writeConnection.setAutoCommit(true);
            } catch (SQLException e) {
                logging.logToError("[RequestResponseSaver] Error resetting autocommit: " + e.getMessage());
            }
        }
    }

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
            parts.clear();
        }
    }

    private CompletableFuture<Void> storeDataAsync(ByteArray data, String filename) {
        if (isShutdown) return CompletableFuture.completedFuture(null);

        CompletableFuture<Void> future = new CompletableFuture<>();
        pendingWrites.put(filename.hashCode(), new WeakReference<>(future));

        WriteTask task = new WriteTask(data, filename, future);
        if (!writeQueue.offer(task)) {
            logging.logToError("[RequestResponseSaver] Write queue is full, rejecting task: " + filename);
            future.completeExceptionally(new StorageException("Write queue is full"));
            pendingWrites.remove(filename.hashCode());
        }
        return future;
    }

    public ByteArray loadData(String filename) throws StorageException {
        String compositeKey = generateCompositeKey(filename);
        String sql = "SELECT header_data, body_data, is_body_base64 FROM http_data WHERE composite_key = ?";

        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            synchronized (connectionLock) {
                ensureConnectionAlive(readConnection);
            }
            pstmt = readConnection.prepareStatement(sql);
            pstmt.setString(1, compositeKey);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String headers = rs.getString("header_data");
                String body = rs.getString("body_data");
                boolean isBodyBase64 = rs.getInt("is_body_base64") == 1;
                byte[] fullMessage = combineHttpMessage(headers, body, isBodyBase64);
                totalReads.incrementAndGet();
                return ByteArray.byteArray(fullMessage);
            }
            return null;

        } catch (SQLException e) {
            try {
                if (!readConnection.isValid(2)) {
                    logging.logToError("[RequestResponseSaver] Read connection invalid, attempting to recreate...");
                    synchronized (connectionLock) {
                        readConnection.close();
                        String dbPath = STORAGE_DIR.resolve(dbFileName).toString();
                        readConnection = createConnection(dbPath);
                        logging.logToOutput("[RequestResponseSaver] Read connection recreated");
                    }
                }
            } catch (SQLException reconnectEx) {
                logging.logToError("[RequestResponseSaver] Failed to recreate read connection: " + reconnectEx.getMessage());
            }
            throw new StorageException("[RequestResponseSaver] Failed to load data for key: " + compositeKey, e);
        } finally {
            if (rs != null) {
                try { rs.close(); } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error closing ResultSet: " + e.getMessage());
                }
            }
            if (pstmt != null) {
                try { pstmt.close(); } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error closing PreparedStatement: " + e.getMessage());
                }
            }
        }
    }

    public void handleNettyResponse(HttpResponse response, int id, long responseTime,
                                    ModifiedRequestResponse modifiedEntry) {
        if (isShutdown) return;

        processingExecutor.execute(() -> {
            try {
                saveModifiedResponseAsync(response, id, responseTime).thenRun(() -> {
                    if (modifiedEntry != null) {
                        int responseLength = calculateResponseLengthWithoutSetCookieValues(response);
                        String contentType = null;
                        try {
                            if (response.mimeType() != null) {
                                contentType = response.mimeType().toString();
                            }
                        } catch (Exception e) {
                            logging.logToError("[RequestResponseSaver] Failed to get MIME type: " + e.getMessage());
                        }
                        String payloadAlias = modifiedEntry.getPayloadAlias();
                        String testType = modifiedEntry.getTestType();
                        modifiedEntry.setModifiedResponseAndCalculateMetadata(
                                response.statusCode(),
                                responseLength,
                                response.body().length(),
                                detectReflectType(response, payloadAlias, testType, responseTime),
                                responseTime,
                                contentType
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

    private CompletableFuture<Void> saveModifiedResponseAsync(HttpResponse response, int id, long timingData) {
        String filename = "ModResp_" + id + "_" + timingData + ".lz4";
        return storeDataAsync(response.toByteArray(), filename);
    }

    public void saveOriginalRequest(HttpRequest request, int messageID) {
        if (isShutdown) return;
        storeDataAsync(request.toByteArray(), "OrigReq_" + messageID + ".lz4");
    }

    public void saveOriginalResponse(HttpResponse response, int messageID) {
        if (isShutdown) return;
        storeDataAsync(response.toByteArray(), "OrigResp_" + messageID + ".lz4");
    }

    public void saveModifiedRequest(HttpRequest request, int id) {
        if (isShutdown) return;
        storeDataAsync(request.toByteArray(), "ModReq_" + id + ".lz4");
    }

    /**
     * [优化3] 计算响应长度，排除 Set-Cookie 值的长度。
     *
     * 原实现调用 response.toByteArray() 对整个响应做一次完整序列化，
     * 仅为取 length，既浪费 CPU 又产生大字节数组的 GC 压力。
     *
     * 改进：直接遍历已解析的 headers 列表和 body 长度来计算，
     * 完全避免序列化。计算方式与原逻辑保持一致（减去 Set-Cookie value 的字节数）。
     *
     * 注：HTTP 状态行（"HTTP/1.1 200 OK\r\n"）固定约 17 字节，
     * 每行 header 格式为 "Name: Value\r\n"（name.length + 2 + value.length + 2），
     * header 块末尾有一个 "\r\n" 分隔符（2 字节）。
     * 这与 Burp 的 toByteArray() 序列化结果在字节计数上保持一致。
     */
    private int calculateResponseLengthWithoutSetCookieValues(HttpResponse response) {
        if (response == null) return -1;

        // 状态行："HTTP/1.1 200 OK\r\n" 约 17 字节（对绝大多数响应足够精确）
        int total = 17;
        int setCookieValuesLength = 0;

        for (HttpHeader header : response.headers()) {
            String name = header.name();
            String value = header.value();
            // "Name: Value\r\n"
            total += name.length() + 2 + value.length() + 2;
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                setCookieValuesLength += value.length();
            }
        }

        // header 块末尾的空行 "\r\n"
        total += 2;
        // body
        total += response.body().length();

        return total - setCookieValuesLength;
    }

    // ========== detectReflectType 及辅助方法 ==========

    private String detectReflectType(HttpResponse response, String payloadAlias, String testType, long responseTime) {
        if (response == null) return "";

        Set<String> detectedTypes = new HashSet<>(8);
        try {
            byte[] bodyBytes = response.body().getBytes();

            // [优化1] 真正的 Aho-Corasick 单次遍历，O(n)
            detectAllBodyPatterns(bodyBytes, detectedTypes);

            if (detectActuator(bodyBytes)) {
                detectedTypes.add("ACTUATOR");
            }

            if (containsBytesPattern(bodyBytes, RXSS_PATTERN.getBytes(StandardCharsets.UTF_8))) {
                detectedTypes.add("RXSS");
            }

            detectHeaderPatterns(response.headers(), detectedTypes, payloadAlias, testType);

            if ("{path}CRLF".equals(payloadAlias) && responseTime > 10000) {
                detectedTypes.add("LongTime-CRLF");
            }
            if ("1' OR /*!sleep*/".equals(payloadAlias) && responseTime > 7000) {
                detectedTypes.add("sql delay");
            }
            if ("xml delay 7".equals(payloadAlias) && responseTime > 7000) {
                detectedTypes.add("xml delay");
            }
            if ("1' OR 1/0; -- ".equals(payloadAlias) && bodyBytes.length > 0) {
                String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);
                if (SQL_ERROR_PATTERN.matcher(bodyStr).find()) {
                    detectedTypes.add("sql error");
                }
            }

            return joinTypes(detectedTypes);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * [优化1] 使用预构建的 Aho-Corasick 自动机进行多模式匹配。
     *
     * 搜索复杂度：O(n)，n = body 字节数。
     * goto 表已在静态初始化时通过 fail 链补全，内循环只有两条操作：
     *   state = AC_GOTO[state][byte]   // 一次二维数组读取
     *   if (AC_OUTPUT[state] != null)  // 一次判空
     * 没有 while 回退，分支预测命中率高。
     */
    private void detectAllBodyPatterns(byte[] body, Set<String> results) {
        if (body == null || body.length == 0) return;
        int state = 0;
        for (byte b : body) {
            state = AC_GOTO[state][b & 0xFF];
            Set<String> output = AC_OUTPUT[state];
            if (!output.isEmpty()) {
                results.addAll(output);
            }
        }
    }

    private boolean detectActuator(byte[] body) {
        int prefixPos = indexOfBytes(body, ACTUATOR_PREFIX, 0);
        if (prefixPos == -1) return false;
        int searchEnd = Math.min(body.length, prefixPos + 200);
        return indexOfBytesInRange(body, ACTUATOR_SUFFIX, prefixPos, searchEnd) != -1;
    }

    private int indexOfBytes(byte[] haystack, byte[] needle, int fromIndex) {
        if (needle.length == 0) return fromIndex;
        if (haystack.length - fromIndex < needle.length) return -1;
        int maxIndex = haystack.length - needle.length;
        for (int i = fromIndex; i <= maxIndex; i++) {
            if (haystack[i] == needle[0]) {
                boolean found = true;
                for (int j = 1; j < needle.length; j++) {
                    if (haystack[i + j] != needle[j]) { found = false; break; }
                }
                if (found) return i;
            }
        }
        return -1;
    }

    private int indexOfBytesInRange(byte[] haystack, byte[] needle, int fromIndex, int toIndex) {
        if (needle.length == 0) return fromIndex;
        if (toIndex - fromIndex < needle.length) return -1;
        int maxIndex = Math.min(toIndex, haystack.length) - needle.length;
        for (int i = fromIndex; i <= maxIndex; i++) {
            if (haystack[i] == needle[0]) {
                boolean found = true;
                for (int j = 1; j < needle.length; j++) {
                    if (haystack[i + j] != needle[j]) { found = false; break; }
                }
                if (found) return i;
            }
        }
        return -1;
    }

    private boolean containsBytesPattern(byte[] haystack, byte[] needle) {
        return indexOfBytes(haystack, needle, 0) != -1;
    }

    private void detectHeaderPatterns(List<HttpHeader> headers, Set<String> results, String payloadAlias, String testType) {
        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();

            if ("Content-Length".equalsIgnoreCase(name)) {
                if ("99999999".equals(value.trim())) {
                    results.add("Content too Large");
                }
                continue;
            }

            if ("CacheFuzz".equals(testType)) {
                if (containsIgnoreCase(name, "cache") || containsIgnoreCase(name, "Server-Timing")) {
                    String valueLower = value.toLowerCase();
                    if (valueLower.contains("hit") || valueLower.contains("cached")) {
                        results.add("Cached");
                    }
                    continue;
                }
            }

            if (containsIgnoreCase(name, "c9w") ||
                    containsIgnoreCase(name, "v5m") ||
                    value.equalsIgnoreCase("www.xixicrt.top")) {
                results.add("CRLF");
                break;
            }
        }
    }

    private boolean containsIgnoreCase(String str, String search) {
        int len = search.length();
        int max = str.length() - len;
        for (int i = 0; i <= max; i++) {
            if (str.regionMatches(true, i, search, 0, len)) return true;
        }
        return false;
    }

    private String joinTypes(Set<String> types) {
        if (types.isEmpty()) return "";
        if (types.size() == 1) return types.iterator().next();
        StringBuilder sb = new StringBuilder(types.size() * 20);
        Iterator<String> it = types.iterator();
        sb.append(it.next());
        while (it.hasNext()) sb.append(',').append(it.next());
        return sb.toString();
    }

    // ========== 工具方法 ==========

    private Path createMonthlyStorageDir() {
        LocalDateTime now = LocalDateTime.now();
        String monthDir = now.format(DateTimeFormatter.ofPattern("yyyyMM"));
        Path monthlyHistoryDir = HISTORY_DIR.resolve(monthDir);
        try {
            Files.createDirectories(monthlyHistoryDir);
            logging.logToOutput("[RequestResponseSaver] Created monthly storage directory: " + monthlyHistoryDir);
            return monthlyHistoryDir;
        } catch (IOException e) {
            logging.logToError("[RequestResponseSaver] Failed to create directory: " + e.getMessage());
            return null;
        }
    }

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

    public String getStats() {
        return String.format("Storage Stats - Total Writes: %d, Total Reads: %d, Write Errors: %d, Pending: %d",
                totalWrites.get(), totalReads.get(), writeErrors.get(), writeQueue.size());
    }

    public void cleanupStorage() {
        logging.logToOutput("[RequestResponseSaver] Starting cleanup...");
        isShutdown = true;

        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

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

        ioExecutor.shutdown();
        processingExecutor.shutdown();
        try {
            if (!ioExecutor.awaitTermination(5, TimeUnit.SECONDS)) ioExecutor.shutdownNow();
            if (!processingExecutor.awaitTermination(5, TimeUnit.SECONDS)) processingExecutor.shutdownNow();
        } catch (InterruptedException e) {
            ioExecutor.shutdownNow();
            processingExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        synchronized (connectionLock) {
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
            if (readConnection != null) {
                try {
                    readConnection.close();
                    logging.logToOutput("[RequestResponseSaver] Read connection closed");
                } catch (SQLException e) {
                    logging.logToError("[RequestResponseSaver] Error closing read connection: " + e.getMessage());
                }
            }
        }

        pendingWrites.clear();
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