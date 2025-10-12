package pzfzr.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * ParamCollector - 参数收集器
 * 用于收集和管理 HTTP 请求/响应中的所有参数
 */
public class ParamCollector {
    private static final Path BASE_DIR = Paths.get(System.getProperty("user.home"), ".burp", "path_fuzzer");
    private static final Path COLLECTED_PARAM_DIR = BASE_DIR.resolve("collected_param");
    private static final int MAX_VALUE_LENGTH = 200;

    private final Logging logging;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // 参数存储：key -> ParamEntry
    private final ConcurrentHashMap<String, ParamEntry> paramMap = new ConcurrentHashMap<>();

    // 读写锁
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    // 文件路径
    private Path currentFile;

    // 线程池
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    /**
     * 参数条目
     */
    public static class ParamEntry {
        private final String url;
        private final String position;
        private final String type;
        private final String key;
        private String value;

        public ParamEntry(String url, String position, String type, String key, String value) {
            this.url = url;
            this.position = position;
            this.type = type;
            this.key = key;
            this.value = value;
        }

        public String getUrl() { return url; }
        public String getPosition() { return position; }
        public String getType() { return type; }
        public String getKey() { return key; }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }

        /**
         * 转换为存储格式：url,position,type,key=value
         * 对value进行转义，将特殊字符转换为可见标记
         */
        public String toStorageFormat() {
            String escapedValue = escapeSpecialChars(value);
            String escapedUrl = escapeSpecialChars(url);
            return String.format("%s,%s,%s,%s=%s", escapedUrl, position, type, key, escapedValue);
        }

        /**
         * 从存储格式解析
         * 对value进行反转义，将标记还原为原始字符
         */
        public static ParamEntry fromStorageFormat(String line) throws IllegalArgumentException {
            if (line == null || line.trim().isEmpty()) {
                throw new IllegalArgumentException("Empty line");
            }

            // 解析格式：url,position,type,key=value
            int firstComma = line.indexOf(',');
            int secondComma = line.indexOf(',', firstComma + 1);
            int thirdComma = line.indexOf(',', secondComma + 1);
            int equalSign = line.indexOf('=', thirdComma + 1);

            if (firstComma == -1 || secondComma == -1 || thirdComma == -1 || equalSign == -1) {
                throw new IllegalArgumentException("Invalid format: " + line);
            }

            String escapedUrl = line.substring(0, firstComma);
            String position = line.substring(firstComma + 1, secondComma);
            String type = line.substring(secondComma + 1, thirdComma);
            String key = line.substring(thirdComma + 1, equalSign);
            String escapedValue = line.substring(equalSign + 1);

            // 反转义url和value
            String url = unescapeSpecialChars(escapedUrl);
            String value = unescapeSpecialChars(escapedValue);

            return new ParamEntry(url, position, type, key, value);
        }

        /**
         * 转义特殊字符为可见标记
         */
        private static String escapeSpecialChars(String input) {
            if (input == null) {
                return "";
            }
            return input
                    .replace("\r\n", "[EOL]")  // Windows换行
                    .replace("\n", "[EOL]")     // Unix换行
                    .replace("\r", "[EOL]")     // Mac换行
                    .replace("\t", "[TAB]")     // 制表符
                    .replace(",", "[COMMA]");   // 逗号（新增，避免与分隔符冲突）
        }

        /**
         * 反转义：将标记还原为原始字符
         */
        private static String unescapeSpecialChars(String input) {
            if (input == null) {
                return "";
            }
            return input
                    .replace("[EOL]", "\n")     // 统一还原为\n
                    .replace("[TAB]", "\t")     // 还原制表符
                    .replace("[COMMA]", ",");   // 还原逗号
        }
    }

    public ParamCollector(Logging logging) {
        this.logging = logging;
        initializeFile();
        initializeDefaultParams();
    }

    /**
     * 初始化文件
     */
    private void initializeFile() {
        try {
            Files.createDirectories(COLLECTED_PARAM_DIR);

            String dateStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
            String hash = generateRandomHash(6);
            String filename = dateStr + "-" + hash + ".txt";

            currentFile = COLLECTED_PARAM_DIR.resolve(filename);

            if (!Files.exists(currentFile)) {
                Files.createFile(currentFile);
            }

            logging.logToOutput("[ParamCollector] Initialized file: " + currentFile);
        } catch (IOException e) {
            logging.logToError("[ParamCollector] Failed to initialize file: " + e.getMessage());
        }
    }

    /**
     * 初始化默认参数
     */
    private void initializeDefaultParams() {
        lock.writeLock().lock();
        try {
            // 默认参数定义
            Map<String, String> defaults = new LinkedHashMap<>();
            defaults.put("size", "88");
            defaults.put("page", "1");
            defaults.put("currentPage", "1");
            defaults.put("pageSize", "88");
            defaults.put("limit", "null");

            for (Map.Entry<String, String> entry : defaults.entrySet()) {
                // 固定 url=default, position=post-json, type=number
                ParamEntry param = new ParamEntry("default", "post-json", "number", entry.getKey(), entry.getValue());
                paramMap.put(entry.getKey(), param);
            }

            // 写入文件保存
            writeToFile();
//            logging.logToOutput("[ParamCollector] Initialized with default params: " + defaults.keySet());
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 生成随机哈希
     */
    private String generateRandomHash(int length) {
        String chars = "0123456789abcdefABCDEF";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * 异步收集参数（从右键菜单传入的请求列表）
     */
    public CompletableFuture<Void> collectParamsAsync(List<HttpRequestResponse> requestResponses) {
        return CompletableFuture.runAsync(() -> {
            int total = requestResponses.size();
            AtomicInteger processed = new AtomicInteger(0);
            int lastProgress = 0;

            logging.logToOutput(String.format("[ParamCollector] Starting collection for %d requests", total));

            for (HttpRequestResponse reqRes : requestResponses) {
                try {
                    // 获取 URL
                    String url = "";
                    try {
                        url = reqRes.request().url();
                    } catch (Exception e) {
                        logging.logToError("[ParamCollector] Failed to get URL: " + e.getMessage());
                    }

                    if (reqRes.request() != null) {
                        collectFromRequest(reqRes.request(), url);
                    }
                    if (reqRes.hasResponse() && reqRes.response() != null) {
                        collectFromResponse(reqRes.response(), url);
                    }
                } catch (Exception e) {
                    logging.logToError("[ParamCollector] Error collecting from request: " + e.getMessage());
                }

                int current = processed.incrementAndGet();
                int currentProgress = (current * 100) / total;

                // 每10%打印一次进度
                if (currentProgress >= lastProgress + 10) {
                    lastProgress = (currentProgress / 10) * 10;
                    logging.logToOutput(String.format("[ParamCollector] Progress: %d%%", lastProgress));
                }
            }

            logging.logToOutput(String.format("[ParamCollector] Collection completed. Total params: %d", paramMap.size()));

            // 收集完成后写入文件
            writeToFile();

        }, executor);
    }

    /**
     * 从请求中收集参数
     */
    private void collectFromRequest(HttpRequest request, String url) {
        // 收集 GET 参数
        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.URL) {
                String type = isNumeric(param.value()) ? "number" : "string";
                addParam(url, "get", type, param.name(), param.value());
            }
        }

        // 收集 COOKIE 参数
        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) {
                addParam(url, "cookie", "string", param.name(), param.value());
            }
        }

        // 收集 POST 参数
        String contentType = request.headerValue("Content-Type");
        if (contentType != null) {
            if (contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
                for (HttpParameter param : request.parameters()) {
                    if (param.type() == HttpParameterType.BODY) {
                        String type = isNumeric(param.value()) ? "number" : "string";
                        addParam(url, "post", type, param.name(), param.value());
                    }
                }
            } else if (contentType.toLowerCase().contains("application/json")) {
                // 收集 JSON 参数
                try {
                    String body = request.bodyToString();
                    if (body != null && !body.trim().isEmpty()) {
                        JsonNode rootNode = objectMapper.readTree(body);
                        collectFromJsonNode(rootNode, "post-json", url);
                    }
                } catch (Exception e) {
                    logging.logToError("[ParamCollector] JSON parse error in request: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 从响应中收集参数
     */
    private void collectFromResponse(HttpResponse response, String url) {
        String contentType = response.headerValue("Content-Type");
        if (contentType != null && contentType.toLowerCase().contains("application/json")) {
            try {
                String body = response.bodyToString();
                if (body != null && !body.trim().isEmpty()) {
                    JsonNode rootNode = objectMapper.readTree(body);
                    collectFromJsonNode(rootNode, "resp-json", url);
                }
            } catch (Exception e) {
                logging.logToError("[ParamCollector] JSON parse error in response: " + e.getMessage());
            }
        }
    }

    /**
     * 从 JSON 节点递归收集参数
     */
    private void collectFromJsonNode(JsonNode node, String position, String url) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String key = field.getKey();
                JsonNode value = field.getValue();

                if (value.isObject() || value.isArray()) {
                    // 递归处理嵌套结构
                    collectFromJsonNode(value, position, url);
                } else {
                    // 叶子节点，收集参数
                    collectLeafNode(key, value, position, url);
                }
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                collectFromJsonNode(element, position, url);
            }
        }
    }

    /**
     * 收集叶子节点
     */
    private void collectLeafNode(String key, JsonNode value, String position, String url) {
        String type;
        String valueStr;

        if (value.isNumber()) {
            type = "number";
            valueStr = value.asText();
        } else if (value.isBoolean()) {
            type = "boolean";
            valueStr = String.valueOf(value.asBoolean());
        } else if (value.isNull()) {
            type = "null";
            valueStr = "null";
        } else {
            type = "string";
            valueStr = value.asText();
        }

        addParam(url, position, type, key, valueStr);
    }

    /**
     * 添加参数（线程安全）
     */
    private void addParam(String url, String position, String type, String key, String value) {
        // 如果参数名包含小数点，则跳过
        if (key != null && key.contains(".")) {
            return;
        }

        // 检查值长度
        if (value != null && value.length() > MAX_VALUE_LENGTH) {
            return;
        }

        // 处理空字符串
        if (value == null) {
            value = "";
        }

        // 处理空URL
        if (url == null) {
            url = "";
        }

        lock.writeLock().lock();
        try {
            ParamEntry entry = new ParamEntry(url, position, type, key, value);
            paramMap.put(key, entry); // 如果key已存在，会被覆盖（保留最新值）
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 判断字符串是否为数字
     */
    private boolean isNumeric(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        try {
            Double.parseDouble(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 写入文件
     */
    public void writeToFile() {
        lock.readLock().lock();
        try {
            List<String> lines = paramMap.values().stream()
                    .map(ParamEntry::toStorageFormat)
                    .sorted()
                    .collect(Collectors.toList());

            Files.write(currentFile, lines, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            logging.logToOutput(String.format("[ParamCollector] Wrote %d params to file", lines.size()));
        } catch (IOException e) {
            logging.logToError("[ParamCollector] Failed to write file: " + e.getMessage());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 从文件加载
     */
    public void loadFromFile() {
        if (!Files.exists(currentFile)) {
            return;
        }

        lock.writeLock().lock();
        try {
            List<String> lines = Files.readAllLines(currentFile, StandardCharsets.UTF_8);
            paramMap.clear();

            for (String line : lines) {
                try {
                    ParamEntry entry = ParamEntry.fromStorageFormat(line);
                    paramMap.put(entry.getKey(), entry);
                } catch (IllegalArgumentException e) {
                    logging.logToError("[ParamCollector] Invalid line format: " + line);
                }
            }

            logging.logToOutput(String.format("[ParamCollector] Loaded %d params from file", paramMap.size()));
        } catch (IOException e) {
            logging.logToError("[ParamCollector] Failed to load file: " + e.getMessage());
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 获取所有参数（用于UI显示）
     */
    public String getAllParamsAsText() {
        lock.readLock().lock();
        try {
            return paramMap.values().stream()
                    .map(ParamEntry::toStorageFormat)
                    .sorted()
                    .collect(Collectors.joining("\n"));
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 从文本更新参数（用于UI更新）
     * @return 错误信息，如果没有错误返回null
     */
    public String updateFromText(String text) {
        if (text == null || text.trim().isEmpty()) {
            lock.writeLock().lock();
            try {
                paramMap.clear();
                writeToFile();
                return null;
            } finally {
                lock.writeLock().unlock();
            }
        }

        String[] lines = text.split("\n");
        Map<String, ParamEntry> newMap = new HashMap<>();

        // 验证所有行
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }

            try {
                ParamEntry entry = ParamEntry.fromStorageFormat(line);
                newMap.put(entry.getKey(), entry);
            } catch (IllegalArgumentException e) {
                return String.format("Error at line %d: %s\n%s", i + 1, e.getMessage(), line);
            }
        }

        // 验证通过，更新数据
        lock.writeLock().lock();
        try {
            paramMap.clear();
            paramMap.putAll(newMap);
            writeToFile();
            return null;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 获取参数数量
     */
    public int getParamCount() {
        return paramMap.size();
    }

    /**
     * 获取所有参数的只读副本
     */
    public Map<String, ParamEntry> getAllParams() {
        lock.readLock().lock();
        try {
            return new HashMap<>(paramMap);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 关闭资源
     */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // 最后写入一次
        writeToFile();
        logging.logToOutput("[ParamCollector] Shutdown completed");
    }
}