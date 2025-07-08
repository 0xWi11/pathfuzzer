package demo.config;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.regex.Pattern;

public class FilterRule {
    private String value;
    private RuleType type;
    private RuleMatchType matchType;
    private boolean enabled;

    public enum RuleType {
        URL,
        HEADER_NAME,
        HEADER_VALUE,
        HOST,
        BODY_VALUE,
        BODY_PARAM,
        PARAM_NAME,
        PARAM_VALUE,
        IN_SCOPE,
        HTTP_METHOD
    }

    public enum RuleMatchType {
        CONTAINS,
        EQUALS,
        REGEX,
        STARTS_WITH,
        ENDS_WITH
    }

    public enum HttpMethod {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
        OPTIONS,
        PATCH,
        TRACE
    }

    public FilterRule(String value, RuleType type, RuleMatchType matchType) {
        this.value = value;
        this.type = type;
        this.matchType = matchType;
        this.enabled = true;
    }

    public boolean matches(HttpRequest request) {
        if (!enabled || value == null) return false;

        try {
            switch (type) {
                case URL:
                    return matchValue(request.url());
                case HEADER_NAME:
                    return request.headers().stream()
                            .map(HttpHeader::name)
                            .anyMatch(this::matchValue);
                case HEADER_VALUE:
                    return request.headers().stream()
                            .map(HttpHeader::value)
                            .anyMatch(this::matchValue);
                case HOST:
                    return matchValue(request.httpService().host());
                case BODY_VALUE:
                    String body = request.bodyToString();
                    return body != null && matchValue(body);
                case BODY_PARAM:
                    return request.parameters().stream()
                            .filter(p -> p.type().toString().contains("BODY"))
                            .map(HttpParameter::value)
                            .anyMatch(this::matchValue);
                case PARAM_NAME:
                    return request.parameters().stream()
                            .map(HttpParameter::name)
                            .anyMatch(this::matchValue);
                case PARAM_VALUE:
                    return request.parameters().stream()
                            .map(HttpParameter::value)
                            .anyMatch(this::matchValue);
                case IN_SCOPE:
                    return request.isInScope() != Boolean.parseBoolean(value);
                case HTTP_METHOD:
                    String requestMethod = request.method().toUpperCase();
                    return matchValue(requestMethod);
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean matchValue(String input) {
        if (input == null || value == null) return false;

        try {
            switch (matchType) {
                case CONTAINS:
                    return input.contains(value);
                case EQUALS:
                    return input.equals(value);
                case REGEX:
                    // 针对URL类型的特殊处理
                    if (type == RuleType.URL) {
                        // 对于静态资源URL的处理，使用find()进行匹配
                        return Pattern.compile(value, Pattern.CASE_INSENSITIVE).matcher(input).find();
                    }
                    // 非URL类型的正则匹配
                    return Pattern.compile(value).matcher(input).matches();
                case STARTS_WITH:
                    return input.startsWith(value);
                case ENDS_WITH:
                    return input.endsWith(value);
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    // Getters and setters
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    public RuleType getType() { return type; }
    public void setType(RuleType type) { this.type = type; }
    public RuleMatchType getMatchType() { return matchType; }
    public void setMatchType(RuleMatchType matchType) { this.matchType = matchType; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    @Override
    public String toString() {
        return String.format("%s - %s - %s", type, matchType, value);
    }
}