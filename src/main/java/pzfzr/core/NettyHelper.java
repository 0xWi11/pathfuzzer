package pzfzr.core;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CompressionUtils;
import burp.api.montoya.utilities.CompressionType;
import burp.api.montoya.core.ByteArray;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

/**
 * NettyHelper - NettyManager的辅助类
 * 提供响应处理、压缩解压等辅助功能
 */
public class NettyHelper {

    private final Logging logging;
    private final CompressionUtils compressionUtils;
    private final NettyManager nettyManager;

    public NettyHelper(Logging logging, CompressionUtils compressionUtils, NettyManager nettyManager) {
        this.logging = logging;
        this.compressionUtils = compressionUtils;
        this.nettyManager = nettyManager;
    }

    /**
     * 处理响应的压缩/解压缩
     */
    public HttpResponse processResponse(HttpResponse response) {
        if (response == null) {
            return null;
        }

        String contentEncoding = null;
        for (HttpHeader header : response.headers()) {
            if ("Content-Encoding".equalsIgnoreCase(header.name())) {
                contentEncoding = header.value();
                break;
            }
        }

        if (contentEncoding == null || contentEncoding.isEmpty()) {
            return response;
        }

        try {
            // 获取响应体
            byte[] body = response.body().getBytes();
            if (body.length == 0) {
                return response;
            }

            // 根据编码类型解压
            byte[] decompressedBody = decompressBody(body, contentEncoding);

            if (decompressedBody != null && decompressedBody != body) {
                // 重建响应
                return rebuildResponse(response, decompressedBody);
            }

        } catch (Exception e) {
            logging.logToError("[NettyHelper] Failed to process response: " + e.getMessage());
        }

        return response;
    }

    /**
     * 解压响应体
     */
    private byte[] decompressBody(byte[] compressedData, String contentEncoding) {
        try {
            CompressionType type = null;

            if ("gzip".equalsIgnoreCase(contentEncoding)) {
                type = CompressionType.GZIP;
            } else if ("deflate".equalsIgnoreCase(contentEncoding)) {
                type = CompressionType.DEFLATE;
            } else if ("br".equalsIgnoreCase(contentEncoding)) {
                type = CompressionType.BROTLI;
            } else {
                return compressedData;
            }

            ByteArray compressed = ByteArray.byteArray(compressedData);
            ByteArray decompressed = compressionUtils.decompress(compressed, type);
            return decompressed.getBytes();

        } catch (Exception e) {
            logging.logToError("[NettyHelper] Decompression failed: " + e.getMessage());
            return compressedData;
        }
    }

    /**
     * 重建响应（移除Content-Encoding，更新Content-Length）
     */
    private HttpResponse rebuildResponse(HttpResponse original, byte[] newBody) {
        StringBuilder responseBuilder = new StringBuilder();

        // 添加状态行
        String firstLine = original.toString().split("\r\n")[0];
        responseBuilder.append(firstLine).append("\r\n");

        // 处理headers
        boolean hasContentLength = false;
        for (HttpHeader header : original.headers()) {
            String name = header.name();
            String value = header.value();

            // 跳过Content-Encoding
            if ("Content-Encoding".equalsIgnoreCase(name)) {
                continue;
            }

            // 更新Content-Length
            if ("Content-Length".equalsIgnoreCase(name)) {
                value = String.valueOf(newBody.length);
                hasContentLength = true;
            }

            responseBuilder.append(name).append(": ").append(value).append("\r\n");
        }

        // 确保有Content-Length
        if (!hasContentLength) {
            responseBuilder.append("Content-Length: ").append(newBody.length).append("\r\n");
        }

        responseBuilder.append("\r\n");

        // 合并header和body
        byte[] headerBytes = responseBuilder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] fullResponse = new byte[headerBytes.length + newBody.length];
        System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
        System.arraycopy(newBody, 0, fullResponse, headerBytes.length, newBody.length);

        return HttpResponse.httpResponse(ByteArray.byteArray(fullResponse));
    }

    /**
     * 创建简单的回调适配器
     */
    public static class SimpleCallback implements NettyManager.ResponseCallback {
        private final CompletableFuture<HttpResponse> future;
        private final Logging logging;

        public SimpleCallback(CompletableFuture<HttpResponse> future, Logging logging) {
            this.future = future;
            this.logging = logging;
        }

        @Override
        public void onResponse(HttpResponse response, long responseTimeMs) {
            future.complete(response);
        }

        @Override
        public void onError(Throwable error) {
            logging.logToError("[NettyHelper] Request failed: " + error.getMessage());
            future.completeExceptionally(error);
        }
    }
}

