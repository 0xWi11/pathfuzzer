package pzfzr.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * NettyAdapter.java - 用于从OkHttp迁移到Netty的适配器
 * 提供同步和异步接口，方便过渡
 */
public class NettyAdapter {

    private final NettyManager nettyManager;
    private final NettyHelper helper;
    private final Logging logging;

    public NettyAdapter(NettyManager nettyManager, NettyHelper helper, Logging logging) {
        this.nettyManager = nettyManager;
        this.helper = helper;
        this.logging = logging;
    }

    /**
     * 发送请求并返回响应（同步接口，内部异步实现）
     */
    public HttpResponse sendRequest(HttpRequest request) throws Exception {
        CompletableFuture<HttpResponse> future = new CompletableFuture<>();

        nettyManager.sendRequest(request, new NettyManager.ResponseCallback() {
            @Override
            public void onResponse(HttpResponse response, long responseTimeMs) {
                // 处理响应（解压等）
                HttpResponse processed = helper.processResponse(response);
                future.complete(processed);
            }

            @Override
            public void onError(Throwable error) {
                future.completeExceptionally(error);
            }
        });

        // 等待结果（最多120秒）
        return future.get(120, TimeUnit.SECONDS);
    }

    /**
     * 异步发送请求
     */
    public CompletableFuture<HttpResponse> sendRequestAsync(HttpRequest request) {
        CompletableFuture<HttpResponse> future = new CompletableFuture<>();

        nettyManager.sendRequest(request, new NettyManager.ResponseCallback() {
            @Override
            public void onResponse(HttpResponse response, long responseTimeMs) {
                HttpResponse processed = helper.processResponse(response);
                future.complete(processed);
            }

            @Override
            public void onError(Throwable error) {
                future.completeExceptionally(error);
            }
        });

        return future;
    }

    /**
     * 发送请求并获取响应时间
     */
    public CompletableFuture<ResponseWithTime> sendRequestWithTiming(HttpRequest request) {
        CompletableFuture<ResponseWithTime> future = new CompletableFuture<>();

        nettyManager.sendRequest(request, new NettyManager.ResponseCallback() {
            @Override
            public void onResponse(HttpResponse response, long responseTimeMs) {
                HttpResponse processed = helper.processResponse(response);
                future.complete(new ResponseWithTime(processed, responseTimeMs));
            }

            @Override
            public void onError(Throwable error) {
                future.completeExceptionally(error);
            }
        });

        return future;
    }

    /**
     * 响应和时间的封装类
     */
    public static class ResponseWithTime {
        public final HttpResponse response;
        public final long responseTimeMs;

        public ResponseWithTime(HttpResponse response, long responseTimeMs) {
            this.response = response;
            this.responseTimeMs = responseTimeMs;
        }
    }
}