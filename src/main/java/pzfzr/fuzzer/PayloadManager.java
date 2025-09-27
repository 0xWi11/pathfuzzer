package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * PayloadManager 管理 ParamFuzzer、RouteFuzzer 和 HeaderFuzzer 的载荷启用/禁用状态
 */
public class PayloadManager {
    private static PayloadManager instance;
    private final List<PayloadInfo> paramPayloads;
    private final List<PayloadInfo> routePayloads;
    private final List<PayloadInfo> headerPayloads;
    private final List<PayloadChangeListener> listeners;

    private PayloadManager() {
        this.paramPayloads = new CopyOnWriteArrayList<>();
        this.routePayloads = new CopyOnWriteArrayList<>();
        this.headerPayloads = new CopyOnWriteArrayList<>();
        this.listeners = new ArrayList<>();
        initializePayloads();
    }

    public static synchronized PayloadManager getInstance() {
        if (instance == null) {
            instance = new PayloadManager();
        }
        return instance;
    }

    private void initializePayloads() {
        // 从 PayloadConstants 初始化参数载荷
        for (PayloadConstants.PayloadInfo oldPayload : PayloadConstants.PARAM_PAYLOAD_INFOS) {
            paramPayloads.add(new PayloadInfo(oldPayload.payload, oldPayload.alias, true));
        }

        // 从 PayloadConstants 初始化路由载荷
        for (PayloadConstants.PayloadInfo oldPayload : PayloadConstants.ROUTE_PAYLOAD_INFOS) {
            routePayloads.add(new PayloadInfo(oldPayload.payload, oldPayload.alias, true));
        }

        // 从 PayloadConstants 初始化头部载荷
        for (PayloadConstants.PayloadInfo oldPayload : PayloadConstants.HEADER_PAYLOAD_INFOS) {
            headerPayloads.add(new PayloadInfo(oldPayload.payload, oldPayload.alias, true));
        }
    }

    // 参数载荷相关方法
    public List<PayloadInfo> getParamPayloads() {
        return new ArrayList<>(paramPayloads);
    }

    public List<PayloadInfo> getEnabledParamPayloads() {
        return paramPayloads.stream()
                .filter(PayloadInfo::isEnabled)
                .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    public void setParamPayloadEnabled(int index, boolean enabled) {
        if (index >= 0 && index < paramPayloads.size()) {
            paramPayloads.get(index).setEnabled(enabled);
            notifyListeners(PayloadType.PARAM);
        }
    }

    public void setAllParamPayloadsEnabled(boolean enabled) {
        paramPayloads.forEach(payload -> payload.setEnabled(enabled));
        notifyListeners(PayloadType.PARAM);
    }

    // 路由载荷相关方法
    public List<PayloadInfo> getRoutePayloads() {
        return new ArrayList<>(routePayloads);
    }

    public List<PayloadInfo> getEnabledRoutePayloads() {
        return routePayloads.stream()
                .filter(PayloadInfo::isEnabled)
                .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    public void setRoutePayloadEnabled(int index, boolean enabled) {
        if (index >= 0 && index < routePayloads.size()) {
            routePayloads.get(index).setEnabled(enabled);
            notifyListeners(PayloadType.ROUTE);
        }
    }

    public void setAllRoutePayloadsEnabled(boolean enabled) {
        routePayloads.forEach(payload -> payload.setEnabled(enabled));
        notifyListeners(PayloadType.ROUTE);
    }

    // 头部载荷相关方法
    public List<PayloadInfo> getHeaderPayloads() {
        return new ArrayList<>(headerPayloads);
    }

    public List<PayloadInfo> getEnabledHeaderPayloads() {
        return headerPayloads.stream()
                .filter(PayloadInfo::isEnabled)
                .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    public void setHeaderPayloadEnabled(int index, boolean enabled) {
        if (index >= 0 && index < headerPayloads.size()) {
            headerPayloads.get(index).setEnabled(enabled);
            notifyListeners(PayloadType.HEADER);
        }
    }

    public void setAllHeaderPayloadsEnabled(boolean enabled) {
        headerPayloads.forEach(payload -> payload.setEnabled(enabled));
        notifyListeners(PayloadType.HEADER);
    }

    // 监听器管理
    public void addListener(PayloadChangeListener listener) {
        listeners.add(listener);
    }

    public void removeListener(PayloadChangeListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners(PayloadType type) {
        for (PayloadChangeListener listener : listeners) {
            listener.onPayloadChanged(type);
        }
    }

    // 枚举和接口
    public enum PayloadType {
        PARAM, ROUTE, HEADER
    }

    public interface PayloadChangeListener {
        void onPayloadChanged(PayloadType type);
    }
}