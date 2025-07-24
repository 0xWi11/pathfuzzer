package pzfzr.fuzzer;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * PayloadManager manages the enable/disable state of payloads for both ParamFuzzer and RouteFuzzer
 */
public class PayloadManager {
    private static PayloadManager instance;
    private final List<PayloadInfo> paramPayloads;
    private final List<PayloadInfo> routePayloads;
    private final List<PayloadChangeListener> listeners;

    private PayloadManager() {
        this.paramPayloads = new CopyOnWriteArrayList<>();
        this.routePayloads = new CopyOnWriteArrayList<>();
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
        // Initialize param payloads from PayloadConstants
        for (PayloadConstants.PayloadInfo oldPayload : PayloadConstants.PARAM_PAYLOAD_INFOS) {
            paramPayloads.add(new PayloadInfo(oldPayload.payload, oldPayload.alias, true));
        }

        // Initialize route payloads from PayloadConstants
        for (PayloadConstants.PayloadInfo oldPayload : PayloadConstants.ROUTE_PAYLOAD_INFOS) {
            routePayloads.add(new PayloadInfo(oldPayload.payload, oldPayload.alias, true));
        }
    }

    // Param payload methods
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

    // Route payload methods
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

    // Listener management
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

    // Enums and interfaces
    public enum PayloadType {
        PARAM, ROUTE
    }

    public interface PayloadChangeListener {
        void onPayloadChanged(PayloadType type);
    }
}