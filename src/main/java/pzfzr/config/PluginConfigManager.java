package pzfzr.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * 插件配置管理器，加载Maven编译时注入的配置
 */
public class PluginConfigManager {
    private static PluginConfigManager instance;
    private final Properties properties;

    private PluginConfigManager() {
        properties = new Properties();
        loadConfig();
    }

    public static synchronized PluginConfigManager getInstance() {
        if (instance == null) {
            instance = new PluginConfigManager();
        }
        return instance;
    }

    private void loadConfig() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("plugin-config.properties")) {
            if (is != null) {
                properties.load(is);
            }
        } catch (IOException e) {
            // 使用默认配置
            setDefaultConfig();
        }
    }

    private void setDefaultConfig() {
        // 设置默认值（PathFuzzer配置）
        properties.setProperty("plugin.name", "PathFuzzer");
        properties.setProperty("plugin.package.prefix", "pzfzr");
        properties.setProperty("netty.port", "20808");
        properties.setProperty("context.menu.name", "PathFuzzer");
        properties.setProperty("switch.jsonlister.enabled", "true");
        properties.setProperty("switch.routefuzzer.enabled", "true");
        properties.setProperty("switch.paramfuzzer.enabled", "true");
        properties.setProperty("switch.paramdeleter.enabled", "true");
        properties.setProperty("switch.paramadder.enabled", "true"); // 新增：ParamAdder默认启用
        properties.setProperty("switch.headerfuzzer.enabled", "false");
        properties.setProperty("switch.cookiefuzzer.enabled", "false");
        properties.setProperty("switch.oobparamfuzzer.enabled", "false");
    }

    // 基本配置获取方法
    public String getPluginName() {
        return properties.getProperty("plugin.name", "PathFuzzer");
    }

    public String getPackagePrefix() {
        return properties.getProperty("plugin.package.prefix", "pzfzr");
    }

    public int getNettyPort() {
        return Integer.parseInt(properties.getProperty("netty.port", "20808"));
    }

    public String getContextMenuName() {
        return properties.getProperty("context.menu.name", "PathFuzzer");
    }

    // 开关配置获取方法
    public boolean isJsonListerEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.jsonlister.enabled", "true"));
    }

    public boolean isRouteFuzzerEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.routefuzzer.enabled", "true"));
    }

    public boolean isParamFuzzerEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.paramfuzzer.enabled", "true"));
    }

    public boolean isParamDeleterEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.paramdeleter.enabled", "true"));
    }

    // 新增：ParamAdder配置获取方法
    public boolean isParamAdderEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.paramadder.enabled", "true"));
    }

    public boolean isHeaderFuzzerEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.headerfuzzer.enabled", "false"));
    }

    public boolean isCookieFuzzerEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.cookiefuzzer.enabled", "false"));
    }

    public boolean isOOBParamFuzzerEnabled() {
        return Boolean.parseBoolean(properties.getProperty("switch.oobparamfuzzer.enabled", "false"));
    }

    // 获取所有开关状态的便捷方法
    public SwitchConfigState getSwitchConfigState() {
        return new SwitchConfigState(
                isJsonListerEnabled(),
                isRouteFuzzerEnabled(),
                isParamFuzzerEnabled(),
                isParamDeleterEnabled(),
                isParamAdderEnabled(), // 新增
                isHeaderFuzzerEnabled(),
                isCookieFuzzerEnabled(),
                isOOBParamFuzzerEnabled()
        );
    }

    /**
     * 开关配置状态类
     */
    public static class SwitchConfigState {
        private final boolean jsonListerEnabled;
        private final boolean routeFuzzerEnabled;
        private final boolean paramFuzzerEnabled;
        private final boolean paramDeleterEnabled;
        private final boolean paramAdderEnabled; // 新增
        private final boolean headerFuzzerEnabled;
        private final boolean cookieFuzzerEnabled;
        private final boolean oobParamFuzzerEnabled;

        public SwitchConfigState(boolean jsonListerEnabled, boolean routeFuzzerEnabled,
                                 boolean paramFuzzerEnabled, boolean paramDeleterEnabled,
                                 boolean paramAdderEnabled, // 新增参数
                                 boolean headerFuzzerEnabled, boolean cookieFuzzerEnabled,
                                 boolean oobParamFuzzerEnabled) {
            this.jsonListerEnabled = jsonListerEnabled;
            this.routeFuzzerEnabled = routeFuzzerEnabled;
            this.paramFuzzerEnabled = paramFuzzerEnabled;
            this.paramDeleterEnabled = paramDeleterEnabled;
            this.paramAdderEnabled = paramAdderEnabled; // 新增
            this.headerFuzzerEnabled = headerFuzzerEnabled;
            this.cookieFuzzerEnabled = cookieFuzzerEnabled;
            this.oobParamFuzzerEnabled = oobParamFuzzerEnabled;
        }

        // Getters
        public boolean isJsonListerEnabled() { return jsonListerEnabled; }
        public boolean isRouteFuzzerEnabled() { return routeFuzzerEnabled; }
        public boolean isParamFuzzerEnabled() { return paramFuzzerEnabled; }
        public boolean isParamDeleterEnabled() { return paramDeleterEnabled; }
        public boolean isParamAdderEnabled() { return paramAdderEnabled; } // 新增
        public boolean isHeaderFuzzerEnabled() { return headerFuzzerEnabled; }
        public boolean isCookieFuzzerEnabled() { return cookieFuzzerEnabled; }
        public boolean isOOBParamFuzzerEnabled() { return oobParamFuzzerEnabled; }
    }
}