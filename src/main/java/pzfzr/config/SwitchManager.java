package pzfzr.config;

public class SwitchManager {
    private boolean masterSwitch;
    private boolean jsonListerSwitch;
    private boolean routefuzzerSwitch;
    private boolean paramfuzzerSwitch;
    private boolean paramdeleterSwitch;
    private boolean headerfuzzerSwitch; // 新增

    // 单例模式
    private static SwitchManager instance;

    private SwitchManager() {
        // 默认值设置
        this.masterSwitch = true;
        this.jsonListerSwitch = false;
        this.routefuzzerSwitch = false;
        this.paramfuzzerSwitch = false;
        this.paramdeleterSwitch = false;
        this.headerfuzzerSwitch = false; // 新增，默认关闭
    }

    public static synchronized SwitchManager getInstance() {
        if (instance == null) {
            instance = new SwitchManager();
        }
        return instance;
    }

    // Getters and setters
    public boolean isMasterSwitch() {
        return masterSwitch;
    }

    public void setMasterSwitch(boolean masterSwitch) {
        this.masterSwitch = masterSwitch;
    }

    public boolean isJsonListerSwitch() {
        return jsonListerSwitch;
    }

    public void setJsonListerSwitch(boolean jsonListerSwitch) {
        this.jsonListerSwitch = jsonListerSwitch;
    }

    public boolean isRoutefuzzerSwitch() {
        return routefuzzerSwitch;
    }

    public void setRoutefuzzerSwitch(boolean routefuzzerSwitch) {
        this.routefuzzerSwitch = routefuzzerSwitch;
    }

    public boolean isParamfuzzerSwitch() {
        return paramfuzzerSwitch;
    }

    public void setParamfuzzerSwitch(boolean paramfuzzerSwitch) {
        this.paramfuzzerSwitch = paramfuzzerSwitch;
    }

    public boolean isParamdeleterSwitch() {
        return paramdeleterSwitch;
    }

    public void setParamdeleterSwitch(boolean paramdeleterSwitch) {
        this.paramdeleterSwitch = paramdeleterSwitch;
    }

    // 新增：HeaderFuzzer相关方法
    public boolean isHeaderfuzzerSwitch() {
        return headerfuzzerSwitch;
    }

    public void setHeaderfuzzerSwitch(boolean headerfuzzerSwitch) {
        this.headerfuzzerSwitch = headerfuzzerSwitch;
    }

    // 获取当前所有开关状态
    public SwitchState getCurrentState() {
        return new SwitchState(
                masterSwitch,
                jsonListerSwitch,
                routefuzzerSwitch,
                paramfuzzerSwitch,
                paramdeleterSwitch,
                headerfuzzerSwitch // 新增
        );
    }
}