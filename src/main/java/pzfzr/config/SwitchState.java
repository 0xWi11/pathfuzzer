package pzfzr.config;

public class SwitchState {
    private final boolean masterSwitch;
    private final boolean jsonlisterSwitch;
    private final boolean routefuzzerSwitch;
    private final boolean paramfuzzerSwitch;
    private final boolean paramdeleterSwitch;
    private final boolean headerfuzzerSwitch; // 新增

    public SwitchState(boolean masterSwitch, boolean jsonlisterSwitch,
                       boolean routefuzzerSwitch, boolean paramfuzzerSwitch,
                       boolean paramdeleterSwitch, boolean headerfuzzerSwitch) { // 新增参数
        this.masterSwitch = masterSwitch;
        this.jsonlisterSwitch = jsonlisterSwitch;
        this.routefuzzerSwitch = routefuzzerSwitch;
        this.paramfuzzerSwitch = paramfuzzerSwitch;
        this.paramdeleterSwitch = paramdeleterSwitch;
        this.headerfuzzerSwitch = headerfuzzerSwitch; // 新增
    }

    public boolean isMasterSwitch() {
        return masterSwitch;
    }

    public boolean isJsonlisterSwitch() {
        return jsonlisterSwitch;
    }

    public boolean isRoutefuzzerSwitch() {
        return routefuzzerSwitch;
    }

    public boolean isParamfuzzerSwitch() {
        return paramfuzzerSwitch;
    }

    public boolean isParamdeleterSwitch() {
        return paramdeleterSwitch;
    }

    // 新增：HeaderFuzzer的getter方法
    public boolean isHeaderfuzzerSwitch() {
        return headerfuzzerSwitch;
    }
}