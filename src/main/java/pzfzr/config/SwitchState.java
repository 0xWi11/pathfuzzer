package pzfzr.config;

public class SwitchState {
    private final boolean masterSwitch;
    private final boolean jsonlisterSwitch;
    private final boolean routefuzzerSwitch;
    private final boolean paramfuzzerSwitch;
    private final boolean knownSwitch;  // 新增


    public SwitchState(boolean masterSwitch, boolean jsonlisterSwitch,
                       boolean routefuzzerSwitch, boolean paramfuzzerSwitch,
                       boolean knownSwitch) {  // 新增参数
        this.masterSwitch = masterSwitch;
        this.jsonlisterSwitch = jsonlisterSwitch;
        this.routefuzzerSwitch = routefuzzerSwitch;
        this.paramfuzzerSwitch = paramfuzzerSwitch;
        this.knownSwitch = knownSwitch;  // 新增
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
    public boolean isKnownSwitch() {
        return knownSwitch;
    }
}