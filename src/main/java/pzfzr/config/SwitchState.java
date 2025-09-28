package pzfzr.config;

public class SwitchState {
    private final boolean masterSwitch;
    private final boolean jsonlisterSwitch;
    private final boolean routefuzzerSwitch;
    private final boolean paramfuzzerSwitch;
    private final boolean paramdeleterSwitch;
    private final boolean headerfuzzerSwitch;
    private final boolean cookiefuzzerSwitch;
    private final boolean oobparamfuzzerSwitch; // 新增：OOBParamFuzzer开关状态

    public SwitchState(boolean masterSwitch, boolean jsonlisterSwitch,
                       boolean routefuzzerSwitch, boolean paramfuzzerSwitch,
                       boolean paramdeleterSwitch, boolean headerfuzzerSwitch,
                       boolean cookiefuzzerSwitch, boolean oobparamfuzzerSwitch) { // 新增参数
        this.masterSwitch = masterSwitch;
        this.jsonlisterSwitch = jsonlisterSwitch;
        this.routefuzzerSwitch = routefuzzerSwitch;
        this.paramfuzzerSwitch = paramfuzzerSwitch;
        this.paramdeleterSwitch = paramdeleterSwitch;
        this.headerfuzzerSwitch = headerfuzzerSwitch;
        this.cookiefuzzerSwitch = cookiefuzzerSwitch;
        this.oobparamfuzzerSwitch = oobparamfuzzerSwitch; // 新增
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

    public boolean isHeaderfuzzerSwitch() {
        return headerfuzzerSwitch;
    }

    public boolean isCookiefuzzerSwitch() {
        return cookiefuzzerSwitch;
    }

    // 新增：OOBParamFuzzer的getter方法
    public boolean isOobparamfuzzerSwitch() {
        return oobparamfuzzerSwitch;
    }
}