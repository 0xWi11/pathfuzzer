package pzfzr.config;

public class SwitchState {
    private final boolean masterSwitch;
    private final boolean jsonlisterSwitch;
    private final boolean routefuzzerSwitch;
    private final boolean paramfuzzerSwitch;
    private final boolean paramdeleterSwitch;
    private final boolean paramadderSwitch; // 新增：ParamAdder开关状态
    private final boolean headerfuzzerSwitch;
    private final boolean cookiefuzzerSwitch;
    private final boolean oobparamfuzzerSwitch;

    public SwitchState(boolean masterSwitch, boolean jsonlisterSwitch,
                       boolean routefuzzerSwitch, boolean paramfuzzerSwitch,
                       boolean paramdeleterSwitch, boolean paramadderSwitch, // 新增参数
                       boolean headerfuzzerSwitch, boolean cookiefuzzerSwitch,
                       boolean oobparamfuzzerSwitch) {
        this.masterSwitch = masterSwitch;
        this.jsonlisterSwitch = jsonlisterSwitch;
        this.routefuzzerSwitch = routefuzzerSwitch;
        this.paramfuzzerSwitch = paramfuzzerSwitch;
        this.paramdeleterSwitch = paramdeleterSwitch;
        this.paramadderSwitch = paramadderSwitch; // 新增
        this.headerfuzzerSwitch = headerfuzzerSwitch;
        this.cookiefuzzerSwitch = cookiefuzzerSwitch;
        this.oobparamfuzzerSwitch = oobparamfuzzerSwitch;
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

    // 新增：ParamAdder的getter方法
    public boolean isParamadderSwitch() {
        return paramadderSwitch;
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