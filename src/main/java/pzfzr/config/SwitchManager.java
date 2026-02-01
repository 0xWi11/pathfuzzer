package pzfzr.config;

public class SwitchManager {
    private boolean masterSwitch;
    private boolean jsonListerSwitch;
    private boolean routefuzzerSwitch;
    private boolean paramfuzzerSwitch;
    private boolean paramdeleterSwitch;
    private boolean paramadderSwitch; // 新增：ParamAdder开关
    private boolean headerfuzzerSwitch;
    private boolean cookiefuzzerSwitch;
    private boolean oobparamfuzzerSwitch;
    private boolean cachefuzzerSwitch;

    private static SwitchManager instance;

    private SwitchManager() {
        this.masterSwitch = true;
        this.jsonListerSwitch = false;
        this.routefuzzerSwitch = false;
        this.paramfuzzerSwitch = false;
        this.paramdeleterSwitch = false;
        this.paramadderSwitch = false; // 新增，默认关闭
        this.headerfuzzerSwitch = false;
        this.cookiefuzzerSwitch = false;
        this.oobparamfuzzerSwitch = false;
        this.cachefuzzerSwitch = false; // 默认关闭
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

    // 新增：ParamAdder相关方法
    public boolean isParamadderSwitch() {
        return paramadderSwitch;
    }

    public void setParamadderSwitch(boolean paramadderSwitch) {
        this.paramadderSwitch = paramadderSwitch;
    }

    public boolean isHeaderfuzzerSwitch() {
        return headerfuzzerSwitch;
    }

    public void setHeaderfuzzerSwitch(boolean headerfuzzerSwitch) {
        this.headerfuzzerSwitch = headerfuzzerSwitch;
    }

    public boolean isCookiefuzzerSwitch() {
        return cookiefuzzerSwitch;
    }

    public void setCookiefuzzerSwitch(boolean cookiefuzzerSwitch) {
        this.cookiefuzzerSwitch = cookiefuzzerSwitch;
    }

    // 新增：OOBParamFuzzer相关方法
    public boolean isOobparamfuzzerSwitch() {
        return oobparamfuzzerSwitch;
    }

    public void setOobparamfuzzerSwitch(boolean oobparamfuzzerSwitch) {
        this.oobparamfuzzerSwitch = oobparamfuzzerSwitch;
    }
    public boolean isCachefuzzerSwitch() {
        return cachefuzzerSwitch;
    }

    public void setCachefuzzerSwitch(boolean cachefuzzerSwitch) {
        this.cachefuzzerSwitch = cachefuzzerSwitch;
    }

    // 获取当前所有开关状态
    public SwitchState getCurrentState() {
        return new SwitchState(
                masterSwitch,
                jsonListerSwitch,
                routefuzzerSwitch,
                paramfuzzerSwitch,
                paramdeleterSwitch,
                paramadderSwitch, // 新增
                headerfuzzerSwitch,
                cookiefuzzerSwitch,
                oobparamfuzzerSwitch,
                cachefuzzerSwitch // 新增
        );
    }
}