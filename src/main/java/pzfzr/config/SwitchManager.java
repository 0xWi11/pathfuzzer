package pzfzr.config;

public class SwitchManager {
    private boolean masterSwitch;
    private boolean builtInSwitch;
    private boolean collectedSwitch;
    private boolean suspiciousSwitch;
    private boolean knownSwitch;  // 新增


    // 单例模式
    private static SwitchManager instance;

    private SwitchManager() {
        // 默认值设置
        this.masterSwitch = true;
        this.builtInSwitch = false;
        this.collectedSwitch = false;
        this.suspiciousSwitch = false;
        this.knownSwitch = false;  // 新增

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

    public boolean isBuiltInSwitch() {
        return builtInSwitch;
    }

    public void setBuiltInSwitch(boolean builtInSwitch) {
        this.builtInSwitch = builtInSwitch;
    }

    public boolean isCollectedSwitch() {
        return collectedSwitch;
    }

    public void setCollectedSwitch(boolean collectedSwitch) {
        this.collectedSwitch = collectedSwitch;
    }

    public boolean isSuspiciousSwitch() {
        return suspiciousSwitch;
    }

    public void setSuspiciousSwitch(boolean suspiciousSwitch) {
        this.suspiciousSwitch = suspiciousSwitch;
    }
    public boolean isKnownSwitch() {
        return knownSwitch;
    }

    public void setKnownSwitch(boolean knownSwitch) {
        this.knownSwitch = knownSwitch;
    }
    // 获取当前所有开关状态
    public SwitchState getCurrentState() {
        return new SwitchState(
                masterSwitch,
                builtInSwitch,
                collectedSwitch,
                suspiciousSwitch,
                knownSwitch  // 新增
        );
    }
}