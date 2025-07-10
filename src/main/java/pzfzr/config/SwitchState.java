package pzfzr.config;

public class SwitchState {
    private final boolean masterSwitch;
    private final boolean builtInSwitch;
    private final boolean collectedSwitch;
    private final boolean suspiciousSwitch;
    private final boolean knownSwitch;  // 新增


    public SwitchState(boolean masterSwitch, boolean builtInSwitch,
                       boolean collectedSwitch, boolean suspiciousSwitch,
                       boolean knownSwitch) {  // 新增参数
        this.masterSwitch = masterSwitch;
        this.builtInSwitch = builtInSwitch;
        this.collectedSwitch = collectedSwitch;
        this.suspiciousSwitch = suspiciousSwitch;
        this.knownSwitch = knownSwitch;  // 新增
    }

    public boolean isMasterSwitch() {
        return masterSwitch;
    }

    public boolean isBuiltInSwitch() {
        return builtInSwitch;
    }

    public boolean isCollectedSwitch() {
        return collectedSwitch;
    }

    public boolean isSuspiciousSwitch() {
        return suspiciousSwitch;
    }
    public boolean isKnownSwitch() {
        return knownSwitch;
    }
}