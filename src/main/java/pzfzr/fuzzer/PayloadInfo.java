// PayloadInfo.java - Enhanced version with enable/disable support
package pzfzr.fuzzer;

/**
 * Enhanced PayloadInfo class that supports enable/disable functionality
 */
public class PayloadInfo {
    public final String payload;
    public final String alias;
    private boolean enabled;

    public PayloadInfo(String payload, String alias) {
        this.payload = payload;
        this.alias = alias;
        this.enabled = true; // Default to enabled
    }

    public PayloadInfo(String payload, String alias, boolean enabled) {
        this.payload = payload;
        this.alias = alias;
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public PayloadInfo copy() {
        return new PayloadInfo(this.payload, this.alias, this.enabled);
    }

    @Override
    public String toString() {
        return alias + " (" + payload + ")";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PayloadInfo that = (PayloadInfo) obj;
        return payload.equals(that.payload) && alias.equals(that.alias);
    }

    @Override
    public int hashCode() {
        return payload.hashCode() + alias.hashCode();
    }
}
