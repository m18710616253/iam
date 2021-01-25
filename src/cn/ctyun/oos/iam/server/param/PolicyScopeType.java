package cn.ctyun.oos.iam.server.param;

/**
 * 策略作用域
 * 
 * @author wangduo
 *
 */
public enum PolicyScopeType {

    All("All"),
    OOS("OOS"),
    Local("Local");

    public String value;

    private PolicyScopeType(String value) {
        this.value = value;
    }

    public static PolicyScopeType fromValue(String value) {
        for (PolicyScopeType enumEntry : PolicyScopeType.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }
        return null;
    }
}
