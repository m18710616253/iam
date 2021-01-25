package cn.ctyun.oos.iam.server.param;

/**
 * MFA分配状态
 * @author wangduo
 */
public enum AssignmentStatusType {

    Assigned("Assigned"),
    Unassigned("Unassigned"),
    Any("Any");

    public String value;

    private AssignmentStatusType(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }

    public static AssignmentStatusType fromValue(String value) {
        for (AssignmentStatusType enumEntry : AssignmentStatusType.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }
        return null;
    }
    
}
