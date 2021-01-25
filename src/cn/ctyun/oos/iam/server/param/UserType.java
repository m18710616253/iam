package cn.ctyun.oos.iam.server.param;

/**
 * 用户类型
 * 根用户和子用户
 * @author wangduo
 */
public enum UserType {

    User("user"),
    Root("root");

    public String value;

    private UserType(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }

    public static UserType fromValue(String value) {
        for (UserType enumEntry : UserType.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }
        return null;
    }
    
}
