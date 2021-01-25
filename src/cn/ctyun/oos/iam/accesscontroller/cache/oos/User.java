package cn.ctyun.oos.iam.accesscontroller.cache.oos;

import java.util.List;

/**
 * 存放用户策略关系列表及用户组关系列表数据
 * @author wangduo
 *
 */
public class User {

    public List<String> groupKeys;
    
    public List<String> policyKeys;
    
    public static String getUserKey(String accountId, String userName) {
        return accountId + "|" + userName.toLowerCase();
    }

    @Override
    public String toString() {
        return "User [groupKeys=" + groupKeys + ", policyKeys=" + policyKeys + "]";
    }
}
