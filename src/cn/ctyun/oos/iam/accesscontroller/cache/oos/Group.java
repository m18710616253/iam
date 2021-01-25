package cn.ctyun.oos.iam.accesscontroller.cache.oos;

import java.util.List;

/**
 * 存放组和策略关系
 * @author wangduo
 *
 */
public class Group {

    public List<String> policyKeys;

    @Override
    public String toString() {
        return "Group [policyKeys=" + policyKeys + "]";
    }
}
