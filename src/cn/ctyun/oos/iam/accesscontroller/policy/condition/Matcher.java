package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.List;

/**
 * 条件匹配工具
 * @author wangduo
 *
 */
public interface Matcher {

    /**
     * 判断指定值是否可以与规则列表中的某项匹配
     * @param value
     * @param patterns
     * @return
     */
    boolean match(String value, List<String> patterns);
}
