package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;

/**
 * 布尔值条件
 * @author wangduo
 *
 */
public class BooleanCondition extends Condition {
    
    public BooleanCondition(String type, String key, List<String> values) throws PolicyParseException {
        super(type, key, values);
    }
    
    @Override
    public Matcher getMatcher(String type) {
        if (!"Bool".equals(type)) {
            return null;
        }
        return (value, patterns) -> {
            return patterns.stream().anyMatch(p -> p.equals(value));
        };
    }
    
}
