package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;

/**
 * ARN条件
 * @author wangduo
 * 本期不实现
 */
public class ArnCondition extends Condition {

    public static enum ArnComparisonType {
        ArnEquals,
        ArnLike,
        ArnNotEquals,
        ArnNotLike;
    };
    
    public ArnCondition(String type, String key, List<String> values) throws PolicyParseException {
        super(type, key, values);
    }

    @Override
    public Matcher getMatcher(String type) {
        return null;
    }
    
}
