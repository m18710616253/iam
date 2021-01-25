package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.accesscontroller.util.MatchUtils;

/**
 * 字符串条件
 * @author wangduo
 */
public class StringCondition extends Condition {

    /**
     * String的所有条件运算符
     */
    public static enum StringComparisonType {
        StringEquals((value, patterns) -> {
            return patterns.stream().anyMatch(p -> p.equals(value));
        }),
        StringNotEquals((value, patterns) -> {
            return !patterns.stream().anyMatch(p -> p.equals(value));
        }),
        StringEqualsIgnoreCase((value, patterns) -> {
            return patterns.stream().anyMatch(p -> p.equalsIgnoreCase(value));
        }),
        StringNotEqualsIgnoreCase((value, patterns) -> {
            return !patterns.stream().anyMatch(p -> p.equalsIgnoreCase(value));
        }),
        StringLike((value, patterns) -> {
            return patterns.stream().anyMatch(p -> MatchUtils.isMatch(value, p));
        }),
        StringNotLike((value, patterns) -> {
            return !patterns.stream().anyMatch(p -> MatchUtils.isMatch(value, p));
        });
        
        public Matcher matcher;
        
        StringComparisonType(Matcher matcher) {
            this.matcher = matcher;
        }
    }
    
    public StringCondition(String type, String key, List<String> values) throws PolicyParseException {
        super(type, key, values);
    }
    
    /**
     * 通过条件运算符名称获取匹配工具
     * @param type
     * @return
     */
    public Matcher getMatcher(String type) {
        for (StringComparisonType stringType : StringComparisonType.values()) {
            if (stringType.toString().equals(type)) {
                return stringType.matcher;
            }
        }
        return null;
    }
}
