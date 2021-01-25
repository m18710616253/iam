package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;

/**
 * 数字条件
 * @author wangduo
 *
 */
public class NumericCondition extends Condition {

    /**
     * 数字条件运算符
     */
    public static enum NumericComparisonType {
        NumericEquals((value, patterns) -> {
            if (StringUtils.isEmpty(value)) return false;
            return patterns.stream().anyMatch(p -> value.equals(p));
        }),
        NumericNotEquals((value, patterns) -> {
            if (StringUtils.isEmpty(value)) return false;
            return !patterns.stream().anyMatch(p -> value.equals(p));
        }),
        NumericGreaterThan((value, patterns) -> {
            if (StringUtils.isEmpty(value)) return false;
            return patterns.stream().anyMatch(p -> compare(value, p) > 0);
        }),
        NumericGreaterThanEquals((value, patterns) -> {
            if (StringUtils.isEmpty(value)) return false;
            return patterns.stream().anyMatch(p -> compare(value, p) >= 0);
        }),
        NumericLessThan((value, patterns) -> {
            if (StringUtils.isEmpty(value)) return false;
            return patterns.stream().anyMatch(p -> compare(value, p) < 0);
        }),
        NumericLessThanEquals((value, patterns) -> {
            if (StringUtils.isEmpty(value)) return false;
            return patterns.stream().anyMatch(p -> compare(value, p) <= 0);
        });
        
        public Matcher matcher;
        
        NumericComparisonType(Matcher matcher) {
            this.matcher = matcher;
            
        }
    };

    public NumericCondition(String type, String key, List<String> values) throws PolicyParseException {
        super(type, key, values);
        // 校验是否是数字
        for (String value : values) {
            try {
                Long.valueOf(value);
            } catch (NumberFormatException e) {
                throw new PolicyParseException("Invalid Numeric Condition value : " + value + ".", e);
            }
        }
    }

    @Override
    public Matcher getMatcher(String type) {
        for (NumericComparisonType NumericType : NumericComparisonType.values()) {
            if (NumericType.toString().equals(type)) {
                return NumericType.matcher;
            }
        }
        return null;
    }

    private static int compare(String value, String pattern) {
        return Long.valueOf(value).compareTo(Long.valueOf(pattern));
    }
}
