package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;

/**
 * 时间条件
 * @author wangduo
 *
 */
public class DateCondition extends Condition {

    public static enum DateComparisonType {
        DateEquals((value, patterns) -> {
            return patterns.stream().anyMatch(p -> dateEquals(value, p));
        }),
        DateNotEquals((value, patterns) -> {
            return !patterns.stream().anyMatch(p -> dateEquals(value, p));
        }),
        DateGreaterThan((value, patterns) -> {
            return patterns.stream().anyMatch(p -> value.compareTo(p) > 0);
        }),
        DateGreaterThanEquals((value, patterns) -> {
            return patterns.stream().anyMatch(p -> value.compareTo(p) >= 0);
        }),
        DateLessThan((value, patterns) -> {
            return patterns.stream().anyMatch(p -> value.compareTo(p) < 0);
        }),
        DateLessThanEquals((value, patterns) -> {
            return patterns.stream().anyMatch(p -> value.compareTo(p) <= 0);
        });
        
        public Matcher matcher;
        
        DateComparisonType(Matcher matcher) {
            this.matcher = matcher;
        }
    };

    public DateCondition(String type, String key, List<String> values) throws PolicyParseException {
        super(type, key, values);
    }

    @Override
    public Matcher getMatcher(String type) {
        for (DateComparisonType dateType : DateComparisonType.values()) {
            if (dateType.toString().equals(type)) {
                return dateType.matcher;
            }
        }
        return null;
    }

    /**
     * 匹配日期部分是否相同
     * @param value
     * @param pattern
     * @return
     */
    private static boolean dateEquals(String value, String pattern) {
        if (value == null || value.length() < 10) {
            return false;
        }
        if (pattern == null || pattern.length() < 10) {
            return false;
        }
        return value.substring(0,10).equals(pattern.substring(0,10));
    }
}
