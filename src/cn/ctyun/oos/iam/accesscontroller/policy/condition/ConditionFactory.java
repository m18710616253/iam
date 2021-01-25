package cn.ctyun.oos.iam.accesscontroller.policy.condition;


import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;

/**
 * Condition工厂类
 * @author wangduo
 *
 */
public class ConditionFactory {

    private ConditionFactory() {}
    
    /**
     * 创建条件
     * @param type 条件运算符
     * @param key 条件键
     * @param values 规则列表
     * @return
     * @throws PolicyParseException
     */
    public static Condition newCondition(String type, String key, List<String> values) throws PolicyParseException {
        
        // 字符串条件
        if (type.startsWith("String")) {
            return new StringCondition(type, key, values);
        }
        // 日期条件
        if (type.startsWith("Date")) {
            return new DateCondition(type, key, values);
        }
        // 布尔值条件
        if (type.startsWith("Bool")) {
            return new BooleanCondition(type, key, values);
        }
        // IP地址条件
        if (type.contains("IpAddress")) {
            return new IpAddressCondition(type, key, values);
        }
        // 数字条件
        if (type.startsWith("Numeric")) {
            return new NumericCondition(type, key, values);
        }
        throw new PolicyParseException("invalidConditionType", "Invalid Condition type : %s.", type);
    }
}
