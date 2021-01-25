package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.RequestInfo;
import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;

/**
 * 策略匹配条件基类
 * @author wangduo
 */
public abstract class Condition {
    
    private static final String IF_EXISTS = "IfExists";
    
    /** 条件运算符 */
    public String type;
    /** 条件键字符串 */
    public String conditionKey;
    /** 条件值列表 */
    public List<String> values;
    /** conditionKey对应的枚举 */
    private ConditionKey conditionKeyEnum;
    
    /** 
     * 条件运算符的末尾是否包含IfExists
     * 当条件运算符以IfExists结尾时
     * 如果请求的内容中存在策略键，则依照策略所述来处理键。
     * 如果该键不存在，则条件元素的计算结果将为true。
     */
    private boolean ifExists = false;
    /** 当前的匹配工具 */
    private Matcher matcher;
    
    public Condition() {}
    
    public Condition(String type, String key, List<String> values) throws PolicyParseException {
        String realType = type;
        if (type.endsWith(IF_EXISTS)) {
            ifExists = true;
            realType = type.substring(0, type.length() - IF_EXISTS.length());
        }
        this.matcher = getMatcher(realType);
        if (this.matcher == null) {
            throw new PolicyParseException("invalidConditionType", "Invalid Condition type : %s.", type);
        }
        this.type = type;
        this.conditionKey = key;
        this.conditionKeyEnum = ConditionKey.get(key);
        if (this.conditionKeyEnum == null) {
            throw new PolicyParseException("invalidConditionKey", "Invalid Condition key : %s.", key);
        }
        this.values = values;
    }
    
    public boolean hasMFAKey() {
        return conditionKey.contains("MultiFactorAuth");
    }
    
    /**
     * 通过条件运算符名称获取匹配工具
     * @param type
     * @return
     */
    public abstract Matcher getMatcher(String type) ;
    
    /**
     * 判断输入的value是否与values列表中的某个值相匹配
     * @param value
     * @return
     */
    public boolean match(RequestInfo requestInfo) {
        // 如果condition只对指定action生效，不是指定action，返回匹配
        if (conditionKeyEnum.targetAction != null && !conditionKeyEnum.targetAction.equals(requestInfo.action)) {
            return true;
        }
        // 获取condition在requestInfo中对应的值
        String value = this.conditionKeyEnum.getter.get(requestInfo);
        if (value == null) {
            // 如果该键不存在，返回是否应该存在
            return ifExists;
        }
        List<String> patterns = values;
        // 如果是字符串条件
        if (this instanceof StringCondition) {
            patterns = new ArrayList<>(values.size());
            for (String pattern : values) {
                // 子用户名策略变量替换
                patterns.add(IAMStringUtils.replaceUserNameVariable(pattern, requestInfo.userName));
            }
        }
        return matcher.match(value, patterns);
    }
    
}
