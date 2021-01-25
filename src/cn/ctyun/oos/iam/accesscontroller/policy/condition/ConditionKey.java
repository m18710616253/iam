package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.util.Arrays;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.RequestInfo;

/**
 * 条件键
 * @author wangduo
 *
 */
public enum ConditionKey {

    /** 当前时间条件键 {@link DateCondition} */
    CURRENT_TIME(Arrays.asList("aws:CurrentTime", "ctyun:CurrentTime"), requestInfo -> requestInfo.currentTime),
    /** 是否使用https条件键 {@link BooleanCondition} */
    SECURE_TRANSPORT(Arrays.asList("aws:SecureTransport", "ctyun:SecureTransport"), requestInfo -> requestInfo.secureTransport),
    /** 请求源IP条件键 {@link IpAddressCondition} */
    SOURCE_IP(Arrays.asList("aws:SourceIp", "ctyun:SourceIp"), requestInfo -> requestInfo.sourceIp),
    /** 请求的UserAgent条件键 {@link StringCondition} */
    USER_AGENT(Arrays.asList("aws:UserAgent", "ctyun:UserAgent"), requestInfo -> requestInfo.userAgent),
    /** 请求的Referer条件键 {@link StringCondition} */
    REFERER(Arrays.asList("aws:Referer", "ctyun:Referer"), requestInfo -> requestInfo.referer),
    /** userid条件键 {@link StringCondition} */
    USERID(Arrays.asList("aws:userid", "ctyun:userid"), requestInfo -> requestInfo.userId),
    /** username条件键 {@link StringCondition} */
    USERNAME(Arrays.asList("aws:username", "ctyun:username"), requestInfo -> requestInfo.userName),
    /** MultiFactorAuthPresent条件键 {@link BoolCondition} */
    MULTI_FACTOR_AUTH_PRESENT(Arrays.asList("aws:MultiFactorAuthPresent", "ctyun:MultiFactorAuthPresent"), requestInfo -> requestInfo.multiFactorAuthPresent),
    /** MultiFactorAuthAge条件键 {@link NumericCondition} */
    MULTI_FACTOR_AUTH_AGE(Arrays.asList("aws:MultiFactorAuthAge", "ctyun:MultiFactorAuthAge"), requestInfo -> requestInfo.multiFactorAuthAge),
    /** OOS PREFIX 条件键 {@link StringCondition} */
    OOS_PREFIX(Arrays.asList("s3:prefix", "oos:prefix"), requestInfo -> requestInfo.oosPrefix, "oos:ListBucket"),
    /** OOS PutBucket ACL 条件键 {@link StringCondition} */
    OOS_X_AMZ_ACL(Arrays.asList("s3:x-amz-acl", "oos:x-amz-acl"), requestInfo -> requestInfo.xAmzAcl, "oos:PutBucket");
    
    /** 可以匹配的条件键列表 */
    public List<String> keys;
    /** 获取值实现 */
    public ValueGetter getter;
    /** 只对指定的action生效 */
    public String targetAction;
    
    ConditionKey(List<String> keys, ValueGetter getter) {
        this.keys = keys;
        this.getter = getter;
    }
    
    ConditionKey(List<String> keys, ValueGetter getter, String targetAction) {
        this.keys = keys;
        this.getter = getter;
        this.targetAction = targetAction;
    } 
    
    /**
     * 获取key对应的条件键
     * @param key
     * @return
     */
    public static ConditionKey get(String key) {
        for (ConditionKey conditionKey : ConditionKey.values()) {
            if (conditionKey.keys.contains(key)) {
                return conditionKey;
            }
        }
        return null;
    }
    
    /**
     * 获取RequestInfo中的值
     */
    interface ValueGetter {
        String get(RequestInfo requestInfo);
    }
}
