package cn.ctyun.oos.iam.server.internal.api;

import java.util.Map;

import cn.ctyun.oos.iam.server.entity.Policy;

/**
 * 多个用户的策略列表
 * @author wangduo
 *
 */
public class UsersPolicies {

    /** 
     * 策略MAP 
     * key: accountId + "|" + userName
     * value: policy 
     */
    public Map<String, Policy> policies;
    
}
