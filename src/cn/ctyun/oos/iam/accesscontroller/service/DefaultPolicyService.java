package cn.ctyun.oos.iam.accesscontroller.service;

import java.io.IOException;
import java.util.List;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.cache.oos.UserPolicyCache;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;

/**
 * 默认的获取策略逻辑 访问IAM服务，用户策略接口获取用户的策略
 * 
 * @author wangduo
 *
 */
public class DefaultPolicyService implements PolicyService {

    private UserPolicyCache policyCache = null;
    
    public DefaultPolicyService() {
        policyCache = new UserPolicyCache();
    }
    
    @Override
    public List<AccessPolicy> getUserPolicies(String accountId, String userName) throws IOException, BaseException  {
        return policyCache.getPolicy(accountId, userName);
    }
}
