package cn.ctyun.oos.iam.server.internal.api;

import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.param.PolicyScopeType;

/**
 * 系统策略参数
 * 
 * @author wangduo
 *
 */
public class OOSPolicyParam {

    public String policyName;
    public String policyDocument;
    public String description;
    
    /**
     * 创建参数
     * @return
     */
    public Policy getCreatePolicy() {
        Policy policy = new Policy();
        policy.policyId = IAMStringUtils.generateId();
        policy.accountId = PolicyScopeType.OOS.value;
        policy.policyName = policyName;
        policy.document = policyDocument;
        policy.isAttachable = true;
        policy.description = description;
        policy.scope = PolicyScopeType.OOS.value;
        policy.createDate = System.currentTimeMillis();
        policy.updateDate = policy.createDate;
        return policy;
    }
    
    /**
     * 更新参数
     * @return
     */
    public Policy getUpdatePolicy() {
        Policy policy = new Policy();
        policy.accountId = PolicyScopeType.OOS.value;
        policy.policyName = policyName;
        policy.document = policyDocument;
        policy.description = description;
        policy.scope = PolicyScopeType.OOS.value;
        policy.updateDate = System.currentTimeMillis();
        return policy;
    }
    
    /**
     * 查询参数
     * @return
     */
    public Policy getQueryPolicy() {
        Policy policy = new Policy();
        policy.policyName = policyName;
        policy.scope = PolicyScopeType.OOS.value;
        return policy;
    }
}
