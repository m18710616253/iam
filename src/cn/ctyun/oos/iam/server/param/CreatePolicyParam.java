package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.PolicyAttachmentCount;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 创建策略参数
 * 
 * @author wangduo
 *
 */
public class CreatePolicyParam extends ActionParameter {

    public String policyName;
    public String policyDocument;
    public String description;
    
    @Override
    public void validate() {
        // 校验策略名
       ValidationUtils.validatePolicyName(policyName, errorMessages);
       // 校验描述
       ValidationUtils.validateDescription(description, errorMessages);
       // 校验策略内容
       ValidationUtils.validatePolicyDocument(policyDocument, errorMessages);
    }
    
    public Policy getPolicy() {
        Policy policy = new Policy();
        policy.policyId = IAMStringUtils.generateId();
        policy.accountId = getAccountId();
        policy.policyName = policyName;
        policy.document = policyDocument;
        policy.isAttachable = true;
        policy.description = description;
        policy.attachmentCount = 0L;
        policy.scope = PolicyScopeType.Local.value;
        policy.createDate = System.currentTimeMillis();
        policy.updateDate = policy.createDate;
        return policy;
    }

    public PolicyAttachmentCount getPolicyAttachmentCount() {
        PolicyAttachmentCount count = new PolicyAttachmentCount();
        count.accountId = getAccountId();
        count.policyName = policyName;
        count.scope = PolicyScopeType.Local.value;
        return count;
    }
    
    public String getResource() {
        return policyName;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generatePolicyArn(getAccountId(), policyName);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generatePolicyResources(getAccountId(), policyName));
        return resources;
    }
}
