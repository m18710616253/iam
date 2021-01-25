package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupPolicy;
import cn.ctyun.oos.iam.server.entity.ParseArnException;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.PolicyEntity;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 策略和组关系维护参数
 * @author wangduo
 *
 */
public class GroupPolicyParam extends ActionParameter {

    public String policyArn;
    public String groupName;
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验策略ARN
        ValidationUtils.validatePolicyArn(policyArn, errorMessages);
        // 验证组名
        ValidationUtils.validateGroupName(groupName, errorMessages);
    }

    /**
     * 使用请求参数创建策略附加到的组
     * @return
     * @throws ParseArnException 
     */
    public PolicyEntity getPolicyEntity(Policy policy, Group group) {
        PolicyEntity policyEntity = new PolicyEntity();
        policyEntity.accountId = getAccountId();
        policyEntity.policyName = policy.policyName;
        policyEntity.scope = policy.scope;
        policyEntity.entityType = PolicyEntity.TYPE_GROUP;
        policyEntity.entityName = groupName;
        policyEntity.id = group.groupId;
        return policyEntity;
    }
    
    /**
     * 使用请求参数创建组被附加的策略
     * @return
     * @throws ParseArnException 
     */
    public GroupPolicy getGroupPolicy(Policy policy) {
        GroupPolicy groupPolicy = new GroupPolicy();
        groupPolicy.accountId = getAccountId();
        groupPolicy.policyName = policy.policyName;
        groupPolicy.scope = policy.scope;
        groupPolicy.groupName = groupName;
        return groupPolicy;
    }
    
    public Group getGroup() {
        Group group = new Group();
        group.accountId = getAccountId();
        group.groupName = groupName;
        return group;
    }
    
    public String getResource() {
        return policyArn;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateGroupArn(getAccountId(), groupName);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generatePolicyResources(policyArn));
        resources.add(ResourcesUtils.generateGroupResources(getAccountId(), groupName));
        return resources;
    }
}
