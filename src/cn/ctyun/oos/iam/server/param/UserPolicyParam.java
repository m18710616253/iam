package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.ParseArnException;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.PolicyEntity;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserPolicy;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 策略和用户关系维护参数
 * @author wangduo
 *
 */
public class UserPolicyParam extends ActionParameter {

    public String policyArn;
    public String userName;
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验策略ARN
        ValidationUtils.validatePolicyArn(policyArn, errorMessages);
        // 验证用户名
        ValidationUtils.validateUserName(userName, errorMessages);
    }

    /**
     * 使用请求参数创建策略附加到的用户
     * @return
     * @throws ParseArnException 
     */
    public PolicyEntity getPolicyUser(Policy policy, User user) {
        PolicyEntity policyEntity = new PolicyEntity();
        policyEntity.accountId = getAccountId();
        policyEntity.policyName = policy.policyName;
        policyEntity.scope = policy.scope;
        policyEntity.entityType = PolicyEntity.TYPE_USER;
        policyEntity.entityName = userName;
        policyEntity.id = user.userId;
        return policyEntity;
    }
    
    /**
     * 使用请求参数创建用户被附加的策略
     * @return
     * @throws ParseArnException 
     */
    public UserPolicy getUserPolicy(Policy policy) {
        UserPolicy userPolicy = new UserPolicy();
        userPolicy.accountId = getAccountId();
        userPolicy.policyName = policy.policyName;
        userPolicy.scope = policy.scope;
        userPolicy.userName = userName;
        return userPolicy;
    }
    
    public User getUser() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = userName;
        return user;
    }
    
    public String getResource() {
        return policyArn;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), userName);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateUserResources(getAccountId(), userName));
        resources.add(ResourcesUtils.generatePolicyResources(policyArn));
        return resources;
    }
}
