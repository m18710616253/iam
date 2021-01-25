package cn.ctyun.oos.iam.server.service;

import java.util.ArrayList;
import java.util.List;

import org.apache.hadoop.hbase.client.Scan;

import cn.ctyun.oos.iam.server.action.api.PolicyAction;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.PolicyEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.DeletePolicyParam;
import cn.ctyun.oos.iam.server.param.GroupPolicyParam;
import cn.ctyun.oos.iam.server.param.PolicyScopeType;
import cn.ctyun.oos.iam.server.param.UserPolicyParam;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.util.IAMAccessControlUtils;

/**
 * 用户通用功能
 * @author wangduo
 *
 */
public class PolicyService {

    /**
     * 删除策略与组、用户的关系
     * @param policy
     * @param deletePolicyParam
     * @throws Throwable 
     */
    public static void deletePolicyAttached(Policy policy, DeletePolicyParam deletePolicyParam) throws Throwable {
        
        // 检查从用户移除策略权限
        List<UserPolicyParam> userPolicyParams = checkDetachUserPolicy(policy, deletePolicyParam);
        // 检查从组移除策略权限
        List<GroupPolicyParam> groupPolicyParams = checkDetachGroupPolicy(policy, deletePolicyParam);
        
        // 删除用户和策略关系
        for (UserPolicyParam userPolicyParam : userPolicyParams) {
            PolicyAction.detachUserPolicy(userPolicyParam);
        }
        // 删除组和策略关系
        for (GroupPolicyParam groupPolicyParam : groupPolicyParams) {
            PolicyAction.detachGroupPolicy(groupPolicyParam);
        }
    }
    
    /**
     * 检查删除用户策略关系权限
     * @param policy
     * @param deletePolicyParam
     * @return
     * @throws Throwable
     */
    private static List<UserPolicyParam> checkDetachUserPolicy(Policy policy, DeletePolicyParam deletePolicyParam) throws Throwable {
        List<UserPolicyParam> detachUserPolicyParams = new ArrayList<>();
        PolicyEntity policyEntityQuery = new PolicyEntity();
        policyEntityQuery.entityType = PolicyEntity.TYPE_USER;
        policyEntityQuery.accountId = deletePolicyParam.getAccountId();
        policyEntityQuery.scope = PolicyScopeType.Local.value;
        policyEntityQuery.policyName = policy.policyName;
        Scan policyEntityScan = HBaseUtils.buildScan(policyEntityQuery.getPolicyEntityPrefix(), null);
        // 获取用户策略关系
        PageResult<PolicyEntity> policyEntityPageResult = HBaseUtils.scan(policyEntityScan, 10000, PolicyEntity.class, false);
        for (PolicyEntity policyEntity : policyEntityPageResult.list) {
            UserPolicyParam userPolicyParam = new UserPolicyParam();
            IAMAccessControlUtils.setProperty(deletePolicyParam, userPolicyParam);
            userPolicyParam.userName = policyEntity.entityName;
            userPolicyParam.policyArn = deletePolicyParam.policyArn;
            detachUserPolicyParams.add(userPolicyParam);
            IAMAccessControlUtils.auth("DetachUserPolicy", userPolicyParam);
        }
        return detachUserPolicyParams;
    }
    
    /**
     * 检查删除策略关系权限
     * @param policy
     * @param deletePolicyParam
     * @return
     * @throws Throwable
     */
    private static List<GroupPolicyParam> checkDetachGroupPolicy(Policy policy, DeletePolicyParam deletePolicyParam) throws Throwable {
        List<GroupPolicyParam> detachGroupPolicyParams = new ArrayList<>();
        PolicyEntity policyEntityQuery = new PolicyEntity();
        policyEntityQuery.entityType = PolicyEntity.TYPE_GROUP;
        policyEntityQuery.accountId = deletePolicyParam.getAccountId();
        policyEntityQuery.scope = PolicyScopeType.Local.value;
        policyEntityQuery.policyName = policy.policyName;
        Scan policyEntityScan = HBaseUtils.buildScan(policyEntityQuery.getPolicyEntityPrefix(), null);
        // 获取用户策略关系
        PageResult<PolicyEntity> policyEntityPageResult = HBaseUtils.scan(policyEntityScan, 10000, PolicyEntity.class, false);
        for (PolicyEntity policyEntity : policyEntityPageResult.list) {
            GroupPolicyParam groupPolicyParam = new GroupPolicyParam();
            IAMAccessControlUtils.setProperty(deletePolicyParam, groupPolicyParam);
            groupPolicyParam.groupName = policyEntity.entityName;
            groupPolicyParam.policyArn = deletePolicyParam.policyArn;
            detachGroupPolicyParams.add(groupPolicyParam);
            IAMAccessControlUtils.auth("DetachGroupPolicy", groupPolicyParam);
        }
        return detachGroupPolicyParams;
    }
    
}
