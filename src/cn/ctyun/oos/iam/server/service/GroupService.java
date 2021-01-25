package cn.ctyun.oos.iam.server.service;

import java.util.ArrayList;
import java.util.List;

import org.apache.hadoop.hbase.client.Scan;

import cn.ctyun.oos.iam.server.action.api.GroupAction;
import cn.ctyun.oos.iam.server.action.api.PolicyAction;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupPolicy;
import cn.ctyun.oos.iam.server.entity.GroupUser;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.DeleteGroupParam;
import cn.ctyun.oos.iam.server.param.GroupPolicyParam;
import cn.ctyun.oos.iam.server.param.GroupUserParam;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.util.IAMAccessControlUtils;

/**
 * 组通用功能
 * @author wangduo
 *
 */
public class GroupService {

    /**
     * 删除附加到组上的用户和策略关系
     * @param group
     * @param deleteGroupParam
     * @throws Throwable 
     */
    public static void deleteGroupAttached(Group group, DeleteGroupParam deleteGroupParam) throws Throwable {
        
        // 检查从组中移除用户权限
        List<GroupUserParam> groupUserParams = checkRemoveUserFromGroup(group, deleteGroupParam);
        // 检查从组移除策略权限
        List<GroupPolicyParam> groupPolicyParams = checkDetachGroupPolicy(group, deleteGroupParam);
        
        // 删除组关系
        for (GroupUserParam groupUserParam : groupUserParams) {
            GroupAction.removeUserFromGroup(groupUserParam);
        }
        // 删除策略关系
        for (GroupPolicyParam groupPolicyParam : groupPolicyParams) {
            PolicyAction.detachGroupPolicy(groupPolicyParam);
        }
    }
    
    /**
     * 检查删除组和用户关系权限
     * @param group
     * @param deleteGroupParam
     * @return
     * @throws Throwable
     */
    private static List<GroupUserParam> checkRemoveUserFromGroup(Group group, DeleteGroupParam deleteGroupParam) throws Throwable  {
        List<GroupUserParam> removeUserFromGroupParams = new ArrayList<>();
        GroupUser groupUserQuery = new GroupUser();
        groupUserQuery.accountId = group.accountId;
        groupUserQuery.groupName = group.groupName;
        Scan groupUserScan = HBaseUtils.buildScan(groupUserQuery.getGroupPrefix(), null);
        // 获取用户组关系
        PageResult<GroupUser> pageResult = HBaseUtils.scan(groupUserScan, 10000, GroupUser.class, false);
        for (GroupUser groupUser : pageResult.list) {
            GroupUserParam groupUserParam = new GroupUserParam();
            IAMAccessControlUtils.setProperty(deleteGroupParam, groupUserParam);
            groupUserParam.userName = groupUser.userName;
            groupUserParam.groupName = groupUser.groupName;
            removeUserFromGroupParams.add(groupUserParam);
            // 检查权限
            IAMAccessControlUtils.auth("RemoveUserFromGroup", groupUserParam);
        }
        return removeUserFromGroupParams;
    }
    
    /**
     * 检查删除策略关系权限
     * @param group
     * @param deleteGroupParam
     * @return
     * @throws Throwable
     */
    private static List<GroupPolicyParam> checkDetachGroupPolicy(Group group, DeleteGroupParam deleteGroupParam) throws Throwable {
        List<GroupPolicyParam> detachGroupPolicyParams = new ArrayList<>();
        GroupPolicy groupPolicyQuery = new GroupPolicy();
        groupPolicyQuery.accountId = group.accountId;
        groupPolicyQuery.groupName = group.groupName;
        Scan groupPolicyScan = HBaseUtils.buildScan(groupPolicyQuery.getGroupPolicyPrefix(), null);
        // 获取用户策略关系
        PageResult<GroupPolicy> groupPolicyPageResult = HBaseUtils.scan(groupPolicyScan, 10000, GroupPolicy.class, false);
        for (GroupPolicy groupPolicy : groupPolicyPageResult.list) {
            GroupPolicyParam groupPolicyParam = new GroupPolicyParam();
            IAMAccessControlUtils.setProperty(deleteGroupParam, groupPolicyParam);
            groupPolicyParam.groupName = groupPolicy.groupName;
            groupPolicyParam.policyArn = groupPolicy.getPolicy().getArn();
            detachGroupPolicyParams.add(groupPolicyParam);
            IAMAccessControlUtils.auth("DetachGroupPolicy", groupPolicyParam);
        }
        return detachGroupPolicyParams;
    }
    
}
