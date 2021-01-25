package cn.ctyun.oos.iam.server.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hbase.client.Scan;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.action.api.AccessKeyAction;
import cn.ctyun.oos.iam.server.action.api.GroupAction;
import cn.ctyun.oos.iam.server.action.api.MFAAction;
import cn.ctyun.oos.iam.server.action.api.PolicyAction;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserGroup;
import cn.ctyun.oos.iam.server.entity.UserMFADevice;
import cn.ctyun.oos.iam.server.entity.UserPolicy;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.DeactivateMFADeviceParam;
import cn.ctyun.oos.iam.server.param.DeleteAccessKeyParam;
import cn.ctyun.oos.iam.server.param.DeleteLoginProfileParam;
import cn.ctyun.oos.iam.server.param.DeleteUserParam;
import cn.ctyun.oos.iam.server.param.GroupUserParam;
import cn.ctyun.oos.iam.server.param.UserPolicyParam;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.util.IAMAccessControlUtils;

/**
 * 用户通用功能
 * @author wangduo
 *
 */
public class UserService {

    /**
     * 删除附加到用户上的的关系
     * 包括策略、组、密码、AK、MFA等关系及对应的AK
     * @param user
     * @param deleteUserParam
     * @throws Throwable 
     */
    public static void deleteUserAttached(User user, DeleteUserParam deleteUserParam) throws Throwable {
        
        // 密码不为空，检查删除控制台密码权限
        if (!StringUtils.isEmpty(user.password)) {
            DeleteLoginProfileParam deleteLoginProfileParam = new DeleteLoginProfileParam();
            setProperty(deleteUserParam, deleteLoginProfileParam);
            deleteLoginProfileParam.userName = deleteUserParam.userName;
            IAMAccessControlUtils.auth("DeleteLoginProfile", deleteLoginProfileParam);
        }
        
        // 检查删除AccessKey权限
        List<DeleteAccessKeyParam> deleteAccessKeyParams = checkDeleteAccessKey(user, deleteUserParam);
        // 检查删除组关系权限
        List<GroupUserParam> removeUserFromGroupParams = checkRemoveUserFromGroup(user, deleteUserParam);
        // 检查删除策略关系权限
        List<UserPolicyParam> detachUserPolicyParams = checkDetachUserPolicy(user, deleteUserParam);
        // 检查删除MFA权限
        DeactivateMFADeviceParam deactivateMFADeviceParam = checkDeactivateMFADevice(user, deleteUserParam);
        
        // 删除AccessKey
        for (DeleteAccessKeyParam deleteAccessKeyParam : deleteAccessKeyParams) {
            AccessKeyAction.deleteAccessKey(deleteAccessKeyParam);
        }
        // 删除组关系
        for (GroupUserParam groupUserParam : removeUserFromGroupParams) {
            GroupAction.removeUserFromGroup(groupUserParam);
        }
        // 删除策略关系
        for (UserPolicyParam userPolicyParam : detachUserPolicyParams) {
            PolicyAction.detachUserPolicy(userPolicyParam);
        }
        // 删除MFA关系
        if (deactivateMFADeviceParam != null) {
            MFAAction.deactivateMFADevice(deactivateMFADeviceParam);
        }
    }
    
    /**
     * 检查删除AccessKey权限
     * @param user
     * @param deleteUserParam
     * @return
     * @throws BaseException
     * @throws IOException
     */
    private static List<DeleteAccessKeyParam> checkDeleteAccessKey(User user, DeleteUserParam deleteUserParam) throws BaseException, IOException {
        List<DeleteAccessKeyParam> deleteAccessKeyParams = new ArrayList<>();
        if (user.accessKeys != null && user.accessKeys.size() > 0) {
            for (String accessKeyId : user.accessKeys) {
                DeleteAccessKeyParam deleteAccessKeyParam = new DeleteAccessKeyParam();
                setProperty(deleteUserParam, deleteAccessKeyParam);
                deleteAccessKeyParam.userName = deleteUserParam.userName;
                deleteAccessKeyParam.accessKeyId = accessKeyId;
                // 添加到待删除列表
                deleteAccessKeyParams.add(deleteAccessKeyParam);
                IAMAccessControlUtils.auth("DeleteAccessKey", deleteAccessKeyParam);
            }
        }
        return deleteAccessKeyParams;
    }
    
    /**
     * 检查删除组关系权限
     * @param user
     * @param deleteUserParam
     * @return
     * @throws Throwable
     */
    private static List<GroupUserParam> checkRemoveUserFromGroup(User user, DeleteUserParam deleteUserParam) throws Throwable {
        List<GroupUserParam> removeUserFromGroupParams = new ArrayList<>();
        UserGroup userGroupQuery = new UserGroup();
        userGroupQuery.accountId = user.accountId;
        userGroupQuery.userName = user.userName;
        Scan userGroupScan = HBaseUtils.buildScan(userGroupQuery.getUserPrefix(), null);
        // 获取用户组关系
        PageResult<UserGroup> userGroupPageResult = HBaseUtils.scan(userGroupScan, 10000, UserGroup.class, false);
        for (UserGroup userGroup : userGroupPageResult.list) {
            GroupUserParam groupUserParam = new GroupUserParam();
            setProperty(deleteUserParam, groupUserParam);
            groupUserParam.userName = userGroup.userName;
            groupUserParam.groupName = userGroup.groupName;
            removeUserFromGroupParams.add(groupUserParam);
            // 检查权限
            IAMAccessControlUtils.auth("RemoveUserFromGroup", groupUserParam);
        }
        return removeUserFromGroupParams;
    }
    
    /**
     * 检查删除策略关系权限
     * @param user
     * @param deleteUserParam
     * @return
     * @throws Throwable
     */
    private static List<UserPolicyParam> checkDetachUserPolicy(User user, DeleteUserParam deleteUserParam) throws Throwable {
        List<UserPolicyParam> detachUserPolicyParams = new ArrayList<>();
        UserPolicy userPolicyQuery = new UserPolicy();
        userPolicyQuery.accountId = user.accountId;
        userPolicyQuery.userName = user.userName;
        Scan userPolicyScan = HBaseUtils.buildScan(userPolicyQuery.getUserPolicyPrefix(), null);
        // 获取用户策略关系
        PageResult<UserPolicy> userPolicyPageResult = HBaseUtils.scan(userPolicyScan, 10000, UserPolicy.class, false);
        for (UserPolicy userPolicy : userPolicyPageResult.list) {
            UserPolicyParam userPolicyParam = new UserPolicyParam();
            setProperty(deleteUserParam, userPolicyParam);
            userPolicyParam.userName = userPolicy.userName;
            userPolicyParam.policyArn = userPolicy.getPolicy().getArn();
            detachUserPolicyParams.add(userPolicyParam);
            IAMAccessControlUtils.auth("DetachUserPolicy", userPolicyParam);
        }
        return detachUserPolicyParams;
    }
    
    /**
     * 检查删除MFA关系权限
     * @param user
     * @param deleteUserParam
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    private static DeactivateMFADeviceParam checkDeactivateMFADevice(User user, DeleteUserParam deleteUserParam) throws IOException, BaseException {
        // 获取用户的MFA信息
        UserMFADevice userMFADevice = new UserMFADevice();
        userMFADevice.accountId = user.accountId;
        userMFADevice.userName = user.userName;
        userMFADevice = HBaseUtils.get(userMFADevice);
        // 用户没有MFA设备
        if (userMFADevice == null) {
            return null;
        }
        DeactivateMFADeviceParam deactivateMFADeviceParam = new DeactivateMFADeviceParam();
        setProperty(deleteUserParam, deactivateMFADeviceParam);
        deactivateMFADeviceParam.serialNumber = userMFADevice.getMFADevice().getArn();
        deactivateMFADeviceParam.userName = user.userName;
        IAMAccessControlUtils.auth("DeactivateMFADevice", deactivateMFADeviceParam);
        return deactivateMFADeviceParam;
    }
    
    /**
     * 复制需要进行访问控制权限校验的属性
     * @param from
     * @param to
     */
    private static void setProperty(ActionParameter from, ActionParameter to) {
        to.currentOwner = from.currentOwner;
        to.currentAccessKey = from.currentAccessKey;
        to.authResult = from.authResult;
        to.request = from.request;
    }
    
}
